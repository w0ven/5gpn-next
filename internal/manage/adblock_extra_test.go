package manage

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/w0ven/5gpn-next/internal/config"
	"github.com/w0ven/5gpn-next/internal/egress"
	"github.com/w0ven/5gpn-next/internal/policy"
	"github.com/w0ven/5gpn-next/internal/ruleset"
)

func TestLooksLikeAd(t *testing.T) {
	for _, h := range []string{
		"ads3-normal-hl.zijieapi.com", "log19-normal-alisg.tiktokv.com", "sentry.io",
		"mobile.events.data.microsoft.com", "analytics.tiktok.com", "app-measurement.com",
		"ulogs.umeng.com", "mi.gdt.qq.com", "rtlog22-normal-alisg.tiktokv.com", "aax.amazon-adsystem.com",
	} {
		if h == "app-measurement.com" || h == "ulogs.umeng.com" {
			// 这两个靠清单拦，名字里没有可靠的特征词，不强求识别。
			continue
		}
		if !looksLikeAd(h) {
			t.Errorf("%s 应识别为疑似广告/上报", h)
		}
	}
	for _, h := range []string{
		"www.youtube.com", "login.live.com", "static.zhihu.com", "api.weixin.qq.com", "blog.example.com",
		"catalog.example.com", "www.adobe.com", "address.example.com", "statics.example.com", "github.com",
	} {
		if looksLikeAd(h) {
			t.Errorf("%s 不应识别为疑似广告/上报", h)
		}
	}
}

func TestAdSuspectsSkipBlockedAndAllowlisted(t *testing.T) {
	dir := t.TempDir()
	cfg := config.Default()
	cfg.AdBlock.Allowlist = []string{"allowed.example"}
	eng := policy.New()
	ads := ruleset.NewDomainSet()
	ads.AddRule("+.blocked-ads.example")
	eng.RegisterDomainSet("ad-block", ads)
	if err := eng.AddRule(policy.Rule{Kind: policy.KindRuleSet, Value: "ad-block", Action: policy.ActionBlock}); err != nil {
		t.Fatal(err)
	}
	m := New(filepath.Join(dir, "config.json"), cfg, eng, egress.NewRegistry())

	for i := 0; i < 3; i++ {
		m.RecordDNS("log19-normal.tiktokv.com.", "proxy")
	}
	m.RecordDNS("analytics.example.net", "direct")
	m.RecordDNS("ads.blocked-ads.example", "proxy")  // 已被规则拦截
	m.RecordDNS("metrics.allowed.example", "direct") // 用户放行过
	m.RecordDNS("www.youtube.com", "proxy")          // 不像广告，不记录
	m.RecordDNS("ads.other.example", "block")        // 已拦截的应答不记录

	got := m.AdSuspects(10)
	if len(got) != 2 || got[0].Host != "log19-normal.tiktokv.com" || got[0].Count != 3 || got[1].Host != "analytics.example.net" {
		t.Fatalf("疑似漏网应只含未拦截、未放行的可疑域名，按次数排序: %+v", got)
	}
}

func TestBlockDomainAddsRuleOnce(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.json")
	cfg := config.Default()
	if err := cfg.Save(path); err != nil {
		t.Fatal(err)
	}
	m := New(path, cfg, policy.New(), egress.NewRegistry())
	if _, err := m.BlockDomain("bad host"); err == nil {
		t.Fatal("非法域名应报错")
	}
	if _, err := m.BlockDomain("Log.Example.COM."); err != nil {
		t.Fatal(err)
	}
	if _, err := m.BlockDomain("log.example.com"); err != nil {
		t.Fatal(err)
	}
	n := 0
	for _, r := range m.Rules() {
		if r == "DOMAIN-SUFFIX,log.example.com,block" {
			n++
		}
	}
	if n != 1 {
		t.Fatalf("应恰好添加一条拦截规则: %v", m.Rules())
	}
}

func TestDNSLogEvictsOldestWhenFull(t *testing.T) {
	var l dnsLog
	now := time.Now()
	for i := 0; i < dnsLogMax; i++ {
		l.record(time.Duration(i).String()+".ads.example", now.Add(time.Duration(i)*time.Millisecond))
	}
	l.record("newest.ads.example", now.Add(time.Hour))
	if len(l.m) > dnsLogMax {
		t.Fatalf("记录数超过上限: %d", len(l.m))
	}
	if _, ok := l.m["newest.ads.example"]; !ok {
		t.Fatal("最新记录应保留")
	}
	if _, ok := l.m["0s.ads.example"]; ok {
		t.Fatal("最旧记录应被淘汰")
	}
}

// 附加列表在管理锁之外下载；下载失败时不开启，并告诉用户原因。
func TestSetAdBlockExtraPrefetchesAndPersists(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.json")
	cfg := config.Default()
	cfg.AdBlock.Enabled = true
	if err := cfg.Save(path); err != nil {
		t.Fatal(err)
	}
	m := New(path, cfg, policy.New(), egress.NewRegistry())

	if _, err := m.SetAdBlockExtra("nope", true); err == nil {
		t.Fatal("未知列表应报错")
	}
	m.FetchRuleSet = func(context.Context, string, string) error { return errors.New("网络不可达") }
	if _, err := m.SetAdBlockExtra("xiaomi", true); err == nil {
		t.Fatal("下载失败时不应开启")
	}
	if len(m.Cfg.AdBlock.Extras) != 0 {
		t.Fatalf("下载失败后配置不应变化: %v", m.Cfg.AdBlock.Extras)
	}

	var fetched []string
	m.FetchRuleSet = func(_ context.Context, name, _ string) error {
		if !m.mu.TryRLock() {
			t.Error("下载时不应持有管理锁")
		} else {
			m.mu.RUnlock()
		}
		fetched = append(fetched, name)
		return nil
	}
	for _, k := range []string{"apple", "xiaomi"} {
		if _, err := m.SetAdBlockExtra(k, true); err != nil {
			t.Fatal(err)
		}
	}
	if len(fetched) != 2 || fetched[0] != "ad-block-apple" {
		t.Fatalf("应预取对应规则集: %v", fetched)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var saved struct {
		AdBlock struct {
			Extras []string `json:"extras"`
		} `json:"ad_block"`
	}
	if err := json.Unmarshal(raw, &saved); err != nil {
		t.Fatal(err)
	}
	if got := saved.AdBlock.Extras; len(got) != 2 || got[0] != "xiaomi" || got[1] != "apple" {
		t.Fatalf("应按目录顺序落盘: %v", got)
	}
	if _, err := m.SetAdBlockExtra("xiaomi", false); err != nil {
		t.Fatal(err)
	}
	st := m.Status("v")
	on := 0
	for _, x := range st.AdBlock.Extras {
		if x.Enabled {
			on++
			if x.Key != "apple" {
				t.Errorf("只应剩苹果开启: %+v", x)
			}
		}
	}
	if on != 1 || len(st.AdBlock.Extras) != len(config.AdBlockExtras) {
		t.Fatalf("状态应列出全部附加列表: %+v", st.AdBlock.Extras)
	}
}
