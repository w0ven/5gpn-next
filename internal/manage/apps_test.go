package manage

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/w0ven/5gpn-next/internal/config"
	"github.com/w0ven/5gpn-next/internal/egress"
	"github.com/w0ven/5gpn-next/internal/policy"
	"github.com/w0ven/5gpn-next/internal/ruleset"
)

func traceLine(t *testing.T, ts time.Time, target, rule, eg string) string {
	t.Helper()
	steps := []map[string]any{{"stage": "policy", "status": "ok", "detail": rule}}
	if eg != "" {
		steps = append(steps, map[string]any{"stage": "egress", "status": "ok", "detail": eg})
	}
	b, err := json.Marshal(map[string]any{"ts": ts.UTC().Format(time.RFC3339Nano), "target": target, "ok": true, "steps": steps})
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func TestCheckAppFindsMismatchAndSuspects(t *testing.T) {
	dir := t.TempDir()
	now := time.Now()
	lines := []string{
		traceLine(t, now.Add(-48*time.Hour), "www.youtube.com:443", "x", "nuross"), // 窗口之外
		traceLine(t, now.Add(-time.Hour), "www.youtube.com:443", "RULE-SET,app-youtube", "ctc"),
		traceLine(t, now.Add(-50*time.Minute), "rr1---sn-a.googlevideo.com:443", "DOMAIN-SUFFIX,googlevideo.com", "ctc"),
		traceLine(t, now.Add(-40*time.Minute), "rr5---sn-b.googlevideo.com:443", "DOMAIN-SUFFIX,googlevideo.com", "ctc"),
		traceLine(t, now.Add(-30*time.Minute), "i.ytimg.com:443", "DOMAIN,i.ytimg.com", "nuross"),
		traceLine(t, now.Add(-20*time.Minute), "youtube-ui.example.net:443", "FINAL", "nuross"),
		traceLine(t, now.Add(-10*time.Minute), "www.google.com:443", "FINAL", "nuross"),
		traceLine(t, now.Add(-5*time.Minute), "ads.youtube.com:443", "RULE-SET,ad-block", ""), // 被拦截，无出口
	}
	logPath := filepath.Join(dir, "trace.jsonl")
	if err := os.WriteFile(logPath, []byte(strings.Join(lines, "\n")+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	cfg := config.Default()
	cfg.LogPath = logPath
	cfg.Apps = map[string]string{"youtube": "ctc"}
	eng := policy.New()
	ds := ruleset.NewDomainSet()
	ds.AddRule("+.youtube.com")
	eng.RegisterDomainSet("app-youtube", ds)
	m := New(filepath.Join(dir, "config.json"), cfg, eng, egress.NewRegistry())

	res, err := m.CheckApp("youtube")
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]AppDomain{}
	for _, d := range res.Domains {
		got[d.Host] = d
	}
	if len(got) != 3 {
		t.Fatalf("应命中 3 个域名，实际 %+v", res.Domains)
	}
	if d := got["*.googlevideo.com"]; d.Count != 2 || !d.OK {
		t.Errorf("googlevideo 边缘节点应归并且全部走 ctc: %+v", d)
	}
	if d := got["i.ytimg.com"]; d.OK || d.Rule != "DOMAIN,i.ytimg.com" || d.Egresses["nuross"] != 1 {
		t.Errorf("i.ytimg.com 应判为未走选定出口并带出命中规则: %+v", d)
	}
	if res.Mismatch != 1 || res.Domains[0].Host != "i.ytimg.com" {
		t.Errorf("异常域名应计数并排在最前: mismatch=%d first=%s", res.Mismatch, res.Domains[0].Host)
	}
	if len(res.Suspects) != 1 || res.Suspects[0].Host != "youtube-ui.example.net" {
		t.Errorf("疑似漏网应只有 youtube-ui.example.net: %+v", res.Suspects)
	}
}

func TestCheckAppNeedsSelectedEgress(t *testing.T) {
	m := New("", config.Default(), policy.New(), egress.NewRegistry())
	if _, err := m.CheckApp("youtube"); err == nil {
		t.Fatal("未选出口时应提示先选择出口")
	}
	if _, err := m.CheckApp("nope"); err == nil {
		t.Fatal("未知应用应报错")
	}
}

func TestSetAppEgressValidatesAndPersists(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.json")
	cfg := config.Default()
	if err := cfg.Save(path); err != nil {
		t.Fatal(err)
	}
	m := New(path, cfg, policy.New(), egress.NewRegistry())

	if err := m.SetAppEgress("nope", "DIRECT"); err == nil {
		t.Error("未知应用应报错")
	}
	if err := m.SetAppEgress("youtube", "missing"); err == nil {
		t.Error("不存在的出口应报错")
	}
	if err := m.SetAppEgress("youtube", "DIRECT"); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var saved struct {
		Apps map[string]string `json:"apps"`
	}
	if err := json.Unmarshal(raw, &saved); err != nil {
		t.Fatal(err)
	}
	if saved.Apps["youtube"] != "DIRECT" {
		t.Fatalf("未落盘: %+v", saved.Apps)
	}
	st, _ := m.App("youtube")
	if st.Egress != "DIRECT" || st.EgressDisplay != "本机直出" || st.Core == 0 {
		t.Errorf("状态异常: %+v", st)
	}
	if err := m.SetAppEgress("youtube", ""); err != nil {
		t.Fatal(err)
	}
	if st, _ := m.App("youtube"); st.Egress != "" || st.EgressDisplay != "跟随默认" {
		t.Errorf("改回跟随默认失败: %+v", st)
	}
}

// 清单下载必须在管理锁之外：下载期间面板/Bot 仍能读取状态；下载失败不阻止设置。
func TestSetAppEgressPrefetchesOutsideLock(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.json")
	cfg := config.Default()
	if err := cfg.Save(path); err != nil {
		t.Fatal(err)
	}
	m := New(path, cfg, policy.New(), egress.NewRegistry())
	var fetched []string
	m.FetchRuleSet = func(ctx context.Context, name, url string) error {
		_ = m.Apps() // 若在锁内调用会死锁
		fetched = append(fetched, name+" "+url)
		return errors.New("网络不可达")
	}
	if err := m.SetAppEgress("meta", "DIRECT"); err != nil {
		t.Fatalf("清单下载失败不应阻止设置: %v", err)
	}
	if len(fetched) != 3 || !strings.HasPrefix(fetched[0], "app-facebook https://") {
		t.Fatalf("应预取 3 份清单: %v", fetched)
	}
	if st, _ := m.App("meta"); st.Egress != "DIRECT" {
		t.Fatalf("设置未生效: %+v", st)
	}
	fetched = nil
	if err := m.SetAppEgress("meta", ""); err != nil || len(fetched) != 0 {
		t.Fatalf("改回跟随默认时不应下载: err=%v fetched=%v", err, fetched)
	}
}
