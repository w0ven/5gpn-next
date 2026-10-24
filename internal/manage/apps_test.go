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

	"github.com/w0ven/5gpn-next/internal/apps"
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
	cfg.AppsChanged = map[string]int64{"youtube": now.Add(-2 * time.Hour).Unix()}
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
		Apps        map[string]string `json:"apps"`
		AppsChanged map[string]int64  `json:"apps_changed"`
	}
	if err := json.Unmarshal(raw, &saved); err != nil {
		t.Fatal(err)
	}
	if saved.Apps["youtube"] != "DIRECT" {
		t.Fatalf("未落盘: %+v", saved.Apps)
	}
	// 变更时间与设置一起落盘，网关重启后核对窗口仍从改出口时算起。
	if ts := saved.AppsChanged["youtube"]; time.Since(time.Unix(ts, 0)) > time.Minute {
		t.Fatalf("变更时间未落盘: %+v", saved.AppsChanged)
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

// 改出口之前的转发不能算作「没走选定出口」；那些域名改为按当前规则复核，
// 这样手机暂时没有新流量时也能判断分流是否正确。
func TestCheckAppSeparatesHistoryFromCurrentRules(t *testing.T) {
	dir := t.TempDir()
	now := time.Now()
	lines := []string{
		traceLine(t, now.Add(-3*time.Hour), "rr3---sn-x.googlevideo.com:443", "FINAL → 代理:nuross", "nuross"),
		traceLine(t, now.Add(-3*time.Hour), "youtubei.googleapis.com:443", "DOMAIN-SUFFIX,googleapis.com → 代理:nuross", "nuross"),
		traceLine(t, now.Add(-3*time.Hour), "www.youtube.com:443", "FINAL → 直连（网关出口）", "DIRECT"),
	}
	logPath := filepath.Join(dir, "trace.jsonl")
	if err := os.WriteFile(logPath, []byte(strings.Join(lines, "\n")+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	cfg := config.Default()
	cfg.LogPath = logPath
	cfg.Apps = map[string]string{"youtube": "ctc"}
	cfg.AppsChanged = map[string]int64{"youtube": now.Add(-time.Hour).Unix()}
	eng := policy.New()
	ds := ruleset.NewDomainSet()
	for _, d := range []string{"+.youtube.com", "+.googlevideo.com", "+.youtubei.googleapis.com", "+.ytimg.com", "+.ggpht.com"} {
		ds.AddRule(d)
	}
	eng.RegisterDomainSet("app-youtube", ds)
	ads := ruleset.NewDomainSet()
	ads.AddRule("+.ads.youtube.com")
	eng.RegisterDomainSet("ad-block", ads)
	// 与线上编译顺序一致：广告拦截 → YouTube（核心域名 + 清单）→ Google。
	yt, _ := apps.Get("youtube")
	rules := []policy.Rule{{Kind: policy.KindRuleSet, Value: "ad-block", Action: policy.ActionBlock}}
	for _, d := range yt.Core {
		rules = append(rules, policy.Rule{Kind: policy.KindDomainSuffix, Value: d, Action: policy.ActionProxy, Egress: "ctc"})
	}
	rules = append(rules,
		policy.Rule{Kind: policy.KindRuleSet, Value: "app-youtube", Action: policy.ActionProxy, Egress: "ctc"},
		policy.Rule{Kind: policy.KindDomainSuffix, Value: "googleapis.com", Action: policy.ActionProxy, Egress: "att"})
	for _, r := range rules {
		if err := eng.AddRule(r); err != nil {
			t.Fatal(err)
		}
	}
	eng.SetFinal(policy.ActionProxy, "nuross")
	m := New(filepath.Join(dir, "config.json"), cfg, eng, egress.NewRegistry())

	res, err := m.CheckApp("youtube")
	if err != nil {
		t.Fatal(err)
	}
	if res.SinceKind != SinceChanged || len(res.Domains) != 0 || res.Mismatch != 0 {
		t.Fatalf("改出口之前的记录不应计入实际出口: kind=%s domains=%+v", res.SinceKind, res.Domains)
	}
	got := map[string]AppRoute{}
	for _, r := range res.Current {
		got[r.Host] = r
	}
	for _, h := range []string{"*.googlevideo.com", "youtubei.googleapis.com", "www.youtube.com", "ytimg.com", "youtu.be"} {
		if r := got[h]; !r.OK || r.Egress != "ctc" {
			t.Errorf("%s 按当前规则应走 ctc: %+v", h, r)
		}
	}
	if _, dup := got["googlevideo.com"]; dup {
		t.Error("已见过的边缘节点覆盖了核心域名，不应重复列出")
	}
	if res.CurrentMismatch != 0 {
		t.Errorf("当前规则不应有异常: %+v", res.Current)
	}

	// 改出口时间未知（旧版本设置）时，以网关启动为界。
	delete(m.Cfg.AppsChanged, "youtube")
	if res, _ := m.CheckApp("youtube"); res.SinceKind != SinceStarted || len(res.Domains) != 0 {
		t.Fatalf("变更时间未知时应以启动时刻为界: %+v", res)
	}
}

func TestRouteNowTreatsBlockedAsExpected(t *testing.T) {
	eng := policy.New()
	ads := ruleset.NewDomainSet()
	ads.AddRule("+.ads.youtube.com")
	eng.RegisterDomainSet("ad-block", ads)
	if err := eng.AddRule(policy.Rule{Kind: policy.KindRuleSet, Value: "ad-block", Action: policy.ActionBlock}); err != nil {
		t.Fatal(err)
	}
	eng.SetFinal(policy.ActionDirect, "")
	yt, _ := apps.Get("youtube")
	routes, bad := routeNow(eng, yt, map[string]string{"ads.youtube.com": "ads.youtube.com"}, "ctc")
	var blocked, direct int
	for _, r := range routes {
		switch {
		case r.Blocked:
			blocked++
			if !r.OK {
				t.Errorf("被拦截的广告域名不应算异常: %+v", r)
			}
		case r.Egress == "DIRECT":
			direct++
		}
	}
	if blocked != 1 || bad != direct || bad == 0 || routes[0].OK {
		t.Fatalf("blocked=%d direct=%d bad=%d routes=%+v", blocked, direct, bad, routes)
	}
}

// TestReadTraceTailIncludesRotatedArchive 轮转后当前日志只剩几条，
// 核对窗口不能因此缩水。
func TestReadTraceTailIncludesRotatedArchive(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "trace.jsonl")
	line := func(ts, host string) string {
		return `{"ts":"` + ts + `","target":"` + host + `:443","steps":[{"stage":"egress","status":"ok","detail":"att"}]}` + "\n"
	}
	if err := os.WriteFile(path+".1", []byte(line("2026-10-24T10:00:00Z", "old.example.com")), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(line("2026-10-24T11:00:00Z", "new.example.com")), 0o644); err != nil {
		t.Fatal(err)
	}
	recs, err := readTraceTail(path, 1<<20, time.Date(2026, 10, 24, 0, 0, 0, 0, time.UTC))
	if err != nil {
		t.Fatal(err)
	}
	if len(recs) != 2 || recs[0].host != "old.example.com" || recs[1].host != "new.example.com" {
		t.Fatalf("recs = %+v", recs)
	}
}
