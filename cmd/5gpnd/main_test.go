package main

import (
	"net/http"
	"net/http/httptest"
	"net/netip"
	"path/filepath"
	"strings"
	"testing"

	"github.com/w0ven/5gpn-next/internal/config"
	"github.com/w0ven/5gpn-next/internal/manage"
	"github.com/w0ven/5gpn-next/internal/policy"
	"github.com/w0ven/5gpn-next/internal/ruleset"
)

func TestHTTPServiceRejectsPublicSourceBeforeRouting(t *testing.T) {
	h := &httpService{ClientCIDR: netip.MustParsePrefix("172.22.0.0/16")}
	req := httptest.NewRequest(http.MethodGet, "https://gateway.example/5gpn/stats", nil)
	req.RemoteAddr = "203.0.113.5:45678"
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	if w.Code != http.StatusForbidden {
		t.Fatalf("status=%d, want 403", w.Code)
	}
}

func TestHTTPServiceAllowsClientAndLoopback(t *testing.T) {
	h := &httpService{ClientCIDR: netip.MustParsePrefix("172.22.0.0/16")}
	for _, remote := range []string{"172.22.9.8:45678", "127.0.0.1:45678", "[::1]:45678"} {
		req := httptest.NewRequest(http.MethodGet, "https://gateway.example/missing", nil)
		req.RemoteAddr = remote
		w := httptest.NewRecorder()
		h.ServeHTTP(w, req)
		if w.Code != http.StatusNotFound {
			t.Fatalf("remote=%s status=%d, want 404 after access allowed", remote, w.Code)
		}
	}
}

func readyEngine() *policy.Engine {
	e := policy.New()
	ds := ruleset.NewDomainSet()
	ds.AddRule("baidu.com")
	e.RegisterDomainSet("cn-domain", ds)
	cs := ruleset.NewCIDRSet()
	cs.AddRule("39.156.0.0/16")
	cs.Finalize()
	e.RegisterCIDRSet("geoip:cn", cs)
	return e
}

func target(t *testing.T, s string) policy.Target {
	t.Helper()
	got, err := policy.ParseTarget(s)
	if err != nil {
		t.Fatal(err)
	}
	return got
}

// 切换国外默认出口只改变 FINAL：自定义分流、国内域名和国内 IP
// 都必须保持原有决策，不得跟着 FINAL 一起切换。
func TestForeignEgressDoesNotOverrideRulesOrDomestic(t *testing.T) {
	cfg := config.Default()
	cfg.Rules = []string{
		"DOMAIN-SUFFIX,openai.com,proxy:special",
		"DOMAIN-SUFFIX,example.org,direct",
	}
	cfg.Final = "proxy:hinet"

	e := readyEngine()
	if err := applyRules(cfg, e); err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name   string
		target string
		action policy.Action
		egress string
	}{
		{"国内域名仍直连", "www.baidu.com:443", policy.ActionDirect, ""},
		{"国内裸 IP 仍直连", "39.156.66.10:443", policy.ActionDirect, ""},
		{"自定义指定出口不变", "api.openai.com:443", policy.ActionProxy, "special"},
		{"自定义 DIRECT 不变", "www.example.org:443", policy.ActionDirect, ""},
		{"仅国外未命中流量走 hinet", "www.google.com:443", policy.ActionProxy, "hinet"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			d := e.Match(target(t, tc.target))
			if d.Action != tc.action || d.Egress != tc.egress {
				t.Fatalf("%s => action=%s egress=%q rule=%s; want %s %q",
					tc.target, d.Action, d.Egress, d.Rule, tc.action, tc.egress)
			}
		})
	}
}

func TestResolvedGeoIPKeepsCustomRulesFirst(t *testing.T) {
	cfg := config.Default()
	cfg.Rules = []string{
		"DOMAIN-SUFFIX,override.example,proxy:special",
	}
	cfg.Final = "proxy:hinet"

	e := readyEngine()
	if err := applyRules(cfg, e); err != nil {
		t.Fatal(err)
	}
	cn := []netip.Addr{netip.MustParseAddr("39.156.66.10")}
	foreign := []netip.Addr{netip.MustParseAddr("142.250.72.36")}

	cases := []struct {
		name   string
		host   string
		addrs  []netip.Addr
		action policy.Action
		egress string
		rule   string
	}{
		{"未收录国内域名由 GEOIP 兜底", "unknown.example:443", cn, policy.ActionDirect, "", "GEOIP,cn"},
		{"自定义规则覆盖 GEOIP", "api.override.example:443", cn, policy.ActionProxy, "special", "DOMAIN-SUFFIX,override.example"},
		{"国外 IP 落到国外默认出口", "foreign.example:443", foreign, policy.ActionProxy, "hinet", "FINAL"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			d := e.MatchResolved(target(t, tc.host), tc.addrs)
			if d.Action != tc.action || d.Egress != tc.egress || d.Rule != tc.rule {
				t.Fatalf("got action=%s egress=%q rule=%q; want %s %q %q",
					d.Action, d.Egress, d.Rule, tc.action, tc.egress, tc.rule)
			}
		})
	}
}

// 国内规则缺失时宁可 DIRECT，也不能静默退化为全局代理。
func TestProxyFinalFallsBackDirectWhenDomesticRulesMissing(t *testing.T) {
	cfg := config.Default()
	cfg.Final = "proxy:hinet"
	e := policy.New()
	if err := applyRules(cfg, e); err != nil {
		t.Fatal(err)
	}
	d := e.Match(target(t, "www.google.com:443"))
	if d.Action != policy.ActionDirect {
		t.Fatalf("missing domestic rules must fail closed to DIRECT, got %s %q", d.Action, d.Egress)
	}
}

// 应用分流：具体应用先于 Google，用户规则与广告拦截先于应用，
// 清单未下载时内置核心域名仍把关键流量送到选定出口。
func TestAppRoutingOrder(t *testing.T) {
	cfg := config.Default()
	cfg.AdBlock.Enabled = true
	cfg.Rules = []string{"DOMAIN,music.youtube.com,proxy:special"}
	cfg.Final = "proxy:nuross"
	cfg.Apps = map[string]string{"youtube": "ctc", "google": "DIRECT"}

	e := readyEngine()
	yt := ruleset.NewDomainSet()
	yt.AddRule("+.youtube.com")
	yt.AddRule("+.googlevideo.com")
	e.RegisterDomainSet("app-youtube", yt)
	g := ruleset.NewDomainSet()
	g.AddRule("+.google.com")
	g.AddRule("+.youtube.com")
	g.AddRule("+.googleapis.com")
	e.RegisterDomainSet("app-google", g)
	ad := ruleset.NewDomainSet()
	ad.AddRule("ads.youtube.com")
	e.RegisterDomainSet(config.AdBlockRuleSetName, ad)
	if err := applyRules(cfg, e); err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		target string
		action policy.Action
		egress string
	}{
		{"www.youtube.com:443", policy.ActionProxy, "ctc"},
		{"rr2---sn-abc.googlevideo.com:443", policy.ActionProxy, "ctc"},
		{"youtubei.googleapis.com:443", policy.ActionProxy, "ctc"},
		{"www.google.com:443", policy.ActionProxy, "DIRECT"},
		{"play.googleapis.com:443", policy.ActionProxy, "DIRECT"},
		{"music.youtube.com:443", policy.ActionProxy, "special"},
		{"ads.youtube.com:443", policy.ActionBlock, ""},
		{"www.baidu.com:443", policy.ActionDirect, ""},
		{"chatgpt.com:443", policy.ActionProxy, "nuross"},
	}
	for _, tc := range cases {
		d := e.Match(target(t, tc.target))
		if d.Action != tc.action || d.Egress != tc.egress {
			t.Errorf("%s => action=%s egress=%q rule=%s; want %s %q",
				tc.target, d.Action, d.Egress, d.Rule, tc.action, tc.egress)
		}
	}
}

func TestAppRoutingCoreWorksWithoutList(t *testing.T) {
	cfg := config.Default()
	cfg.Final = "proxy:nuross"
	cfg.Apps = map[string]string{"youtube": "ctc"}
	e := readyEngine() // 未注册 app-youtube：模拟清单首次下载失败
	if err := applyRules(cfg, e); err != nil {
		t.Fatal(err)
	}
	for _, h := range []string{"www.youtube.com:443", "rr1---sn-x.googlevideo.com:443", "i.ytimg.com:443", "youtubei.googleapis.com:443"} {
		if d := e.Match(target(t, h)); d.Egress != "ctc" {
			t.Errorf("%s => egress=%q rule=%s，清单缺失时核心域名仍应走 ctc", h, d.Egress, d.Rule)
		}
	}
}

// TestEgressAlertsFollowLiveToggle Bot 里切换告警开关必须立即生效，
// 不能只在启动时决定是否接上推送。
func TestEgressAlertsFollowLiveToggle(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.json")
	cfg := &config.Config{}
	if err := cfg.Save(path); err != nil {
		t.Fatal(err)
	}
	mgr := manage.New(path, cfg, nil, nil)
	var got []string
	hub := &notifyHub{}
	hub.Set(func(s string) { got = append(got, s) })
	send := egressAlerts(mgr, hub)

	send("a")
	off, on := true, false
	if err := mgr.SetMonitorAlerts(0, 0, &off); err != nil {
		t.Fatal(err)
	}
	send("b")
	if err := mgr.SetMonitorAlerts(0, 0, &on); err != nil {
		t.Fatal(err)
	}
	send("c")
	if strings.Join(got, ",") != "a,c" {
		t.Fatalf("推送 = %v, 期望 [a c]", got)
	}
}

func TestRulesetAlertsOnceAndRecover(t *testing.T) {
	sets := []config.RuleSetConfig{{Name: "cn-domain", URL: "https://x"}, {Name: "local", Path: "/x"}}
	alerted := map[string]bool{}
	st := map[string]ruleset.Status{"cn-domain": {Fails: 2, LastError: "HTTP 404"}}
	if got := rulesetAlerts(sets, st, alerted); len(got) != 0 {
		t.Fatalf("未到阈值不应告警: %v", got)
	}
	st["cn-domain"] = ruleset.Status{Fails: 3, LastError: "HTTP 404"}
	got := rulesetAlerts(sets, st, alerted)
	if len(got) != 1 || !strings.Contains(got[0], "HTTP 404") {
		t.Fatalf("应告警一次: %v", got)
	}
	st["cn-domain"] = ruleset.Status{Fails: 4, LastError: "HTTP 404"}
	if got := rulesetAlerts(sets, st, alerted); len(got) != 0 {
		t.Fatalf("不应重复告警: %v", got)
	}
	st["cn-domain"] = ruleset.Status{}
	if got := rulesetAlerts(sets, st, alerted); len(got) != 1 || !strings.Contains(got[0], "恢复") {
		t.Fatalf("应发恢复通知: %v", got)
	}
}
