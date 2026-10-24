package main

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/w0ven/5gpn-next/internal/config"
	"github.com/w0ven/5gpn-next/internal/egress"
	"github.com/w0ven/5gpn-next/internal/manage"
	"github.com/w0ven/5gpn-next/internal/policy"
)

// newRuleManager 用与生产相同的 applyRules 装配热重载。
func newRuleManager(t *testing.T) *manage.Manager {
	t.Helper()
	cfg := config.Default()
	cfg.Final = "proxy:nuross"
	cfg.Egress = append(cfg.Egress,
		config.EgressConfig{Name: "nuross", Type: "socks5", Addr: "127.0.0.1:7891", DisplayName: "🇯🇵 Nuross"},
		config.EgressConfig{Name: "att", Type: "socks5", Addr: "127.0.0.1:7892", DisplayName: "🇺🇸ATT"})
	path := filepath.Join(t.TempDir(), "config.json")
	if err := cfg.Save(path); err != nil {
		t.Fatal(err)
	}
	m := manage.New(path, cfg, readyEngine(), egress.NewRegistry())
	m.Reload = func() (*policy.Engine, *egress.Registry, error) {
		e := readyEngine()
		if err := applyRules(m.Cfg, e); err != nil {
			return nil, nil, err
		}
		return e, egress.NewRegistry(), nil
	}
	return m
}

// TestAddRuleRejectsRulesThatWouldNotWork 以前这些都提示“添加成功”却不生效，
// 或者把流量悄悄送到网关本机直出。
func TestAddRuleRejectsRulesThatWouldNotWork(t *testing.T) {
	m := newRuleManager(t)
	for _, r := range []string{
		"DOMAN-SUFFIX,typo.com,block",
		"DOMAIN-SUFFIX,x.com,proxy:nosuch",
		"FINAL,,block",
		"MATCH,,proxy:att",
		"DOMAIN-SUFFIX,x.com",
		"DOMAIN-SUFFIX,,block",
		"IP-CIDR,1.2.3.0/33,block",
		"RULE-SET,no-such-set,block",
		"DOMAIN-SUFFIX,x.com,whatever",
	} {
		if _, err := m.AddRule(r); err == nil {
			t.Errorf("应拒绝: %s", r)
		}
	}
	if n := len(m.Rules()); n != 0 {
		t.Fatalf("拒绝的规则不应写入，现有 %d 条: %v", n, m.Rules())
	}
}

func TestAddRuleNormalizesAndExplainsEffect(t *testing.T) {
	m := newRuleManager(t)
	cases := []struct{ in, stored, msg string }{
		{"domain-suffix, *.OpenAI.com ,proxy:🇺🇸ATT", "DOMAIN-SUFFIX,openai.com,proxy:att", "openai.com 经出口 🇺🇸ATT"},
		{"DOMAIN,example.cn,direct", "DOMAIN,example.cn,direct", "由手机直连"},
		{"DOMAIN-KEYWORD,ads,reject", "DOMAIN-KEYWORD,ads,block", "将被拦截"},
		{"IP-CIDR,8.8.8.8,proxy:DIRECT", "IP-CIDR,8.8.8.8/32,proxy:DIRECT", "网关本机直出"},
		{"DOMAIN-SUFFIX,claude.ai,proxy", "DOMAIN-SUFFIX,claude.ai,proxy", "走默认出口"},
	}
	for _, tc := range cases {
		msg, err := m.AddRule(tc.in)
		if err != nil {
			t.Fatalf("%s: %v", tc.in, err)
		}
		if m.Rules()[0] != tc.stored {
			t.Errorf("%s: 存为 %q，期望 %q", tc.in, m.Rules()[0], tc.stored)
		}
		if !strings.Contains(msg, tc.msg) {
			t.Errorf("%s: 说明 %q 应包含 %q", tc.in, msg, tc.msg)
		}
	}
	if _, err := m.AddRule("DOMAIN-SUFFIX,OPENAI.com,proxy:att"); err == nil {
		t.Error("重复规则应拒绝")
	}

	// 不带出口名的 proxy 跟随默认出口，而不是找不到出口后回退本机直出。
	d := m.Policy.Match(target(t, "claude.ai:443"))
	if d.Action != policy.ActionProxy || d.Egress != "nuross" {
		t.Fatalf("proxy 应跟随默认出口 nuross，得到 %s %q", d.Action, d.Egress)
	}
}

// TestAddRuleWarnsWhenShadowedByBuiltin 私网段被内置规则先命中，用户规则对它无效。
func TestAddRuleWarnsWhenShadowedByBuiltin(t *testing.T) {
	m := newRuleManager(t)
	msg, err := m.AddRule("IP-CIDR,192.168.1.0/24,proxy:att")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(msg, "不生效") {
		t.Fatalf("应说明被内置规则抢先命中: %q", msg)
	}
}

func TestRemoveRuleChecksExpectedText(t *testing.T) {
	m := newRuleManager(t)
	for _, r := range []string{"DOMAIN,a.com,block", "DOMAIN,b.com,block"} {
		if _, err := m.AddRule(r); err != nil {
			t.Fatal(err)
		}
	}
	// 列表现为 [b, a]；按页面上旧的序号 0 删 a 必须被拒。
	if err := m.RemoveRule(0, "DOMAIN,a.com,block"); err == nil {
		t.Fatal("序号与原文不一致时应拒绝删除")
	}
	if err := m.RemoveRule(1, "DOMAIN,a.com,block"); err != nil {
		t.Fatal(err)
	}
	if got := m.Rules(); len(got) != 1 || got[0] != "DOMAIN,b.com,block" {
		t.Fatalf("剩余规则 = %v", got)
	}
}

func TestRuleProblemsFlagsLegacyRules(t *testing.T) {
	m := newRuleManager(t)
	m.Cfg.Rules = []string{"DOMAIN,ok.com,block", "FINAL,,proxy:att", "DOMAIN,x.com,proxy:gone"}
	p := m.RuleProblems()
	if len(p) != 2 || p[1] == "" || p[2] == "" {
		t.Fatalf("problems = %v", p)
	}
}
