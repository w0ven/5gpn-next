package manage

import "testing"

func TestRuleSetLabel(t *testing.T) {
	for name, want := range map[string]string{
		"cn-domain":       "国内域名",
		"geoip:cn":        "国内 IP",
		"ad-block":        "广告拦截（anti-AD）",
		"ad-block-xiaomi": "附加拦截：小米 / 红米",
		"my-list":         "my-list",
	} {
		if got := ruleSetLabel(name); got != want {
			t.Errorf("ruleSetLabel(%q) = %q, 期望 %q", name, got, want)
		}
	}
}
