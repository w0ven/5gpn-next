package config

import (
	"strings"
	"testing"
)

func TestAppRuleSetsOnlyForEnabledApps(t *testing.T) {
	c := Default()
	c.AdBlock.Enabled = true
	c.Apps = map[string]string{"meta": "ctc", "youtube": "ctc"}
	names := map[string]int{}
	for _, rs := range c.EffectiveRuleSets() {
		names[rs.Name]++
		if strings.HasPrefix(rs.Name, "app-") && (rs.Kind != "domain" || rs.IntervalHours != 24 || !strings.HasSuffix(rs.URL, ".list")) {
			t.Errorf("应用清单配置异常: %+v", rs)
		}
	}
	for _, want := range []string{AdBlockRuleSetName, "app-youtube", "app-facebook", "app-instagram", "app-whatsapp"} {
		if names[want] != 1 {
			t.Errorf("%s 出现 %d 次，应恰好 1 次", want, names[want])
		}
	}
	if names["app-google"] != 0 || names["app-netflix"] != 0 {
		t.Error("未启用的应用不应下载清单")
	}

	rules := c.AppRules()
	if len(rules) == 0 || !strings.HasSuffix(rules[0], ",proxy:ctc") {
		t.Fatalf("AppRules = %v", rules)
	}
	c.Apps = nil
	if len(c.AppRules()) != 0 {
		t.Error("未启用任何应用时不应生成规则")
	}
}
