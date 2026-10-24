package manage

import (
	"strings"
	"time"

	"github.com/w0ven/5gpn-next/internal/apps"
	"github.com/w0ven/5gpn-next/internal/config"
	"github.com/w0ven/5gpn-next/internal/ruleset"
)

// RuleSetState 是规则集状态页的一行。
type RuleSetState struct {
	Name    string
	Label   string
	Entries int
	// Updated 是内容最后一次变化（缓存文件写入）的时间。
	Updated time.Time
	// Check 是最近一次联网检查的结果；从未检查过时为零值。
	Check ruleset.Status
	// IntervalHours 为负数表示不自动更新。
	IntervalHours int
	Local         bool
}

// Failing 报告最近一次检查是否失败。
func (s RuleSetState) Failing() bool { return s.Check.Fails > 0 }

// RuleSetStates 返回当前生效的全部规则集及其更新状态。
func (m *Manager) RuleSetStates() []RuleSetState {
	sets := m.EffectiveRuleSets()
	f := ruleset.NewFetcher(ruleSetDir)
	statuses := f.Statuses()

	m.mu.RLock()
	pol := m.Policy
	m.mu.RUnlock()

	out := make([]RuleSetState, 0, len(sets))
	for _, rs := range sets {
		st := RuleSetState{
			Name:          rs.Name,
			Label:         ruleSetLabel(rs.Name),
			Check:         statuses[rs.Name],
			IntervalHours: rs.IntervalHours,
			Local:         rs.Path != "",
		}
		if st.IntervalHours == 0 {
			st.IntervalHours = 24
		}
		if pol != nil {
			if rs.Kind == "ipcidr" {
				st.Entries = pol.CIDRSetLen(rs.Name)
			} else {
				st.Entries = pol.DomainSetLen(rs.Name)
			}
		}
		if t, ok := f.CacheInfo(rs.Name); ok {
			st.Updated = t
		}
		out = append(out, st)
	}
	return out
}

func ruleSetLabel(name string) string {
	switch name {
	case "cn-domain":
		return "国内域名"
	case "geoip:cn":
		return "国内 IP"
	case config.AdBlockRuleSetName:
		return "广告拦截（anti-AD）"
	}
	if key, ok := strings.CutPrefix(name, config.AdBlockRuleSetName+"-"); ok {
		if x, ok := config.AdBlockExtraByKey(key); ok {
			return "附加拦截：" + x.Name
		}
	}
	if apps.IsListRuleSet(name) {
		for _, a := range apps.All() {
			for _, l := range a.Lists {
				if apps.RuleSetName(l) == name {
					return "应用分流：" + a.Name
				}
			}
		}
	}
	return name
}
