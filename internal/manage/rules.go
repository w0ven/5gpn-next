package manage

import (
	"fmt"
	"net/netip"
	"strings"

	"github.com/w0ven/5gpn-next/internal/config"
	"github.com/w0ven/5gpn-next/internal/policy"
)

// 自定义规则支持的类型。FINAL/MATCH 不在其中：默认出口由配置的 final
// 决定，写成规则会被它覆盖，看起来添加成功却永远不生效。
var ruleKinds = []string{"DOMAIN", "DOMAIN-SUFFIX", "DOMAIN-KEYWORD", "IP-CIDR", "GEOIP", "RULE-SET"}

// AddRule 校验并插入一条自定义规则，返回该规则实际效果的说明。
//
// 新规则插到最前，便于覆盖既有的大规则集。
func (m *Manager) AddRule(rule string) (string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	norm, err := m.normalizeRuleLocked(rule)
	if err != nil {
		return "", err
	}
	for _, r := range m.Cfg.Rules {
		if strings.EqualFold(strings.TrimSpace(r), norm) {
			return "", fmt.Errorf("规则 %s 已存在", norm)
		}
	}
	m.Cfg.Rules = append([]string{norm}, m.Cfg.Rules...)
	if err := m.saveAndReloadLocked(); err != nil {
		return "", err
	}
	return m.ruleEffectLocked(norm), nil
}

// RemoveRule 删除第 idx 条规则。expect 非空时必须与该位置的规则一致：
// 列表在用户确认期间可能被另一端（Bot/面板）改过，序号会整体错位。
func (m *Manager) RemoveRule(idx int, expect string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if idx < 0 || idx >= len(m.Cfg.Rules) {
		return fmt.Errorf("规则列表已变化，请刷新后重试")
	}
	if expect != "" && strings.TrimSpace(m.Cfg.Rules[idx]) != strings.TrimSpace(expect) {
		return fmt.Errorf("规则列表已变化，为避免误删已取消，请刷新后重试")
	}
	m.Cfg.Rules = append(m.Cfg.Rules[:idx], m.Cfg.Rules[idx+1:]...)
	return m.saveAndReloadLocked()
}

// RuleProblems 返回现有规则中不会生效的条目（序号 → 原因），
// 供列表标出旧版本里未经校验就加进来的规则。
func (m *Manager) RuleProblems() map[int]string {
	m.mu.RLock()
	defer m.mu.RUnlock()
	out := map[int]string{}
	for i, r := range m.Cfg.Rules {
		if _, err := m.normalizeRuleLocked(r); err != nil {
			out[i] = err.Error()
		}
	}
	return out
}

// normalizeRuleLocked 用与编译时相同的语义校验一条规则，并返回规范写法。
// 调用方须持有锁。
func (m *Manager) normalizeRuleLocked(rule string) (string, error) {
	parts := strings.Split(strings.TrimSpace(rule), ",")
	for i := range parts {
		parts[i] = strings.TrimSpace(parts[i])
	}
	if len(parts) == 4 && strings.EqualFold(parts[3], "no-resolve") {
		parts = parts[:3]
	}
	if len(parts) != 3 {
		return "", fmt.Errorf("格式应为 类型,值,动作，例如 DOMAIN-SUFFIX,openai.com,proxy")
	}
	kind, val, act := strings.ToUpper(parts[0]), parts[1], parts[2]
	if kind == "IP-CIDR6" {
		kind = "IP-CIDR"
	}
	switch kind {
	case "FINAL", "MATCH":
		return "", fmt.Errorf("默认出口请在「出口」里切换，写成规则不会生效")
	}
	known := false
	for _, k := range ruleKinds {
		known = known || k == kind
	}
	if !known {
		return "", fmt.Errorf("不支持的类型 %q，可用：%s", parts[0], strings.Join(ruleKinds, " · "))
	}
	if val == "" || strings.ContainsAny(val, " \t") {
		return "", fmt.Errorf("规则值不能为空或含空格")
	}

	switch kind {
	case "DOMAIN", "DOMAIN-SUFFIX":
		val = strings.TrimSuffix(strings.ToLower(val), ".")
		if kind == "DOMAIN-SUFFIX" {
			val = strings.TrimPrefix(strings.TrimPrefix(val, "*"), ".")
		}
		if !validDomain(val) {
			return "", fmt.Errorf("域名 %q 无效", parts[1])
		}
	case "DOMAIN-KEYWORD":
		val = strings.ToLower(val)
	case "IP-CIDR":
		p, err := netip.ParsePrefix(val)
		if err != nil {
			a, aerr := netip.ParseAddr(val)
			if aerr != nil {
				return "", fmt.Errorf("IP 段 %q 无效", val)
			}
			p = netip.PrefixFrom(a, a.BitLen())
		}
		val = p.Masked().String()
	case "GEOIP":
		val = strings.ToUpper(val)
		if !m.ruleSetKnownLocked("geoip:" + strings.ToLower(val)) {
			return "", fmt.Errorf("没有 GEOIP %s 的数据，目前只支持 CN", val)
		}
	case "RULE-SET":
		if !m.ruleSetKnownLocked(val) {
			return "", fmt.Errorf("规则集 %q 不存在", val)
		}
	}

	action, err := m.normalizeActionLocked(act)
	if err != nil {
		return "", err
	}
	return kind + "," + val + "," + action, nil
}

func (m *Manager) normalizeActionLocked(act string) (string, error) {
	switch strings.ToLower(act) {
	case "direct":
		return "direct", nil
	case "block", "reject":
		return "block", nil
	case "proxy":
		return "proxy", nil
	}
	name := act
	if n, ok := strings.CutPrefix(act, "proxy:"); ok {
		name = n
	} else if n, ok := strings.CutPrefix(strings.ToLower(act), "proxy:"); ok {
		name = n
	}
	name = strings.TrimSpace(name)
	// 允许用展示名或不区分大小写的出口名：用户照着界面上看到的名字写，
	// 写错了以前会悄悄回退到网关本机直出。
	for _, e := range m.Cfg.Egress {
		if e.Name == name {
			return "proxy:" + e.Name, nil
		}
	}
	for _, e := range m.Cfg.Egress {
		if strings.EqualFold(e.Name, name) || (e.DisplayName != "" && strings.EqualFold(e.DisplayName, name)) {
			return "proxy:" + e.Name, nil
		}
	}
	var names []string
	for _, e := range m.Cfg.Egress {
		names = append(names, e.Name)
	}
	return "", fmt.Errorf("动作 %q 无效。可用：direct（手机直连）· block（拦截）· proxy（默认出口）· proxy:出口名（%s）",
		act, strings.Join(names, " · "))
}

func (m *Manager) ruleSetKnownLocked(name string) bool {
	if m.Policy != nil && (m.Policy.DomainSetLen(name) > 0 || m.Policy.CIDRSetLen(name) > 0) {
		return true
	}
	for _, rs := range m.Cfg.EffectiveRuleSets() {
		if rs.Name == name {
			return true
		}
	}
	return false
}

func validDomain(s string) bool {
	if s == "" || len(s) > 253 || strings.HasPrefix(s, ".") || strings.Contains(s, "..") {
		return false
	}
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9', r == '-', r == '.', r == '_':
		case r > 127:
		default:
			return false
		}
	}
	return true
}

// ruleEffectLocked 用当前引擎实际匹配一次，说明规则对代表性目标的效果；
// 被更早的内置规则抢先命中时如实说明。调用方须持有锁。
func (m *Manager) ruleEffectLocked(rule string) string {
	parts := strings.SplitN(rule, ",", 3)
	kind, val := parts[0], parts[1]
	what := describeAction(parts[2], m.Cfg)
	var sample string
	switch kind {
	case "DOMAIN", "DOMAIN-SUFFIX":
		sample = val
	case "IP-CIDR":
		if p, err := netip.ParsePrefix(val); err == nil {
			sample = p.Addr().String()
		}
	}
	if sample == "" || m.Policy == nil {
		return "已添加：匹配的流量" + what
	}
	t, err := policy.ParseTarget(sample + ":443")
	if err != nil {
		return "已添加：匹配的流量" + what
	}
	dec := m.Policy.MatchResolved(t, nil)
	if dec.Rule != kind+","+val {
		return fmt.Sprintf("已添加，但 %s 会先命中内置规则 %s，这条规则对它不生效", sample, dec.Rule)
	}
	return fmt.Sprintf("已添加：%s %s", sample, what)
}

// describeAction 把规则动作翻译成用户能看懂的去向。
func describeAction(action string, cfg *config.Config) string {
	switch action {
	case "direct":
		return "由手机直连（不经网关）"
	case "block":
		return "将被拦截"
	case "proxy":
		return "走默认出口"
	}
	name := strings.TrimPrefix(action, "proxy:")
	for _, e := range cfg.Egress {
		if e.Name == name {
			if e.Type == "direct" {
				return "经网关、由网关本机直出"
			}
			return "经出口 " + displayOf(e)
		}
	}
	return "经出口 " + name
}
