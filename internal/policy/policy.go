// Package policy 实现有序 first-match 的分流决策引擎。
//
// 加密 DNS 先按域名决策；连接回到网关后再按目标 IP 做 GEOIP 兜底。
// 两个硬约束：
//  1. 裸 IP 目标没有域名可匹配，GEOIP 判定是必需品而非可选项。
//  2. 出口无 IPv6 时，IPv6 字面量目标必须 fail-fast，否则 App 会判定
//     “无网络连接”。
package policy

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/w0ven/5gpn-next/internal/ruleset"
)

// Action 是决策结果。
type Action string

const (
	ActionDirect Action = "direct" // 网关本机直出
	ActionProxy  Action = "proxy"  // 交给指定出口
	ActionBlock  Action = "block"  // 拒绝
)

// Decision 是一次判定的完整结果，用于 trace 与审计。
type Decision struct {
	Action Action
	Egress string // ActionProxy 时的出口名
	Rule   string // 命中的规则描述，便于用户自助排障
	Index  int    // 命中规则在列表中的序号；-1 表示落到 final
}

// RuleKind 是规则类型。
type RuleKind string

const (
	KindDomain        RuleKind = "DOMAIN"
	KindDomainSuffix  RuleKind = "DOMAIN-SUFFIX"
	KindDomainKeyword RuleKind = "DOMAIN-KEYWORD"
	KindIPCIDR        RuleKind = "IP-CIDR"
	KindRuleSet       RuleKind = "RULE-SET"
	KindGeoIP         RuleKind = "GEOIP"
	KindFinal         RuleKind = "FINAL"
)

// Rule 是一条有序规则。
type Rule struct {
	Kind        RuleKind
	Value       string
	Action      Action
	Egress      string
	domains     *ruleset.DomainSet // KindRuleSet(domain) 用
	cidrs       *ruleset.CIDRSet   // KindRuleSet(ipcidr) / KindGeoIP 用
	prefix      netip.Prefix       // KindIPCIDR 用
	hasPfx      bool
	privateOnly bool   // 是否为私网/回环保护段（不抢占后续显式域名规则）
	matchVal    string // 预转小写的匹配值，避免热路径分配
	dotSuffix   string // KindDomainSuffix 预拼接的 "."+matchVal
	desc        string // 预构建的规则描述 "KIND,VALUE"
}

// Engine 持有规则列表与命名规则集。
type Engine struct {
	mu    sync.RWMutex
	rules []Rule
	final Decision

	// 命名规则集：供 RULE-SET / GEOIP 引用
	domainSets map[string]*ruleset.DomainSet
	cidrSets   map[string]*ruleset.CIDRSet

	// egressHasV6 决定 IPv6 字面量目标是否 fail-fast
	egressHasV6 bool

	// DNS 缓存用于“域名解析后再匹配 IP-CIDR/GEOIP”。
	// Engine 在热重载时整体替换，缓存自然随规则生命周期清空。
	resolveMu    sync.RWMutex
	resolveCache map[string]resolveEntry
	// resolveSlots 限制并发 DNS：Speedtest 会瞬间枚举数千个全球节点，
	// 无上限解析会堆积 goroutine 并把 256MB cgroup 顶穿。
	resolveSlots chan struct{}
	resolver     *net.Resolver
	upstreamSeq  atomic.Uint32
}

type resolveEntry struct {
	addrs  []netip.Addr
	expire time.Time
}

// New 返回默认引擎：final 走 proxy（其余国际出海）。
func New() *Engine {
	return &Engine{
		final:        Decision{Action: ActionProxy, Rule: "FINAL", Index: -1},
		domainSets:   make(map[string]*ruleset.DomainSet),
		cidrSets:     make(map[string]*ruleset.CIDRSet),
		resolveCache: make(map[string]resolveEntry),
		resolveSlots: make(chan struct{}, 32),
	}
}

// SetDNSUpstream 指定域名 GEOIP 兜底解析使用的上游 DNS（形如 "223.5.5.5:53"），
// 避免受宿主机残旧 /etc/resolv.conf（如失效的 127.0.0.1 或被污染的海外公共 DNS）拖累。
func (e *Engine) SetDNSUpstream(upstreams []string) {
	var clean []string
	for _, u := range upstreams {
		u = strings.TrimSpace(u)
		if u == "" {
			continue
		}
		if _, _, err := net.SplitHostPort(u); err != nil {
			u = net.JoinHostPort(u, "53")
		}
		clean = append(clean, u)
	}
	if len(clean) == 0 {
		return
	}
	r := &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
			idx := int(e.upstreamSeq.Add(1)-1) % len(clean)
			d := net.Dialer{Timeout: 300 * time.Millisecond}
			return d.DialContext(ctx, network, clean[idx])
		},
	}
	e.mu.Lock()
	e.resolver = r
	e.mu.Unlock()
}

// SetEgressHasV6 声明出口是否具备 IPv6 能力。
func (e *Engine) SetEgressHasV6(v bool) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.egressHasV6 = v
}

// EgressHasV6 返回出口 IPv6 能力。
func (e *Engine) EgressHasV6() bool {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.egressHasV6
}

// RegisterDomainSet 注册域名规则集，供 RULE-SET 引用。
func (e *Engine) RegisterDomainSet(name string, ds *ruleset.DomainSet) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.domainSets[name] = ds
}

// RegisterCIDRSet 注册 CIDR 规则集，供 RULE-SET / GEOIP 引用。
func (e *Engine) RegisterCIDRSet(name string, cs *ruleset.CIDRSet) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.cidrSets[name] = cs
}

// SetFinal 设置兜底动作。FINAL 只处理未命中任何规则的流量。
func (e *Engine) SetFinal(a Action, egress string) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.final = Decision{Action: a, Egress: egress, Rule: "FINAL", Index: -1}
}

// Final 返回当前运行态的兜底决策。
func (e *Engine) Final() Decision {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.final
}

// DomainSetLen 返回指定域名规则集的条数；未注册时返回 0。
//
// 供状态展示使用：区分“开关已打开”与“规则真的载入了”，
// 避免出现“显示已开启但实际一条没拦”的假成功。
func (e *Engine) DomainSetLen(name string) int {
	e.mu.RLock()
	ds := e.domainSets[name]
	e.mu.RUnlock()
	if ds == nil {
		return 0
	}
	return ds.Len()
}

// CIDRSetLen 返回指定 IP 段规则集的条数；未注册时返回 0。
func (e *Engine) CIDRSetLen(name string) int {
	e.mu.RLock()
	cs := e.cidrSets[name]
	e.mu.RUnlock()
	if cs == nil {
		return 0
	}
	return cs.Len()
}

// DomainSetMatch 报告 host 是否命中指定域名规则集；规则集未注册时为 false。
func (e *Engine) DomainSetMatch(name, host string) bool {
	e.mu.RLock()
	ds := e.domainSets[name]
	e.mu.RUnlock()
	return ds != nil && ds.Match(host)
}

// DomesticRulesReady 报告国内直连的两套强制规则是否都已有效载入。
// 仅“注册了名字”不够，空规则集同样视为未就绪。
func (e *Engine) DomesticRulesReady() bool {
	e.mu.RLock()
	ds := e.domainSets["cn-domain"]
	cs := e.cidrSets["geoip:cn"]
	e.mu.RUnlock()
	return ds != nil && ds.Len() > 0 && cs != nil && cs.Len() > 0
}

// AddRule 追加一条规则，顺序即优先级。
func (e *Engine) AddRule(r Rule) error {
	switch r.Kind {
	case KindIPCIDR:
		p, err := netip.ParsePrefix(r.Value)
		if err != nil {
			return fmt.Errorf("IP-CIDR %q 解析失败: %w", r.Value, err)
		}
		r.prefix = p.Masked()
		r.hasPfx = true
		r.privateOnly = isPrivateOrReservedPrefix(r.prefix)

	case KindRuleSet:
		e.mu.RLock()
		ds, okD := e.domainSets[r.Value]
		cs, okC := e.cidrSets[r.Value]
		e.mu.RUnlock()
		if !okD && !okC {
			return fmt.Errorf("RULE-SET %q 未注册", r.Value)
		}
		r.domains, r.cidrs = ds, cs

	case KindGeoIP:
		e.mu.RLock()
		cs, ok := e.cidrSets["geoip:"+strings.ToLower(r.Value)]
		e.mu.RUnlock()
		if !ok {
			return fmt.Errorf("GEOIP %q 未注册", r.Value)
		}
		r.cidrs = cs

	case KindDomain:
		if r.Value == "" {
			return fmt.Errorf("%s 规则值为空", r.Kind)
		}
		r.matchVal = strings.ToLower(strings.TrimSuffix(r.Value, "."))

	case KindDomainSuffix:
		if r.Value == "" {
			return fmt.Errorf("%s 规则值为空", r.Kind)
		}
		v := strings.ToLower(strings.TrimSuffix(strings.TrimPrefix(r.Value, "."), "."))
		if v == "" {
			return fmt.Errorf("%s 规则值为空", r.Kind)
		}
		r.matchVal = v
		r.dotSuffix = "." + v

	case KindDomainKeyword:
		if r.Value == "" {
			return fmt.Errorf("%s 规则值为空", r.Kind)
		}
		r.matchVal = strings.ToLower(r.Value)

	case KindFinal:
		e.SetFinal(r.Action, r.Egress)
		return nil

	default:
		return fmt.Errorf("未知规则类型 %q", r.Kind)
	}

	r.desc = string(r.Kind) + "," + r.Value
	e.mu.Lock()
	defer e.mu.Unlock()
	e.rules = append(e.rules, r)
	return nil
}

// Len 返回规则条数。
func (e *Engine) Len() int {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return len(e.rules)
}

// Target 是一次待判定的连接目标。
type Target struct {
	Host string // 域名或 IP 字面量（不含端口）
	Port int
	addr netip.Addr
	isIP bool
}

// ParseTarget 从 "host:port" 解析目标；自动识别 IP 字面量。
func ParseTarget(hostport string) (Target, error) {
	host, portStr, err := net.SplitHostPort(hostport)
	if err != nil {
		// 容忍不带端口
		host = strings.Trim(hostport, "[]")
		portStr = "443"
	}
	port := 443
	if p, err := strconv.Atoi(portStr); err == nil && p > 0 && p <= 65535 {
		port = p
	} else if p, err := net.LookupPort("tcp", portStr); err == nil {
		port = p
	}
	return TargetFromHostPort(host, port), nil
}

// TargetFromHostPort 从已分离的 host 与 port 构造 Target，供已知端口的热路径免去拼接与再切分。
func TargetFromHostPort(host string, port int) Target {
	clean := strings.ToLower(strings.TrimSuffix(strings.Trim(host, "[]"), "."))
	if port <= 0 || port > 65535 {
		port = 443
	}
	t := Target{Host: clean, Port: port}
	if a, err := netip.ParseAddr(clean); err == nil {
		t.addr = a.Unmap()
		t.isIP = true
	}
	return t
}

// IsIP 表示目标是裸 IP（无域名可匹配）。
func (t Target) IsIP() bool { return t.isIP }

// Addr 返回 IP 字面量地址。
func (t Target) Addr() netip.Addr { return t.addr }

// Match 执行有序 first-match 判定。域名不做 DNS 解析；需要让
// IP-CIDR/GEOIP 同时作用于域名时使用 MatchContext 或 MatchResolved。
func (e *Engine) Match(t Target) Decision {
	return e.matchResolved(t, nil)
}

// MatchDomainShortCircuit 在无需 DNS 解析即可唯一确定域名决策时直接返回结果。
//
// 当目标是域名，且在命中的域名规则之前不存在任何用户级公网 IP/GEOIP 规则
// （仅允许内置私网保护段）时，决策已确定：
//   - DoT 可对 block/proxy 直接应答，省去向国内 DNS 发查询与等待；
//   - sniff / quicfwd 可跳过本机 DNS 解析，直接进入拨号。
func (e *Engine) MatchDomainShortCircuit(t Target) (Decision, bool) {
	if t.isIP || t.Host == "" {
		return Decision{}, false
	}
	e.mu.RLock()
	rules := e.rules
	e.mu.RUnlock()

	for i := range rules {
		r := &rules[i]
		if r.matchesDomainOnly(t.Host) {
			desc := r.desc
			if desc == "" {
				desc = string(r.Kind) + "," + r.Value
			}
			return Decision{
				Action: r.Action,
				Egress: r.Egress,
				Rule:   desc,
				Index:  i,
			}, true
		}
		// 若遇到非私网保护的 IP 类规则（例如用户在域名规则前写了公网 IP-CIDR），
		// 则不能跳过 DNS 解析，需交给完整流程按真实解析结果匹配。
		if r.needsResolvedIP() {
			return Decision{}, false
		}
	}
	return Decision{}, false
}

// MatchContext 先尝试纯域名无解析短路；未命中时再解析域名并按原始规则顺序
// 同时匹配域名与目标 IP。正向结果缓存 5 分钟；解析失败时退回纯域名规则。
func (e *Engine) MatchContext(ctx context.Context, t Target) Decision {
	if t.isIP || t.Host == "" {
		return e.Match(t)
	}
	if dec, ok := e.MatchDomainShortCircuit(t); ok {
		return dec
	}
	addrs := filterDNSPoisonForTakeover(t.Host, e.resolve(ctx, t.Host))
	return e.MatchResolved(t, addrs)
}

// MatchResolved 使用调用方已解析的地址参与 IP-CIDR/GEOIP 判定。
// Android DoT 使用其上游 DNS 的真实应答调用此方法，避免重复解析。
func (e *Engine) MatchResolved(t Target, addrs []netip.Addr) Decision {
	return e.matchResolved(t, normalizeAddrs(addrs))
}

func (e *Engine) matchResolved(t Target, addrs []netip.Addr) Decision {
	e.mu.RLock()
	rules := e.rules
	final := e.final
	e.mu.RUnlock()

	for i := range rules {
		r := &rules[i]
		if !r.matches(t, addrs) {
			continue
		}
		desc := r.desc
		if desc == "" {
			desc = string(r.Kind) + "," + r.Value
		}
		return Decision{
			Action: r.Action,
			Egress: r.Egress,
			Rule:   desc,
			Index:  i,
		}
	}
	return final
}

func (e *Engine) resolve(ctx context.Context, host string) []netip.Addr {
	now := time.Now()
	e.resolveMu.RLock()
	cached, ok := e.resolveCache[host]
	e.resolveMu.RUnlock()
	if ok && now.Before(cached.expire) {
		return append([]netip.Addr(nil), cached.addrs...)
	}

	// 高峰时直接退回域名规则/FINAL，不排队拖慢整条连接。
	select {
	case e.resolveSlots <- struct{}{}:
		defer func() { <-e.resolveSlots }()
	default:
		return nil
	}

	// GEOIP 是兜底而不是连接前置硬依赖；350ms 内解析不到就放行
	// 后续规则，避免个别坏 DNS 把首包拖满旧版的 2 秒。
	e.mu.RLock()
	res := e.resolver
	e.mu.RUnlock()
	if res == nil {
		res = net.DefaultResolver
	}
	rctx, cancel := context.WithTimeout(ctx, 350*time.Millisecond)
	defer cancel()
	addrs, err := res.LookupNetIP(rctx, "ip", host)
	addrs = normalizeAddrs(addrs)
	ttl := 5 * time.Minute
	if err != nil || len(addrs) == 0 {
		addrs = nil
		ttl = 30 * time.Second // 负缓存，抑制同一坏域名反复解析
	}

	e.resolveMu.Lock()
	// 有界缓存：先删过期项，仍过大时任意淘汰到 3072 条。
	if len(e.resolveCache) >= 4096 {
		for key, item := range e.resolveCache {
			if now.After(item.expire) {
				delete(e.resolveCache, key)
			}
		}
		for key := range e.resolveCache {
			if len(e.resolveCache) < 3072 {
				break
			}
			delete(e.resolveCache, key)
		}
	}
	e.resolveCache[host] = resolveEntry{
		addrs:  append([]netip.Addr(nil), addrs...),
		expire: now.Add(ttl),
	}
	e.resolveMu.Unlock()
	return addrs
}

func normalizeAddrs(in []netip.Addr) []netip.Addr {
	out := make([]netip.Addr, 0, len(in))
	seen := make(map[netip.Addr]struct{}, len(in))
	for _, a := range in {
		if !a.IsValid() {
			continue
		}
		a = a.Unmap()
		if _, ok := seen[a]; ok {
			continue
		}
		seen[a] = struct{}{}
		out = append(out, a)
	}
	return out
}

func isPrivateOrReservedPrefix(p netip.Prefix) bool {
	a := p.Masked().Addr().Unmap()
	if !a.IsValid() {
		return false
	}
	return a.IsPrivate() || a.IsLoopback() || a.IsLinkLocalUnicast() || a.IsUnspecified()
}

// filterDNSPoisonForTakeover 剔除本机 DNS 对公网域名返回的回环/未指定/私网地址
// （常见于运营商抢答或 GFW DNS 投毒返回 127.0.0.1 / 0.0.0.0 / 10.x），
// 避免未知境外域名误中顶部 BuiltinPre 私网直连规则后在出口侧自杀。
func filterDNSPoisonForTakeover(host string, addrs []netip.Addr) []netip.Addr {
	if len(addrs) == 0 || host == "localhost" || strings.HasSuffix(host, ".localhost") {
		return addrs
	}
	hasPoison := false
	for _, a := range addrs {
		u := a.Unmap()
		if !u.IsValid() || u.IsLoopback() || u.IsUnspecified() || u.IsPrivate() || u.IsLinkLocalUnicast() {
			hasPoison = true
			break
		}
	}
	if !hasPoison {
		return addrs
	}
	out := make([]netip.Addr, 0, len(addrs))
	for _, a := range addrs {
		u := a.Unmap()
		if !u.IsValid() || u.IsLoopback() || u.IsUnspecified() || u.IsPrivate() || u.IsLinkLocalUnicast() {
			continue
		}
		out = append(out, u)
	}
	return out
}

func (r *Rule) needsResolvedIP() bool {
	switch r.Kind {
	case KindIPCIDR:
		return r.hasPfx && !r.privateOnly
	case KindGeoIP:
		return r.cidrs != nil
	case KindRuleSet:
		return r.cidrs != nil
	}
	return false
}

func (r *Rule) matchesDomainOnly(host string) bool {
	switch r.Kind {
	case KindDomain:
		v := r.matchVal
		if v == "" {
			v = strings.ToLower(r.Value)
		}
		return host == v
	case KindDomainSuffix:
		v := r.matchVal
		if v == "" {
			v = strings.ToLower(strings.TrimPrefix(r.Value, "."))
			return host == v || strings.HasSuffix(host, "."+v)
		}
		return host == v || strings.HasSuffix(host, r.dotSuffix)
	case KindDomainKeyword:
		v := r.matchVal
		if v == "" {
			v = strings.ToLower(r.Value)
		}
		return strings.Contains(host, v)
	case KindRuleSet:
		return r.domains != nil && r.domains.Match(host)
	}
	return false
}

func (r *Rule) matches(t Target, resolved []netip.Addr) bool {
	matchAddr := func(fn func(netip.Addr) bool) bool {
		if t.isIP && fn(t.addr) {
			return true
		}
		for _, a := range resolved {
			if fn(a) {
				return true
			}
		}
		return false
	}

	switch r.Kind {
	case KindDomain, KindDomainSuffix, KindDomainKeyword:
		return !t.isIP && r.matchesDomainOnly(t.Host)

	case KindIPCIDR:
		return r.hasPfx && matchAddr(r.prefix.Contains)

	case KindGeoIP:
		return r.cidrs != nil && matchAddr(r.cidrs.Match)

	case KindRuleSet:
		if !t.isIP && r.domains != nil && r.domains.Match(t.Host) {
			return true
		}
		return r.cidrs != nil && matchAddr(r.cidrs.Match)
	}
	return false
}
