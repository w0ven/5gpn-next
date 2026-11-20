// Package fw 维护 5gpn-next 自有的 nftables 规则。
//
// 只操作本项目独占的 inet fgpn 表，绝不触碰其它表或链，
// 因此不会影响 Docker、fail2ban 或用户既有防火墙配置。
package fw

import (
	"bufio"
	"context"
	"fmt"
	"net/netip"
	"os/exec"
	"sort"
	"strconv"
	"strings"
	"time"
)

const (
	tableName = "inet fgpn"
	chainName = "input"
	// quicComment 标记由本程序添加的 QUIC 放行规则。
	quicComment = "5gpn-quic-takeover"
	cmdTimeout  = 5 * time.Second
)

// EnsureIngressRestrictions 为已监听端口补齐“回环放行 + 客户端放行 + 公网丢弃”。
//
// install.sh 会为新装机器写完整规则，但内置自更新只替换二进制，不会重跑
// 安装器；生产旧机因此可能长期只有 allow、没有兜底 drop，或缺少 iif "lo" accept
// 导致本机回环访问面板/DoT/接管端口被公网兜底 drop 吞掉。这里在每次新版
// 启动时幂等补齐，使安全修复真正覆盖存量部署。应用层仍保留第二道校验。
func EnsureIngressRestrictions(ctx context.Context, clientCIDR string, tcpPorts, udpPorts []int) (changed bool, err error) {
	pfx, err := netip.ParsePrefix(clientCIDR)
	if err != nil {
		return false, fmt.Errorf("客户端网段无效: %w", err)
	}
	family := "ip"
	if pfx.Addr().Is6() {
		family = "ip6"
	}
	cidr := pfx.Masked().String()
	rules, err := listChain(ctx)
	if err != nil {
		return false, err
	}
	hasComment := func(comments ...string) bool {
		for _, r := range rules {
			for _, comment := range comments {
				if strings.Contains(r.text, `comment "`+comment+`"`) {
					return true
				}
			}
		}
		return false
	}
	hasLoopbackAccept := func() bool {
		for _, r := range rules {
			if strings.Contains(r.text, `comment "5gpn-loopback"`) ||
				(strings.Contains(r.text, `iif "lo"`) && strings.Contains(r.text, "accept")) ||
				(strings.Contains(r.text, `iifname "lo"`) && strings.Contains(r.text, "accept")) {
				return true
			}
		}
		return false
	}

	// 回环流量必须优先放行：否则下方的无源地址兜底 drop 会把本机访问
	// 127.0.0.1:20443 / :853 / :443 全部丢弃（nftables input 钩子同样作用于 lo）。
	if !hasLoopbackAccept() {
		if err := run(ctx, "insert", "rule", "inet", "fgpn", chainName,
			"iif", "lo", "accept", "comment", `"5gpn-loopback"`); err != nil {
			return changed, err
		}
		changed = true
	}

	// 优先按规则实际覆盖的端口号判定，防止更改监听端口后因旧 comment 仍在而漏加新端口放行。
	portAllowed := func(proto string, port int) bool {
		for _, r := range rules {
			if ruleAllowsPort(r.text, cidr, proto, port) {
				return true
			}
		}
		return false
	}
	portDenied := func(proto string, port int) bool {
		for _, r := range rules {
			if ruleDropsPublicPort(r.text, proto, port) {
				return true
			}
		}
		return false
	}

	for _, port := range cleanPorts(tcpPorts) {
		allowComment := "5gpn-runtime-allow-tcp-" + strconv.Itoa(port)
		denyComment := "5gpn-runtime-deny-tcp-" + strconv.Itoa(port)
		allowCovered := hasComment(allowComment) || portAllowed("tcp", port)
		denyCovered := hasComment(denyComment) || portDenied("tcp", port)
		if !allowCovered {
			if err := run(ctx, "insert", "rule", "inet", "fgpn", chainName,
				family, "saddr", cidr, "tcp", "dport", strconv.Itoa(port), "accept",
				"comment", `"`+allowComment+`"`); err != nil {
				return changed, err
			}
			changed = true
		}
		if !denyCovered {
			if err := run(ctx, "add", "rule", "inet", "fgpn", chainName,
				"tcp", "dport", strconv.Itoa(port), "drop",
				"comment", `"`+denyComment+`"`); err != nil {
				return changed, err
			}
			changed = true
		}
	}
	for _, port := range cleanPorts(udpPorts) {
		allowComment := "5gpn-runtime-allow-udp-" + strconv.Itoa(port)
		denyComment := "5gpn-runtime-deny-udp-" + strconv.Itoa(port)
		allowCovered := hasComment(allowComment) || portAllowed("udp", port)
		if port == 443 && hasComment(quicComment) {
			allowCovered = true
		}
		denyCovered := hasComment(denyComment) || portDenied("udp", port)
		if !allowCovered {
			if err := run(ctx, "insert", "rule", "inet", "fgpn", chainName,
				family, "saddr", cidr, "udp", "dport", strconv.Itoa(port), "accept",
				"comment", `"`+allowComment+`"`); err != nil {
				return changed, err
			}
			changed = true
		}
		if !denyCovered {
			if err := run(ctx, "add", "rule", "inet", "fgpn", chainName,
				"udp", "dport", strconv.Itoa(port), "drop",
				"comment", `"`+denyComment+`"`); err != nil {
				return changed, err
			}
			changed = true
		}
	}
	// 若机器上同时残留前代 PrivDNS Gateway 的 inet pdg 表（policy drop），
	// 补齐本网关监听端口（如 20443 面板端口）的客户端放行，防止被 pdg 默认丢弃。
	if pdgChanged, _ := ensureLegacyPDGIngress(ctx, family, cidr, cleanPorts(tcpPorts)); pdgChanged {
		changed = true
	}
	return changed, nil
}

// ensureLegacyPDGIngress 在检测到遗留的 inet pdg 表为 policy drop 时，
// 幂等补齐网关 TCP 监听端口的客户端放行；不存在 inet pdg 表时静默跳过。
func ensureLegacyPDGIngress(ctx context.Context, family, cidr string, tcpPorts []int) (bool, error) {
	rules, policyDrop, err := listTableChainWithMeta(ctx, "inet", "pdg", chainName)
	if err != nil || !policyDrop {
		return false, nil
	}
	changed := false
	for _, port := range tcpPorts {
		allowed := false
		allowComment := "5gpn-runtime-allow-tcp-" + strconv.Itoa(port)
		for _, r := range rules {
			if strings.Contains(r.text, `comment "`+allowComment+`"`) ||
				ruleAllowsPort(r.text, cidr, "tcp", port) {
				allowed = true
				break
			}
		}
		if !allowed {
			if err := run(ctx, "insert", "rule", "inet", "pdg", chainName,
				family, "saddr", cidr, "tcp", "dport", strconv.Itoa(port), "accept",
				"comment", `"`+allowComment+`"`); err != nil {
				return changed, err
			}
			changed = true
		}
	}
	return changed, nil
}

// ruleAllowsPort 判断一条 nft 规则是否已对 cidr 放行 proto/port（支持单端口与 { a, b } 集合）。
func ruleAllowsPort(text, cidr, proto string, port int) bool {
	if !strings.Contains(text, cidr) || !strings.Contains(text, "accept") {
		return false
	}
	return dportMatches(text, proto, port)
}

// ruleDropsPublicPort 判断一条无源地址过滤的兜底 drop 规则是否覆盖 proto/port。
func ruleDropsPublicPort(text, proto string, port int) bool {
	if strings.Contains(text, "saddr") || !strings.Contains(text, "drop") {
		return false
	}
	return dportMatches(text, proto, port)
}

func dportMatches(text, proto string, port int) bool {
	key := proto + " dport "
	idx := strings.Index(text, key)
	if idx < 0 {
		return false
	}
	rest := strings.TrimSpace(text[idx+len(key):])
	want := strconv.Itoa(port)
	if strings.HasPrefix(rest, "{") {
		end := strings.IndexByte(rest, '}')
		if end < 0 {
			return false
		}
		for _, tok := range strings.FieldsFunc(rest[1:end], func(r rune) bool {
			return r == ',' || r == ' ' || r == '\t'
		}) {
			if tok == want {
				return true
			}
		}
		return false
	}
	fields := strings.Fields(rest)
	return len(fields) > 0 && fields[0] == want
}

func cleanPorts(in []int) []int {
	seen := make(map[int]struct{}, len(in))
	out := make([]int, 0, len(in))
	for _, p := range in {
		if p < 1 || p > 65535 {
			continue
		}
		if _, ok := seen[p]; ok {
			continue
		}
		seen[p] = struct{}{}
		out = append(out, p)
	}
	sort.Ints(out)
	return out
}

// EnsureQUICAccept 让客户端的 QUIC（UDP 443）能够到达网关监听。
//
// 旧版本在防火墙层 reject UDP 443，指望客户端回落 TCP；Google Play
// 下载器不回落，只会无限重试。接管 QUIC 后必须放行，否则新监听收不到
// 任何数据报。
//
// 行为是幂等的：已放行则不做任何修改。仅当确实改动过才返回 changed=true。
func EnsureQUICAccept(ctx context.Context, clientCIDR string) (changed bool, err error) {
	rules, err := listChain(ctx)
	if err != nil {
		return false, err
	}

	var rejectHandles []string
	hasAccept := false
	for _, r := range rules {
		// 只操作本项目带明确 comment 的“客户端 QUIC 行为”规则。
		// 兼容旧版遗留的 5gpn-dns-quic 与 5gpn-android-quic 两种拒绝规则。
		// 公网来源的兜底 drop 也包含 udp/443，绝不能被这里误删。
		switch {
		case strings.Contains(r.text, `comment "`+quicComment+`"`):
			if strings.Contains(r.text, "accept") {
				hasAccept = true
			}
		case strings.Contains(r.text, `comment "5gpn-dns-quic"`),
			strings.Contains(r.text, `comment "5gpn-android-quic"`):
			if r.handle != "" {
				rejectHandles = append(rejectHandles, r.handle)
			}
		}
	}

	// 先加放行、再删拒绝：任何时刻都不出现「既不放行也不拒绝」的空窗。
	if !hasAccept {
		if err := addAccept(ctx, clientCIDR); err != nil {
			return false, err
		}
		changed = true
	}
	for _, h := range rejectHandles {
		if err := deleteRule(ctx, h); err != nil {
			return changed, err
		}
		changed = true
	}
	// 兼容前代 PrivDNS Gateway 遗留的 inet pdg 表：nftables 多个 input 链中
	// 只要有一条链 drop/reject，数据包仍会被丢弃（fgpn accept 不跳过后续表）。
	// 若 inet pdg 存在且仍在 reject 客户端 UDP 443，幂等替换为 accept。
	if pdgChanged, _ := ensureLegacyPDGQUICAccept(ctx, clientCIDR); pdgChanged {
		changed = true
	}
	return changed, nil
}

// ensureLegacyPDGQUICAccept 在检测到前代遗留的 inet pdg 表含客户端 UDP 443
// reject 时，先插入同源 accept 再移除该 reject；没有 inet pdg 表时静默跳过。
func ensureLegacyPDGQUICAccept(ctx context.Context, clientCIDR string) (bool, error) {
	pfx, err := netip.ParsePrefix(clientCIDR)
	if err != nil {
		return false, err
	}
	family := "ip"
	if pfx.Addr().Is6() {
		family = "ip6"
	}
	cidr := pfx.Masked().String()
	rules, err := listTableChain(ctx, "inet", "pdg", chainName)
	if err != nil {
		return false, nil
	}
	var rejectHandles []string
	hasAccept := false
	for _, r := range rules {
		if strings.Contains(r.text, `comment "`+quicComment+`"`) && strings.Contains(r.text, "accept") {
			hasAccept = true
			continue
		}
		if strings.Contains(r.text, "udp dport 443") && strings.Contains(r.text, "reject") &&
			strings.Contains(r.text, cidr) && r.handle != "" {
			rejectHandles = append(rejectHandles, r.handle)
		}
	}
	if len(rejectHandles) == 0 {
		return false, nil
	}
	changed := false
	if !hasAccept {
		if err := run(ctx, "insert", "rule", "inet", "pdg", chainName,
			family, "saddr", cidr, "udp", "dport", "443", "accept",
			"comment", `"`+quicComment+`"`); err != nil {
			return false, err
		}
		changed = true
	}
	for _, h := range rejectHandles {
		if err := run(ctx, "delete", "rule", "inet", "pdg", chainName, "handle", h); err != nil {
			return changed, err
		}
		changed = true
	}
	return changed, nil
}

// RestoreQUICReject 恢复「拒绝 UDP 443」的旧行为。
//
// 关闭 QUIC 接管时调用：监听已经不存在，若继续放行，客户端发出的
// QUIC 会石沉大海（无 ICMP 回应），比明确拒绝更糟。
func RestoreQUICReject(ctx context.Context, clientCIDR string) (changed bool, err error) {
	rules, err := listChain(ctx)
	if err != nil {
		return false, err
	}
	var acceptHandles []string
	hasReject := false
	for _, r := range rules {
		switch {
		case strings.Contains(r.text, `comment "5gpn-dns-quic"`):
			hasReject = true
		case strings.Contains(r.text, `comment "`+quicComment+`"`):
			if r.handle != "" {
				acceptHandles = append(acceptHandles, r.handle)
			}
		}
	}
	if !hasReject {
		pfx, perr := netip.ParsePrefix(clientCIDR)
		family := "ip"
		cidr := clientCIDR
		if perr == nil {
			if pfx.Addr().Is6() {
				family = "ip6"
			}
			cidr = pfx.Masked().String()
		}
		// insert 保证客户端规则位于公网兜底 drop 之前。
		if err := run(ctx, "insert", "rule", "inet", "fgpn", chainName,
			family, "saddr", cidr, "udp", "dport", "443",
			"reject", "with", "icmp", "port-unreachable",
			"comment", `"5gpn-dns-quic"`); err != nil {
			return false, err
		}
		changed = true
	}
	for _, h := range acceptHandles {
		if err := deleteRule(ctx, h); err != nil {
			return changed, err
		}
		changed = true
	}
	return changed, nil
}

type rule struct {
	text   string
	handle string
}

func listChain(ctx context.Context) ([]rule, error) {
	return listTableChain(ctx, "inet", "fgpn", chainName)
}

func listTableChain(ctx context.Context, fam, tbl, ch string) ([]rule, error) {
	rules, _, err := listTableChainWithMeta(ctx, fam, tbl, ch)
	return rules, err
}

func listTableChainWithMeta(ctx context.Context, fam, tbl, ch string) ([]rule, bool, error) {
	c, cancel := context.WithTimeout(ctx, cmdTimeout)
	defer cancel()
	out, err := exec.CommandContext(c, "nft", "-a", "list", "chain", fam, tbl, ch).CombinedOutput()
	if err != nil {
		return nil, false, fmt.Errorf("读取 %s %s %s 失败: %w (%s)", fam, tbl, ch, err, strings.TrimSpace(string(out)))
	}
	var rules []rule
	policyDrop := false
	sc := bufio.NewScanner(strings.NewReader(string(out)))
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if strings.HasPrefix(line, "type ") {
			if strings.Contains(line, "policy drop") {
				policyDrop = true
			}
			continue
		}
		if line == "" || strings.HasPrefix(line, "table ") ||
			strings.HasPrefix(line, "chain ") || line == "}" {
			continue
		}
		r := rule{text: line}
		if i := strings.LastIndex(line, "# handle "); i >= 0 {
			r.handle = strings.TrimSpace(line[i+len("# handle "):])
			r.text = strings.TrimSpace(line[:i])
		}
		rules = append(rules, r)
	}
	return rules, policyDrop, sc.Err()
}

func addAccept(ctx context.Context, clientCIDR string) error {
	pfx, err := netip.ParsePrefix(clientCIDR)
	family := "ip"
	cidr := clientCIDR
	if err == nil {
		if pfx.Addr().Is6() {
			family = "ip6"
		}
		cidr = pfx.Masked().String()
	}
	// insert 保证客户端放行位于公网兜底 drop 之前。
	return run(ctx, "insert", "rule", "inet", "fgpn", chainName,
		family, "saddr", cidr, "udp", "dport", "443", "accept",
		"comment", `"`+quicComment+`"`)
}

func deleteRule(ctx context.Context, handle string) error {
	return run(ctx, "delete", "rule", "inet", "fgpn", chainName, "handle", handle)
}

func run(ctx context.Context, args ...string) error {
	c, cancel := context.WithTimeout(ctx, cmdTimeout)
	defer cancel()
	out, err := exec.CommandContext(c, "nft", args...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("nft %s 失败: %w (%s)",
			strings.Join(args, " "), err, strings.TrimSpace(string(out)))
	}
	return nil
}
