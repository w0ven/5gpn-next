package bot

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"log"
	"strconv"
	"strings"
	"time"

	"github.com/w0ven/5gpn-next/internal/config"
	"github.com/w0ven/5gpn-next/internal/manage"
	"github.com/w0ven/5gpn-next/internal/qrcode"
	"github.com/w0ven/5gpn-next/internal/stats"
)

// ---------- 主页 ----------

func (b *Bot) showMenu(ctx context.Context, v view) {
	st := b.Manager.Status(b.Version)

	var sb strings.Builder
	sb.WriteString(brand() + "  <b>NEXT</b>\n")
	var info strings.Builder
	if st.DomesticReady {
		fmt.Fprintf(&info, "%s 运行中 · %s · <code>%s</code>", ic("online"), st.Uptime, esc(st.Version))
	} else {
		fmt.Fprintf(&info, "%s 国内规则未就绪，已回落本机直出", ic("warn"))
	}
	fmt.Fprintf(&info, "\n出口　<b>%s</b>", esc(currentEgress(st)))
	if s := appsSummary(b.Manager.Apps()); s != "" {
		fmt.Fprintf(&info, "\n分流　<b>%s</b>", s)
	}
	if sum, ok := b.Manager.TrafficSummary(); ok {
		fmt.Fprintf(&info, "\n今日　<b>%s</b>", stats.HumanBytes(sum.Today.Total()))
		if st.AdBlock.Enabled && st.AdBlock.Hits.Today > 0 {
			fmt.Fprintf(&info, " · 拦截 <b>%d</b>", st.AdBlock.Hits.Today)
		}
	}
	sb.WriteString(card(info.String()))

	var rows [][]btn
	if tag := b.Manager.UpdateBanner(); tag != "" {
		sb.WriteString(note("new", "<b>"+esc(tag)+"</b> 可更新"))
		rows = append(rows, []btn{{Text: "查看 " + tag, Data: "update", Icon: "new", Style: "primary"}})
	}
	rows = append(rows,
		[]btn{{Text: "状态", Data: "status", Icon: "status"}, {Text: "出口", Data: "egress", Icon: "egress"}},
		[]btn{{Text: "分流", Data: "rules", Icon: "route"}, {Text: "拦截", Data: "adblock", Icon: "shield"}},
		[]btn{{Text: "诊断", Data: "probe", Icon: "probe"}, {Text: "接入", Data: "client", Icon: "device"}},
	)
	last := []btn{{Text: "版本", Data: "update", Icon: "update"}}
	if b.PanelURL != "" {
		last = append(last, btn{Text: "面板", Data: "url:" + b.PanelURL, Icon: "panel"})
	}
	rows = append(rows, last)
	b.render(ctx, v, sb.String(), inlineKeyboard(rows...))
}

func currentEgress(st manage.Status) string {
	for _, e := range st.Egress {
		if e.Current {
			return orDefault(e.Display, e.Name)
		}
	}
	return "本机直出"
}

// appsSummary 概括已单独指定出口的应用，没有时为空。
func appsSummary(list []manage.AppStatus) string {
	var on []manage.AppStatus
	for _, a := range list {
		if a.Egress != "" {
			on = append(on, a)
		}
	}
	switch len(on) {
	case 0:
		return ""
	case 1:
		return esc(on[0].Name) + " → " + esc(on[0].EgressDisplay)
	default:
		return fmt.Sprintf("%s 等 %d 个应用", esc(on[0].Name), len(on))
	}
}

// ---------- 状态 ----------

func (b *Bot) showStatus(ctx context.Context, v view, extra string) {
	st := b.Manager.Status(b.Version)
	sys := b.Manager.SysHealthNow()

	var sb strings.Builder
	sb.WriteString(head("status", "运行状态"))
	var info strings.Builder
	fmt.Fprintf(&info, "版本　<code>%s</code>\n", esc(st.Version))
	fmt.Fprintf(&info, "运行　<b>%s</b> · 内存 <b>%.1f MB</b>", st.Uptime, st.MemoryMB)
	if sys.CertKnown {
		info.WriteString("\n" + certHealthLine(sys.CertDays))
	}
	if st.DomesticReady {
		info.WriteString("\n国内　<b>直连规则就绪</b>")
	} else {
		info.WriteString("\n" + ic("warn") + " 国内规则未就绪，已回落本机直出")
	}
	sb.WriteString(card(info.String()))

	if h, ok := b.Manager.HealthReport(); ok && len(h.Egress) > 0 {
		var lines strings.Builder
		for i, e := range h.Egress {
			if i > 0 {
				lines.WriteString("\n")
			}
			icon := rateIcon(e.Probe1h.FailRate())
			if e.Probe1h.Count == 0 && e.Fw1h.Count > 0 {
				icon = rateIcon(e.Fw1h.FailRate())
			}
			avg := "—"
			if e.Probe1h.Count > 0 {
				avg = e.Probe1h.Avg()
			}
			fmt.Fprintf(&lines, "%s %s　<b>%s</b>", icon, esc(e.Name), avg)
		}
		sb.WriteString("\n<b>出口</b>\n" + card(lines.String()))
	}
	var counters []string
	for _, k := range []string{"connect", "blocked", "dial_fail", "auth_fail", "v6_fastfail"} {
		if val, ok := st.Counters[k]; ok {
			counters = append(counters, fmt.Sprintf("%s <b>%d</b>", counterName(k), val))
		}
	}
	if len(counters) > 0 {
		sb.WriteString("\n<b>本次运行</b>\n" + card(strings.Join(counters, " · ")))
	}
	if sum, ok := b.Manager.TrafficSummary(); ok {
		fmt.Fprintf(&sb, "\n<b>今日转发</b>　↑ %s · ↓ %s",
			stats.HumanBytes(sum.Today.Up), stats.HumanBytes(sum.Today.Down))
	}
	sb.WriteString(extra)

	b.render(ctx, v, sb.String(), inlineKeyboard(
		[]btn{{Text: "流量", Data: "traffic", Icon: "traffic"}, {Text: "健康", Data: "health", Icon: "status"}},
		[]btn{{Text: "刷新", Data: "refresh:status"}},
		navRow("menu"),
	))
}

func counterName(k string) string {
	switch k {
	case "connect":
		return "连接"
	case "blocked":
		return "拦截"
	case "dial_fail":
		return "拨号失败"
	case "auth_fail":
		return "鉴权失败"
	case "v6_fastfail":
		return "IPv6 回落"
	}
	return k
}

func (b *Bot) showTraffic(ctx context.Context, v view) {
	sum, ok := b.Manager.TrafficSummary()
	if !ok {
		b.render(ctx, v, head("traffic", "转发流量")+"统计功能未启用。", backTo("status"))
		return
	}

	var sb strings.Builder
	sb.WriteString(head("traffic", "转发流量"))
	sb.WriteString("<i>只统计经过网关的数据；国内网站等手机本地直连的流量不在其中。</i>\n")
	row := func(name string, d stats.Day) {
		fmt.Fprintf(&sb, "\n<b>%s</b>　%s\n", name, stats.HumanBytes(d.Total()))
		fmt.Fprintf(&sb, "<blockquote>↑ %s · ↓ %s\n%d 连接 · 直出 %d · 代理 %d",
			stats.HumanBytes(d.Up), stats.HumanBytes(d.Down), d.Conns, d.DirectConns, d.ProxyConns)
		if d.Blocked > 0 {
			fmt.Fprintf(&sb, " · 拦截 %d", d.Blocked)
		}
		// v0.13.9 及更早版本把 QUIC/失败写成未识别 action；历史聚合
		// 无法可靠反推直连或代理，只透明展示差额，不伪造分类。
		if u := d.Conns - d.DirectConns - d.ProxyConns - d.Blocked; u > 0 {
			fmt.Fprintf(&sb, " · 旧版未分类 %d", u)
		}
		if d.Failed > 0 {
			fmt.Fprintf(&sb, "\n其中失败 %d", d.Failed)
		}
		sb.WriteString("</blockquote>")
	}
	row("今日", sum.Today)
	row("近 7 天", sum.Days7)
	row("近 30 天", sum.Days30)

	if len(sum.TopDomain) > 0 {
		sb.WriteString("\n<b>流量最高的站点</b>\n<blockquote expandable>")
		for i, t := range sum.TopDomain {
			if i >= 8 {
				break
			}
			if i > 0 {
				sb.WriteString("\n")
			}
			fmt.Fprintf(&sb, "%d. <code>%s</code> · %s", i+1, esc(truncateText(t.Host, 30)), stats.HumanBytes(t.Bytes))
		}
		sb.WriteString("</blockquote>")
	}
	fmt.Fprintf(&sb, "\n<i>按北京时间自然日统计，自 %s 起。</i>", esc(sum.Since))

	b.render(ctx, v, sb.String(), inlineKeyboard(
		[]btn{{Text: "刷新", Data: "refresh:traffic"}},
		navRow("status"),
	))
}

// ---------- 出口 ----------

func (b *Bot) showEgress(ctx context.Context, v view) {
	st := b.Manager.Status(b.Version)
	latency := map[string]string{}
	if h, ok := b.Manager.HealthReport(); ok {
		for _, e := range h.Egress {
			if e.Probe1h.Count > 0 {
				latency[e.Name] = rateIcon(e.Probe1h.FailRate()) + " " + e.Probe1h.Avg()
			}
		}
	}

	var sb strings.Builder
	sb.WriteString(head("egress", "出口"))
	sb.WriteString("<i>默认出口承接没有命中任何规则的国外流量。</i>\n")
	if !st.DomesticReady {
		sb.WriteString(card(ic("warn")+" 国内直连规则尚未就绪，已回落本机直出；切换代理出口前会先刷新国内规则。") + "\n")
	}
	var lines strings.Builder
	var bs []btn
	for i, e := range st.Egress {
		disp := orDefault(e.Display, e.Name)
		mark := "○"
		if e.Current {
			mark = "●"
		}
		if i > 0 {
			lines.WriteString("\n")
		}
		fmt.Fprintf(&lines, "%s <b>%s</b>　<i>%s</i>", mark, esc(disp), esc(e.Type))
		if l, ok := latency[e.Name]; ok {
			lines.WriteString(" · " + l)
		}
		bs = append(bs, btn{Text: mark + " " + truncateText(disp, 14), Data: "egress_info:" + e.Name})
	}
	sb.WriteString(card(lines.String()))
	sb.WriteString("\n<i>● 为默认出口，点出口进入管理。</i>")

	rows := grid(2, bs)
	rows = append(rows, []btn{{Text: "添加出口", Data: "ask_egress_add", Icon: "egress"}}, navRow("menu"))
	b.render(ctx, v, sb.String(), inlineKeyboard(rows...))
}

func findEgress(st manage.Status, name string) (manage.EgressStatus, bool) {
	for _, e := range st.Egress {
		if e.Name == name {
			return e, true
		}
	}
	return manage.EgressStatus{}, false
}

// showEgressInfo 是单出口详情页。extra 为 "confirm_delete" 时进入删除确认，
// 其余非空值作为底部状态行原样附加。
func (b *Bot) showEgressInfo(ctx context.Context, v view, name, extra string) {
	eg, ok := findEgress(b.Manager.Status(b.Version), name)
	if !ok {
		b.showEgress(ctx, v)
		return
	}
	disp := orDefault(eg.Display, eg.Name)
	sub := ""
	if eg.Current {
		sub = "默认出口"
	}

	var sb strings.Builder
	sb.WriteString(head("egress", esc(disp), sub))
	var info strings.Builder
	fmt.Fprintf(&info, "协议　<b>%s</b>", esc(eg.Type))
	if eg.Server != "" {
		fmt.Fprintf(&info, "\n服务器　<code>%s</code>", esc(eg.Server))
	}
	if eg.HasIPv6 {
		info.WriteString("\nIPv6　<b>可代拨</b>")
	} else {
		info.WriteString("\nIPv6　<b>不支持</b>")
	}
	if h, ok := b.Manager.HealthReport(); ok {
		for _, e := range h.Egress {
			if e.Name != name {
				continue
			}
			if e.Probe1h.Count > 0 {
				fmt.Fprintf(&info, "\n近 1 小时　%s 均 <b>%s</b> · p95 <b>%s</b> · 失败 <b>%d</b>/%d",
					rateIcon(e.Probe1h.FailRate()), e.Probe1h.Avg(), e.Probe1h.P95(), e.Probe1h.Fail, e.Probe1h.Count)
			}
			if e.UpBytes > 0 || e.DownBytes > 0 {
				fmt.Fprintf(&info, "\n流量　↑ <b>%s</b> · ↓ <b>%s</b>", humanBytes(e.UpBytes), humanBytes(e.DownBytes))
			}
			break
		}
	}
	sb.WriteString(card(info.String()))

	if extra == "confirm_delete" {
		sb.WriteString(note("warn", "确认删除？将停止它的代理实例；若它是默认出口，自动回落本机直出；指向它的应用分流改回跟随默认。"))
		b.render(ctx, v, sb.String(), inlineKeyboard(
			[]btn{{Text: "确认删除", Data: "del_egress:" + name, Style: "danger"}, {Text: "取消", Data: "egress_info:" + name}},
		))
		return
	}
	sb.WriteString(extra)

	var rows [][]btn
	if !eg.Current {
		rows = append(rows, []btn{{Text: "设为默认出口", Data: "switch:" + name, Icon: "egress", Style: "primary"}})
	}
	row := []btn{{Text: "测试", Data: "test_egress:" + name, Icon: "probe"}}
	if name != "DIRECT" {
		row = append(row, btn{Text: "改名", Data: "rename_egress:" + name})
	}
	rows = append(rows, row)
	if name != "DIRECT" {
		rows = append(rows, []btn{{Text: "删除", Data: "del_egress_ask:" + name, Style: "danger"}})
	}
	rows = append(rows, navRow("egress"))
	b.render(ctx, v, sb.String(), inlineKeyboard(rows...))
}

func (b *Bot) doSwitchEgress(ctx context.Context, v view, name string) {
	b.showEgressInfo(ctx, v, name, note("loading", "正在验证出口并切换…"))
	if err := b.Manager.SwitchEgress(name); err != nil {
		b.ack(ctx, v, "切换失败", true)
		b.showEgressInfo(ctx, v, name, note("warn", "切换失败："+esc(err.Error())))
		return
	}
	b.ack(ctx, v, "已设为默认出口", false)
	b.showEgressInfo(ctx, v, name, note("ok", "已设为默认出口"))
}

func (b *Bot) doTestEgress(ctx context.Context, v view, name string) {
	b.showEgressInfo(ctx, v, name, note("loading", "正在经该出口访问外网…"))
	d, err := b.Manager.TestEgress(name)
	if err != nil {
		b.showEgressInfo(ctx, v, name, note("warn", "不通："+esc(err.Error())))
		return
	}
	b.showEgressInfo(ctx, v, name, note("ok", fmt.Sprintf("连通 · 端到端 <b>%dms</b>", d.Milliseconds())))
}

// doEgressAdd 执行添加出口（引导式两步流程的收口），成功后直接进入新出口的详情页。
func (b *Bot) doEgressAdd(ctx context.Context, v view, name, link string) {
	if !strings.Contains(link, "://") {
		b.ask(ctx, v, "egress_add_link|"+name, head("egress", "添加出口", "2 / 2")+"粘贴节点分享链接。", "egress",
			"这不像分享链接，请粘贴完整的 <code>ss://</code> <code>vless://</code> 等链接")
		return
	}
	before := map[string]bool{}
	for _, e := range b.Manager.Status(b.Version).Egress {
		before[e.Name] = true
	}
	b.render(ctx, v, head("egress", "添加出口")+note("loading", "正在添加并验证连通性，最长约 12 秒…"), "")
	msg, err := b.Manager.AddEgress(name, link)
	if err != nil {
		b.render(ctx, v, errBox("添加失败", err), inlineKeyboard(
			[]btn{{Text: "重新添加", Data: "ask_egress_add", Icon: "egress"}}, navRow("egress")))
		return
	}
	for _, e := range b.Manager.Status(b.Version).Egress {
		if !before[e.Name] {
			b.showEgressInfo(ctx, v, e.Name, note("ok", esc(msg)))
			return
		}
	}
	b.showEgress(ctx, v)
}

// ---------- 分流 ----------

func (b *Bot) showRules(ctx context.Context, v view) { b.showRulesNote(ctx, v, "") }

// showRulesNote 显示分流页；notice 非空时在底部附上刚才操作的结果。
func (b *Bot) showRulesNote(ctx context.Context, v view, notice string) {
	rules := b.Manager.Rules()
	problems := b.Manager.RuleProblems()

	var sb strings.Builder
	sb.WriteString(head("route", "分流"))
	sb.WriteString("<i>自定义规则 → 应用分流 → 国内直连 → 默认出口，命中即停。</i>\n")

	var on strings.Builder
	n := 0
	for _, a := range b.Manager.Apps() {
		if a.Egress == "" {
			continue
		}
		if n > 0 {
			on.WriteString("\n")
		}
		n++
		fmt.Fprintf(&on, "%s %s → <b>%s</b>", appLogo(a), esc(a.Name), esc(a.EgressDisplay))
	}
	if n == 0 {
		on.WriteString("全部跟随默认出口")
	}
	sb.WriteString("\n<b>应用</b>\n" + card(on.String()))

	fmt.Fprintf(&sb, "\n<b>自定义规则</b>　%d 条\n", len(rules))
	if len(rules) == 0 {
		sb.WriteString(card("暂无。国内直连、国外走出口已由内置规则完成，只有个别域名需要特殊处理时才添加。"))
	} else {
		var lines strings.Builder
		for i, r := range rules {
			if i >= 10 {
				fmt.Fprintf(&lines, "\n… 另有 %d 条", len(rules)-10)
				break
			}
			if i > 0 {
				lines.WriteString("\n")
			}
			fmt.Fprintf(&lines, "%d. <code>%s</code>", i+1, esc(r))
			if p, bad := problems[i]; bad {
				fmt.Fprintf(&lines, "\n　%s <i>不生效：%s</i>", ic("warn"), esc(p))
			}
		}
		sb.WriteString(card(lines.String()))
	}

	rows := [][]btn{
		{{Text: "应用分流", Data: "apps", Icon: "route"}, {Text: "添加规则", Data: "ask_rule_add"}},
	}
	second := []btn{{Text: "内置规则", Data: "rules_builtin"}, {Text: "规则集状态", Data: "rulesets"}}
	if len(rules) > 0 {
		second = append([]btn{{Text: "删除规则", Data: "rule_del_menu"}}, second...)
	}
	rows = append(rows, second, navRow("menu"))
	if notice != "" {
		sb.WriteString(note("ok", esc(notice)))
	}
	b.render(ctx, v, sb.String(), inlineKeyboard(rows...))
}

// showRuleSets 列出每个规则集的条目数、内容更新时间与最近一次检查结果。
func (b *Bot) showRuleSets(ctx context.Context, v view) {
	states := b.Manager.RuleSetStates()
	var sb strings.Builder
	sb.WriteString(head("route", "规则集状态"))
	sb.WriteString("<i>网关按各自的间隔联网检查，失败后每小时重试，连续 3 次失败会推送提醒。</i>\n")
	failing := 0
	for _, st := range states {
		var c strings.Builder
		fmt.Fprintf(&c, "<b>%s</b>", esc(st.Label))
		if st.Entries > 0 {
			fmt.Fprintf(&c, "　%s 条", groupDigits(st.Entries))
		}
		c.WriteString("\n")
		switch {
		case st.Local:
			c.WriteString("本地文件，不联网更新")
		case st.Failing():
			failing++
			fmt.Fprintf(&c, "%s 连续 %d 次检查失败（最近 %s）\n<i>%s</i>",
				ic("warn"), st.Check.Fails, agoShort(st.Check.LastCheck), esc(truncateText(st.Check.LastError, 90)))
		case st.Check.LastCheck.IsZero():
			c.WriteString("尚未联网检查")
		default:
			fmt.Fprintf(&c, "%s %s检查正常", ic("ok"), agoShort(st.Check.LastCheck))
		}
		if !st.Local {
			if !st.Updated.IsZero() {
				fmt.Fprintf(&c, "\n内容更新于 %s", agoShort(st.Updated))
			}
			if st.IntervalHours < 0 {
				c.WriteString(" · 不自动更新")
			} else {
				fmt.Fprintf(&c, " · 每 %d 小时检查", st.IntervalHours)
			}
		}
		sb.WriteString(card(c.String()))
	}
	if failing > 0 {
		sb.WriteString(note("warn", fmt.Sprintf("%d 个规则集在用旧版本，网络恢复后会自动更新。", failing)))
	}
	b.render(ctx, v, sb.String(), backTo("rules"))
}

func (b *Bot) showBuiltinRules(ctx context.Context, v view) {
	var sb strings.Builder
	sb.WriteString(head("route", "内置规则", "不可修改"))
	section := func(title string, rules ...[]string) {
		fmt.Fprintf(&sb, "\n<b>%s</b>\n<blockquote expandable>", title)
		first := true
		for _, list := range rules {
			for _, r := range list {
				if !first {
					sb.WriteString("\n")
				}
				first = false
				fmt.Fprintf(&sb, "<code>%s</code>", esc(r))
			}
		}
		sb.WriteString("</blockquote>")
	}
	section("最先匹配 · 私网保护与 DoH 阻断", config.BuiltinPre(), config.BuiltinDoHBlock())
	section("应用分流之后 · Google 下载修复", config.BuiltinGoogleFix())
	section("最后兜底 · 国内直连", config.BuiltinPost())
	b.render(ctx, v, sb.String(), backTo("rules"))
}

// askRuleAdd 提示添加规则，动态列出可用出口名。
func (b *Bot) askRuleAdd(ctx context.Context, v view, errNote string) {
	var sb strings.Builder
	sb.WriteString(head("route", "添加规则"))
	sb.WriteString("格式　<code>类型,值,动作</code>\n")
	sb.WriteString("动作　<code>direct</code> 手机直连（国内）· <code>block</code> 拦截\n")
	sb.WriteString("　　　<code>proxy</code> 默认出口 · <code>proxy:出口名</code>\n")
	sb.WriteString("　　　<code>proxy:DIRECT</code> 网关本机直出\n")
	var names []string
	for _, n := range b.Manager.SortedEgressNames() {
		if n != "DIRECT" {
			names = append(names, esc(n))
		}
	}
	example := "出口名"
	if len(names) > 0 {
		fmt.Fprintf(&sb, "出口　<code>%s</code>\n", strings.Join(names, "</code> · <code>"))
		example = names[0]
	}
	sb.WriteString(card("<code>DOMAIN-SUFFIX,openai.com,proxy:" + example + "</code>\n" +
		"<code>DOMAIN-SUFFIX,example.cn,direct</code>\n<code>DOMAIN-KEYWORD,ads,block</code>"))
	sb.WriteString("\n<i>新规则插在最前面，优先匹配。添加后会告诉你它实际让流量走哪里。</i>")
	b.ask(ctx, v, "rule_add", sb.String(), "rules", esc(errNote))
}

func (b *Bot) showRuleDelMenu(ctx context.Context, v view) {
	rules := b.Manager.Rules()
	if len(rules) == 0 {
		b.showRules(ctx, v)
		return
	}
	var sb strings.Builder
	sb.WriteString(head("route", "删除规则"))
	sb.WriteString("<i>点要删除的规则，删除前会再确认一次。</i>\n")
	var rows [][]btn
	for i, r := range rules {
		if i >= 12 {
			fmt.Fprintf(&sb, "\n<i>另有 %d 条，请在内网面板中操作。</i>", len(rules)-12)
			break
		}
		rows = append(rows, []btn{{Text: fmt.Sprintf("%d · %s", i+1, truncateText(ruleGist(r), 26)),
			Data: fmt.Sprintf("rule_del_ask:%d", i)}})
	}
	rows = append(rows, navRow("rules"))
	b.render(ctx, v, sb.String(), inlineKeyboard(rows...))
}

func (b *Bot) askRuleDelete(ctx context.Context, v view, arg string) {
	idx, err := strconv.Atoi(arg)
	rules := b.Manager.Rules()
	if err != nil || idx < 0 || idx >= len(rules) {
		b.showRuleDelMenu(ctx, v)
		return
	}
	b.render(ctx, v, head("route", "删除规则")+card("<code>"+esc(rules[idx])+"</code>")+
		note("warn", "确认删除？删除后立即生效。"),
		inlineKeyboard([]btn{
			{Text: "确认删除", Data: fmt.Sprintf("rule_del_do:%d:%s", idx, ruleFingerprint(rules[idx])), Style: "danger"},
			{Text: "取消", Data: "rule_del_menu"},
		}))
}

// doRuleDelete 校验指纹后删除：规则列表在确认期间可能已变化，
// 指纹不匹配时拒绝，避免误删错位后的其它规则。
func (b *Bot) doRuleDelete(ctx context.Context, v view, arg string) {
	idxStr, fp, _ := strings.Cut(arg, ":")
	idx, err := strconv.Atoi(idxStr)
	rules := b.Manager.Rules()
	if err != nil || idx < 0 || idx >= len(rules) || ruleFingerprint(rules[idx]) != fp {
		b.ack(ctx, v, "规则列表已变化，为避免误删已取消，请重新选择", true)
		b.showRuleDelMenu(ctx, v)
		return
	}
	if err := b.Manager.RemoveRule(idx, rules[idx]); err != nil {
		b.fail(ctx, v, "删除失败", err, "rules")
		return
	}
	b.ack(ctx, v, "已删除", false)
	b.showRules(ctx, v)
}

// ruleGist 取规则中最有辨识度的部分（值），供按钮标签使用。
func ruleGist(r string) string {
	parts := strings.Split(r, ",")
	if len(parts) >= 2 {
		return strings.TrimSpace(parts[1])
	}
	return r
}

// ruleFingerprint 生成规则内容短指纹，用于确认删除时校验列表未变化。
func ruleFingerprint(r string) string {
	sum := sha256.Sum256([]byte(r))
	return hex.EncodeToString(sum[:4])
}

// ---------- 广告拦截 ----------

func groupDigits(n int) string {
	s := strconv.Itoa(n)
	for i := len(s) - 3; i > 0; i -= 3 {
		s = s[:i] + "," + s[i:]
	}
	return s
}

func (b *Bot) doAdBlockToggle(ctx context.Context, v view, on bool) {
	if on {
		b.render(ctx, v, head("shield", "广告拦截")+note("loading", "正在更新规则，首次需下载规则集，约十几秒…"), "")
	}
	cctx, cancel := context.WithTimeout(ctx, 150*time.Second)
	msg, err := b.Manager.SetAdBlock(cctx, on)
	cancel()
	if err != nil {
		b.ack(ctx, v, "操作失败："+err.Error(), true)
		b.render(ctx, v, errBox("广告拦截", err), inlineKeyboard(
			[]btn{{Text: "重试", Data: "adblock_on"}}, navRow("adblock")))
		return
	}
	b.ack(ctx, v, msg, false)
	b.showAdBlock(ctx, v)
}

func (b *Bot) doAdAllowHit(ctx context.Context, v view, fp string) {
	host := ""
	for _, ev := range b.Manager.Status(b.Version).AdBlock.Hits.Recent {
		if ruleFingerprint(ev.Host) == fp {
			host = ev.Host
			break
		}
	}
	if host == "" {
		b.ack(ctx, v, "这条记录已经翻过去了，请在最新列表里再选", true)
		b.showAdBlock(ctx, v)
		return
	}
	if err := b.Manager.AllowAd(host); err != nil {
		b.fail(ctx, v, "放行失败", err, "adblock")
		return
	}
	b.ack(ctx, v, "已放行 "+host, false)
	b.showAdBlock(ctx, v)
}

func (b *Bot) showAdAllowlist(ctx context.Context, v view) {
	list := b.Manager.AdAllowlist()

	var sb strings.Builder
	sb.WriteString(head("shield", "白名单"))
	if len(list) == 0 {
		sb.WriteString(card("暂无。某个 App 被误拦时，把它的域名加进来即可放行。"))
	} else {
		var lines strings.Builder
		for i, d := range list {
			if i > 0 {
				lines.WriteString("\n")
			}
			fmt.Fprintf(&lines, "%d. <code>%s</code>", i+1, esc(d))
		}
		sb.WriteString(card(lines.String()))
	}

	var bs []btn
	for i, d := range list {
		if i >= 10 {
			break
		}
		bs = append(bs, btn{Text: "移除 " + truncateText(d, 20), Data: fmt.Sprintf("ad_allow_del:%d:%s", i, ruleFingerprint(d))})
	}
	rows := grid(1, bs)
	rows = append(rows, []btn{{Text: "加入白名单", Data: "ask_ad_allow", Icon: "shield"}}, navRow("adblock"))
	b.render(ctx, v, sb.String(), inlineKeyboard(rows...))
}

// ---------- 诊断 ----------

// probeSites 是诊断页的常用站点，按钮带对应应用的 Logo。
var probeSites = []struct{ host, app string }{
	{"youtube.com", "youtube"}, {"google.com", "google"}, {"chatgpt.com", "chatgpt"},
	{"claude.ai", "claude"}, {"netflix.com", "netflix"}, {"github.com", "github"},
}

func (b *Bot) askProbe(ctx context.Context, v view) {
	var bs []btn
	for _, s := range probeSites {
		bs = append(bs, btn{Text: s.host, Data: "probe_go:" + s.host, Icon: "app:" + s.app})
	}
	rows := grid(3, bs)
	rows = append(rows, navRow("menu"))
	text := head("probe", "连通诊断") +
		"发送要检测的域名，或点常用站点。\n" +
		"<i>逐层检查 入口 → 策略 → 出口 → 连接 → 应用。</i>"
	id := b.render(ctx, v, text, inlineKeyboard(rows...))
	b.mu.Lock()
	b.pending[v.chatID] = "probe"
	b.promptMsg[v.chatID] = id
	b.mu.Unlock()
}

func (b *Bot) doProbe(ctx context.Context, v view, target string) {
	target = strings.TrimSpace(target)
	if target == "" {
		b.askProbe(ctx, v)
		return
	}
	b.render(ctx, v, head("probe", "连通诊断")+note("loading", "正在诊断 <code>"+esc(target)+"</code>…"), "")
	cctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	tr := b.Manager.Probe(cctx, target)
	cancel()

	verdict, iconName := "连通正常", "ok"
	if !tr.OK() {
		verdict, iconName = "存在故障", "warn"
	}
	body := head(iconName, "诊断结果", verdict) +
		"<code>" + esc(target) + "</code>\n<pre>" + esc(tr.Human()) + "</pre>"
	var rows [][]btn
	again := "probe_go:" + target
	if len(again) <= 64 {
		rows = append(rows, []btn{{Text: "再测一次", Data: again}, {Text: "换一个", Data: "probe", Icon: "probe"}})
	} else {
		rows = append(rows, []btn{{Text: "换一个", Data: "probe", Icon: "probe"}})
	}
	rows = append(rows, navRow("menu"))
	b.render(ctx, v, body, inlineKeyboard(rows...))
}

// ---------- 接入 ----------

func (b *Bot) showClient(ctx context.Context, v view) {
	b.renderClient(ctx, v, "")
}

func (b *Bot) renderClient(ctx context.Context, v view, extra string) {
	var g manage.AndroidGuide
	if b.Manager.AndroidInfo != nil {
		g = b.Manager.AndroidInfo()
	}

	var sb strings.Builder
	sb.WriteString(head("device", "接入"))
	sb.WriteString("\n" + ic("apple") + " <b>iPhone / iPad</b>\n")
	sb.WriteString(card("安装描述文件即可。仅蜂窝数据生效，连 Wi-Fi 自动停用。"))
	sb.WriteString("\n" + ic("android") + " <b>Android</b>\n")
	if g.Enabled {
		sb.WriteString(card("设置 → 网络和互联网 → 私人 DNS\n选「私人 DNS 提供商主机名」，填入\n<code>" + esc(g.DoTHost) + "</code>"))
	} else {
		sb.WriteString(card("未启用：把配置里的 <code>dns.enabled</code> 设为 <code>true</code> 并重启服务。"))
	}
	if b.PanelURL != "" {
		sb.WriteString("\n" + ic("panel") + " <b>内网面板</b>\n")
		sb.WriteString(card("<code>" + esc(b.PanelURL) + "</code>\n手机走内网卡时直接打开即可查看；要修改设置，点「面板登录」拿一次性链接（10 分钟内有效，登录后 30 天免登）。"))
	}
	sb.WriteString(extra)

	var row []btn
	if b.Manager.DNSProfileBytes != nil {
		row = append(row, btn{Text: "iOS 描述文件", Data: "ios_dns_profile", Icon: "apple", Style: "primary"})
	}
	var rows [][]btn
	if len(row) > 0 {
		rows = append(rows, row)
	}
	if b.PanelURL != "" {
		panelRow := []btn{{Text: "打开面板", Data: "url:" + b.PanelURL, Icon: "panel"}}
		if b.PanelLogin != nil {
			panelRow = append(panelRow, btn{Text: "面板登录", Data: "panel_login"})
		}
		rows = append(rows, panelRow)
	}
	rows = append(rows, navRow("menu"))
	b.render(ctx, v, sb.String(), inlineKeyboard(rows...))
}

// showPanelLogin 签发一次性面板登录链接。链接只放在按钮里、不出现在消息
// 正文：Telegram 会抓取正文链接做预览，那一次访问就会把它用掉。
func (b *Bot) showPanelLogin(ctx context.Context, v view) {
	link, err := b.PanelLogin()
	if err != nil {
		b.fail(ctx, v, "生成登录链接失败", err, "client")
		return
	}
	text := head("panel", "面板登录") +
		card("点下面的按钮在手机浏览器里打开，即可在面板里修改设置。\n\n链接只能用一次，10 分钟内有效；登录后这台设备 30 天内不用再登录。") +
		note("warn", "不要转发这个按钮：拿到链接的人就能修改网关设置。")
	b.render(ctx, v, text, inlineKeyboard(
		[]btn{{Text: "打开面板并登录", Data: "url:" + link, Icon: "panel", Style: "primary"}},
		navRow("client")))
}

// sendDNSProfile 下发蜂窝 DNS 描述文件：先收起上次发的文件，再发二维码与文件，
// 最后把接入页重新放到它们下面，保持「屏幕在最底部」。
func (b *Bot) sendDNSProfile(ctx context.Context, v view) {
	if b.Manager.DNSProfileBytes == nil {
		b.fail(ctx, v, "获取失败", fmt.Errorf("蜂窝 DNS 模式需要启用 dns.enabled（DoT 入口）"), "client")
		return
	}
	data, err := b.Manager.DNSProfileBytes()
	if err != nil {
		b.fail(ctx, v, "生成失败", err, "client")
		return
	}

	b.mu.Lock()
	old := b.files[v.chatID]
	delete(b.files, v.chatID)
	b.mu.Unlock()
	for _, id := range old {
		b.deleteMessage(ctx, v.chatID, id)
	}

	var sent []int64
	if url := b.Manager.ProfileDownloadURL(); url != "" {
		if png, qerr := qrcode.EncodePNG(url); qerr != nil {
			log.Printf("Bot 生成描述文件二维码失败: %v", qerr)
		} else {
			caption := "<b>扫码安装</b>\n" +
				"1. 如装过旧版 5gpn 描述文件，先删除\n" +
				"2. 手机走<b>内网卡蜂窝数据</b>，用相机扫码\n" +
				"3. 设置 → 通用 → VPN 与设备管理 → 安装\n\n" +
				"<code>" + esc(url) + "</code>\n" +
				"<i>链接含随机串，请勿外传；仅内网卡来源可访问。</i>"
			if id, err := b.sendFile(ctx, "sendPhoto", "photo", v.chatID, "5gpn-next-dns.png", png, caption); err != nil {
				log.Printf("Bot 发送描述文件二维码失败: %v", err)
			} else {
				sent = append(sent, id)
			}
		}
	}
	docCaption := "<b>或点开文件安装</b>\n设置 → 通用 → VPN 与设备管理 → 安装"
	id, err := b.sendFile(ctx, "sendDocument", "document", v.chatID, "5gpn-next-dns.mobileconfig", data, docCaption)
	if err != nil {
		b.fail(ctx, v, "发送失败", err, "client")
		return
	}
	sent = append(sent, id)
	b.mu.Lock()
	b.files[v.chatID] = sent
	b.mu.Unlock()

	b.ack(ctx, v, "描述文件已发送", false)
	b.renderClient(ctx, view{chatID: v.chatID, cb: v.cb}, note("ok", "描述文件已发在上方，扫码或点开文件都能安装。"))
}
