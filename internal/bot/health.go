package bot

import (
	"context"
	"fmt"
	"html"
	"strings"

	"github.com/w0ven/5gpn-next/internal/certrenew"
	"github.com/w0ven/5gpn-next/internal/monitor"
)

// showHealth 展示健康监控总览：出口探测、真实转发、DoT、会话水位与网关进程。
func (b *Bot) showHealth(ctx context.Context, v view) {
	h, ok := b.Manager.HealthReport()
	if !ok {
		b.render(ctx, v, head("status", "健康")+"监控未启用。", backTo("status"))
		return
	}
	sys := b.Manager.SysHealthNow()

	var sb strings.Builder
	sb.WriteString(head("status", "健康"))

	if len(h.Egress) == 0 {
		sb.WriteString(card("探测数据积累中，约 1 分钟后可见。"))
	} else {
		target := h.ProbeTarget
		if target == "" {
			target = "远端目标"
		}
		fmt.Fprintf(&sb, "\n<b>出口链路</b>　<i>探测 %s</i>\n", html.EscapeString(target))
		for _, e := range h.Egress {
			sb.WriteString(egressHealthLine(e))
		}
	}

	var dns strings.Builder
	if h.DNS1h.Count > 0 {
		fmt.Fprintf(&dns, "%s 1h　均 <b>%s</b> · p95 <b>%s</b> · 失败 <b>%d</b>/%d",
			rateIcon(h.DNS1h.FailRate()), h.DNS1h.Avg(), h.DNS1h.P95(), h.DNS1h.Fail, h.DNS1h.Count)
	} else {
		dns.WriteString("1h 内无上游查询（缓存命中或无流量）")
	}
	if h.DNS24h.Count > 0 {
		fmt.Fprintf(&dns, "\n24h　均 <b>%s</b> · p95 <b>%s</b> · 失败 <b>%d</b>/%d",
			h.DNS24h.Avg(), h.DNS24h.P95(), h.DNS24h.Fail, h.DNS24h.Count)
	}
	sb.WriteString("\n<b>DNS 上游</b>\n" + card(dns.String()) + "\n")

	var proc strings.Builder
	fmt.Fprintf(&proc, "%s TCP　<b>%d</b> / %d", levelIcon(h.TCPActive, h.TCPMax), h.TCPActive, h.TCPMax)
	if h.QUICMax > 0 {
		fmt.Fprintf(&proc, "　%s QUIC　<b>%d</b> / %d", levelIcon(h.QUICActive, h.QUICMax), h.QUICActive, h.QUICMax)
	}
	fmt.Fprintf(&proc, "\n内存　<b>%.1f MB</b> · goroutine <b>%d</b> · 运行 <b>%s</b>", sys.MemoryMB, sys.Goroutines, sys.Uptime)
	if sys.CertKnown {
		proc.WriteString("\n" + certHealthLine(sys.CertDays))
	}
	sb.WriteString("\n<b>网关</b>\n" + card(proc.String()))

	var bs []btn
	for _, e := range h.Egress {
		bs = append(bs, btn{Text: truncateText(e.Name, 12), Data: "health_detail:" + e.Name, Icon: "probe"})
	}
	rows := grid(2, bs)
	rows = append(rows,
		[]btn{{Text: "刷新", Data: "refresh:health"}, {Text: "告警设置", Data: "monitor_settings", Icon: "alert"}},
		navRow("status"))
	b.render(ctx, v, sb.String(), inlineKeyboard(rows...))
}

// certHealthLine 渲染证书状态。过期时 DoT 全部握手失败，必须比临期更醒目。
func certHealthLine(days int) string {
	switch {
	case days < 0:
		return fmt.Sprintf("🚨 证书已过期　<b>%d 天</b>", -days)
	case days <= certrenew.WarnDays:
		return fmt.Sprintf("⚠️ 证书剩余　<b>%d 天</b>", days)
	default:
		return fmt.Sprintf("🔐 证书剩余　<b>%d 天</b>", days)
	}
}

// egressHealthLine 渲染单个出口的两行摘要。
func egressHealthLine(e monitor.EgressHealth) string {
	var sb strings.Builder
	icon := rateIcon(e.Probe1h.FailRate())
	if e.Probe1h.Count == 0 && e.Fw1h.Count > 0 {
		icon = rateIcon(e.Fw1h.FailRate())
	}
	fmt.Fprintf(&sb, "%s <b>%s</b>\n<blockquote>", icon, html.EscapeString(e.Name))
	wrote := false
	label := e.Kind.Label()
	if e.Probe1h.Count > 0 {
		fmt.Fprintf(&sb, "%s 1h　均 <b>%s</b> · p95 <b>%s</b> · 失败 <b>%d</b>/%d",
			label, e.Probe1h.Avg(), e.Probe1h.P95(), e.Probe1h.Fail, e.Probe1h.Count)
		wrote = true
	}
	if e.Probe24h.Count > 0 && e.Probe24h.Count != e.Probe1h.Count {
		if wrote {
			sb.WriteString("\n")
		}
		fmt.Fprintf(&sb, "%s 24h　均 <b>%s</b> · p95 <b>%s</b> · 失败 <b>%d</b>/%d",
			label, e.Probe24h.Avg(), e.Probe24h.P95(), e.Probe24h.Fail, e.Probe24h.Count)
		wrote = true
	}
	if e.Fw1h.Count > 0 {
		if wrote {
			sb.WriteString("\n")
		}
		fmt.Fprintf(&sb, "转发 1h　<b>%d</b> 次 · 均 <b>%s</b> · 失败 <b>%d</b>（%.0f%%）",
			e.Fw1h.Count, e.Fw1h.Avg(), e.Fw1h.Fail, e.Fw1h.FailRate()*100)
		wrote = true
	}
	if e.UpBytes > 0 || e.DownBytes > 0 {
		if wrote {
			sb.WriteString("\n")
		}
		fmt.Fprintf(&sb, "流量　↑ <b>%s</b> · ↓ <b>%s</b>",
			humanBytes(e.UpBytes), humanBytes(e.DownBytes))
		wrote = true
	}
	if !wrote {
		sb.WriteString("暂无数据")
	}
	if !e.Probe1h.LastFailAt.IsZero() {
		fmt.Fprintf(&sb, "\n上次失败　%s", e.Probe1h.LastFailAt.In(beijing).Format("15:04:05"))
	}
	sb.WriteString("</blockquote>\n")
	return sb.String()
}

// showHealthDetail 展示单出口最近异常探测点。
func (b *Bot) showHealthDetail(ctx context.Context, v view, name string) {
	samples := b.Manager.HealthAnomalies(name, 20)

	var sb strings.Builder
	sb.WriteString(head("probe", html.EscapeString(name), "近 24 小时异常"))
	if len(samples) == 0 {
		sb.WriteString(card(ic("ok") + " 没有异常探测点，这条出口很稳。"))
	} else {
		var lines strings.Builder
		for i, s := range samples {
			if i > 0 {
				lines.WriteString("\n")
			}
			if s.OK {
				fmt.Fprintf(&lines, "🐢 %s　<b>%s</b> 慢", s.At.In(beijing).Format("01-02 15:04"), monitor.FormatUS(s.US))
			} else {
				fmt.Fprintf(&lines, "🔴 %s　<b>失败</b>", s.At.In(beijing).Format("01-02 15:04"))
			}
		}
		sb.WriteString(card(lines.String()))
		sb.WriteString("\n<i>失败或明显慢于均值的探测点，新的在前。感觉卡顿时对一下时间点。</i>")
	}

	b.render(ctx, v, sb.String(), inlineKeyboard(
		[]btn{{Text: "刷新", Data: "refresh:health_detail:" + name}},
		navRow("health"),
	))
}

// humanBytes 把字节数格式化为人类可读。
func humanBytes(n int64) string {
	switch {
	case n >= 1<<30:
		return fmt.Sprintf("%.1f GB", float64(n)/(1<<30))
	case n >= 1<<20:
		return fmt.Sprintf("%.1f MB", float64(n)/(1<<20))
	case n >= 1<<10:
		return fmt.Sprintf("%.1f KB", float64(n)/(1<<10))
	}
	return fmt.Sprintf("%d B", n)
}

// rateIcon 按失败率返回红黄绿。
func rateIcon(r float64) string {
	switch {
	case r >= 0.2:
		return "🔴"
	case r > 0:
		return "🟡"
	default:
		return "🟢"
	}
}

// levelIcon 按水位占比返回红黄绿。
func levelIcon(cur, max int) string {
	if max <= 0 {
		return "🟢"
	}
	switch r := float64(cur) / float64(max); {
	case r >= 0.9:
		return "🔴"
	case r >= 0.6:
		return "🟡"
	default:
		return "🟢"
	}
}

// showMonitorSettings 展示并调整健康监控告警设置。
func (b *Bot) showMonitorSettings(ctx context.Context, v view) {
	after, cooldown, disabled := b.Manager.MonitorSettings()

	var sb strings.Builder
	state := "已开启"
	if disabled {
		state = "已关闭"
	}
	sb.WriteString(head("alert", "告警", state))
	sb.WriteString(card(fmt.Sprintf("连续失败　<b>%d</b> 次后告警（约 %d 分钟无响应）\n冷却　<b>%d</b> 分钟", after, after, cooldown)))
	sb.WriteString("\n<i>出口连续探测失败达到阈值时推送，恢复后自动通知。</i>")

	toggle := btn{Text: "关闭告警", Data: "monitor_toggle_alerts", Icon: "mute", Style: "danger"}
	if disabled {
		toggle = btn{Text: "开启告警", Data: "monitor_toggle_alerts", Icon: "alert", Style: "success"}
	}
	b.render(ctx, v, sb.String(), inlineKeyboard(
		[]btn{{Text: fmt.Sprintf("阈值 %d 次", after), Data: "ask_monitor_after"},
			{Text: fmt.Sprintf("冷却 %d 分钟", cooldown), Data: "ask_monitor_cooldown"}},
		[]btn{toggle},
		navRow("health"),
	))
}
