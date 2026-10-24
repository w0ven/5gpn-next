package bot

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/w0ven/5gpn-next/internal/manage"
	"github.com/w0ven/5gpn-next/internal/stats"
)

func (b *Bot) showAdBlock(ctx context.Context, v view) {
	ad := b.Manager.Status(b.Version).AdBlock
	suspects := b.Manager.AdSuspects(0)

	var sb strings.Builder
	state := "已关闭"
	if ad.Enabled {
		state = "已开启"
	}
	sb.WriteString(head("shield", "广告拦截", state))
	var info strings.Builder
	switch {
	case ad.Enabled && ad.Domains > 0:
		fmt.Fprintf(&info, "规则　anti-AD <b>%s</b> 条", groupDigits(ad.Domains))
		if ad.UpdatedAt > 0 {
			fmt.Fprintf(&info, " · %s更新", agoShort(time.Unix(ad.UpdatedAt, 0)))
		}
		info.WriteString("\n")
	case ad.Enabled:
		info.WriteString(ic("warn") + " 规则尚未载入，点「重试载入」\n")
	}
	if names, n := extrasOn(ad.Extras); len(names) > 0 {
		fmt.Fprintf(&info, "附加　<b>%s</b>", esc(strings.Join(names, "、")))
		if n > 0 {
			fmt.Fprintf(&info, "（+%s 条）", groupDigits(n))
		}
		info.WriteString("\n")
	}
	fmt.Fprintf(&info, "今日　<b>%s</b> 次 · 近 7 天 <b>%s</b> 次", groupDigits(int(ad.Hits.Today)), groupDigits(int(ad.Hits.Days7)))
	if line := sparkline(ad.Hits.Daily); line != "" {
		info.WriteString("\n" + line + "　<i>近 7 天</i>")
	}
	if ad.Allowlist > 0 {
		fmt.Fprintf(&info, "\n白名单　<b>%d</b> 条", ad.Allowlist)
	}
	sb.WriteString(card(info.String()))

	var rows [][]btn
	if n := min(len(ad.Hits.Recent), 3); n > 0 {
		var lines strings.Builder
		for i := 0; i < n; i++ {
			ev := ad.Hits.Recent[i]
			if i > 0 {
				lines.WriteString("\n")
			}
			fmt.Fprintf(&lines, "<code>%s</code> · %s", esc(ev.Host), agoShort(time.Unix(ev.At, 0)))
			rows = append(rows, []btn{{Text: "放行 " + truncateText(ev.Host, 24), Data: "ad_allow_hit:" + ruleFingerprint(ev.Host)}})
		}
		sb.WriteString("\n<b>最近拦截</b>　<i>误拦了就点下面放行</i>\n" + card(lines.String()))
	}
	if len(suspects) > 0 {
		sb.WriteString(note("probe", fmt.Sprintf("<b>%d</b> 个疑似漏网：像广告或上报、却没被拦的域名", len(suspects))))
	}
	sb.WriteString("\n<i>只拦 DNS 查询；视频内广告、信息流广告和写死 IP 的 App 拦不到。</i>")

	extraLabel := "附加列表"
	if names, _ := extrasOn(ad.Extras); len(names) > 0 {
		extraLabel = fmt.Sprintf("附加列表（%d）", len(names))
	}
	suspectLabel := "疑似漏网"
	if len(suspects) > 0 {
		suspectLabel = fmt.Sprintf("疑似漏网（%d）", len(suspects))
	}
	rows = append(rows, []btn{{Text: extraLabel, Data: "ad_extras"}, {Text: suspectLabel, Data: "ad_suspects", Icon: "probe"}})
	if ad.Enabled {
		second := []btn{{Text: "白名单", Data: "ad_allow_list"}}
		if ad.Domains == 0 {
			second = append(second, btn{Text: "重试载入", Data: "adblock_on"})
		}
		rows = append(rows, second, []btn{{Text: "关闭拦截", Data: "adblock_off", Style: "danger"}})
	} else {
		rows = append(rows,
			[]btn{{Text: "开启拦截", Data: "adblock_on", Icon: "shield", Style: "success"}},
			[]btn{{Text: "白名单", Data: "ad_allow_list"}})
	}
	rows = append(rows, navRow("menu"))
	b.render(ctx, v, sb.String(), inlineKeyboard(rows...))
}

// extrasOn 返回已开启附加列表的名称与已载入的条目总数。
func extrasOn(list []manage.AdBlockExtraStatus) ([]string, int) {
	var names []string
	n := 0
	for _, x := range list {
		if x.Enabled {
			names = append(names, x.Name)
			n += x.Domains
		}
	}
	return names, n
}

// sparkline 把每日计数画成一行小柱；全为 0 时返回空串。
func sparkline(days []stats.DayCount) string {
	var top int64
	for _, d := range days {
		top = max(top, d.Count)
	}
	if top == 0 {
		return ""
	}
	const bars = "▁▂▃▄▅▆▇█"
	levels := []rune(bars)
	var sb strings.Builder
	for _, d := range days {
		i := 0
		if d.Count > 0 {
			i = 1 + int(d.Count*int64(len(levels)-2)/top)
		}
		sb.WriteRune(levels[i])
	}
	return sb.String()
}

// agoShort 把时间写成「N 分钟前」这类相对说法，避免服务器时区造成的误读。
func agoShort(t time.Time) string {
	d := time.Since(t)
	switch {
	case d < time.Minute:
		return "刚刚"
	case d < time.Hour:
		return fmt.Sprintf("%d 分钟前", int(d.Minutes()))
	case d < 48*time.Hour:
		return fmt.Sprintf("%d 小时前", int(d.Hours()))
	}
	return fmt.Sprintf("%d 天前", int(d.Hours()/24))
}

func (b *Bot) showAdExtras(ctx context.Context, v view, extra string) {
	ad := b.Manager.Status(b.Version).AdBlock

	var sb strings.Builder
	sb.WriteString(head("shield", "附加列表"))
	sb.WriteString("<i>按自己的设备勾选，主规则 anti-AD 始终生效；列表每天自动更新。</i>\n")
	var lines strings.Builder
	for i, x := range ad.Extras {
		if i > 0 {
			lines.WriteString("\n")
		}
		mark := "○"
		if x.Enabled {
			mark = "●"
		}
		fmt.Fprintf(&lines, "%s <b>%s</b>", mark, esc(x.Name))
		if x.Enabled && x.Domains > 0 {
			fmt.Fprintf(&lines, "　%s 条", groupDigits(x.Domains))
		}
		fmt.Fprintf(&lines, "\n　<i>%s</i>", esc(x.Desc))
		if x.Warn != "" {
			fmt.Fprintf(&lines, "\n　%s %s", ic("warn"), esc(x.Warn))
		}
	}
	sb.WriteString(card(lines.String()))
	if !ad.Enabled {
		sb.WriteString(note("warn", "广告拦截未开启，勾选的列表会在开启后生效。"))
	}
	sb.WriteString(extra)

	var bs []btn
	for _, x := range ad.Extras {
		e := btn{Text: "○ " + x.Name, Data: "ad_extra:" + x.Key}
		if x.Enabled {
			e = btn{Text: "● " + x.Name, Data: "ad_extra:" + x.Key, Style: "primary"}
		}
		bs = append(bs, e)
	}
	rows := grid(2, bs)
	rows = append(rows, navRow("adblock"))
	b.render(ctx, v, sb.String(), inlineKeyboard(rows...))
}

func (b *Bot) doAdExtra(ctx context.Context, v view, key string) {
	on := false
	for _, x := range b.Manager.Status(b.Version).AdBlock.Extras {
		if x.Key == key {
			on = !x.Enabled
		}
	}
	if on {
		b.showAdExtras(ctx, v, note("loading", "正在下载列表…"))
	}
	msg, err := b.Manager.SetAdBlockExtra(key, on)
	if err != nil {
		b.ack(ctx, v, err.Error(), true)
		b.showAdExtras(ctx, v, note("warn", esc(err.Error())))
		return
	}
	b.ack(ctx, v, msg, false)
	b.showAdExtras(ctx, v, "")
}

const suspectRows = 8

func (b *Bot) showAdSuspects(ctx context.Context, v view) {
	list := b.Manager.AdSuspects(0)

	var sb strings.Builder
	sb.WriteString(head("probe", "疑似漏网", "最近 24 小时"))
	sb.WriteString("<i>像广告或数据上报、却没被拦截的域名，按查询次数排序。点「拦截」加入自定义规则，可在 分流 → 删除规则 撤销。</i>\n")
	if len(list) == 0 {
		sb.WriteString(card("暂时没有发现。手机正常使用一段时间后再来看；网关重启后会重新积累。"))
	} else {
		var lines strings.Builder
		for i, s := range list {
			if i >= 20 {
				fmt.Fprintf(&lines, "\n… 另有 %d 个", len(list)-20)
				break
			}
			if i > 0 {
				lines.WriteString("\n")
			}
			fmt.Fprintf(&lines, "<code>%s</code>　×%d", esc(s.Host), s.Count)
		}
		sb.WriteString("<blockquote expandable>" + lines.String() + "</blockquote>")
	}

	var rows [][]btn
	for i, s := range list {
		if i >= suspectRows {
			break
		}
		rows = append(rows, []btn{{Text: "拦截 " + truncateText(s.Host, 26), Data: "ad_block_host:" + ruleFingerprint(s.Host)}})
	}
	rows = append(rows, []btn{{Text: "刷新", Data: "refresh:ad_suspects"}}, navRow("adblock"))
	b.render(ctx, v, sb.String(), inlineKeyboard(rows...))
}

func (b *Bot) doAdBlockHost(ctx context.Context, v view, fp string) {
	host := ""
	for _, s := range b.Manager.AdSuspects(0) {
		if ruleFingerprint(s.Host) == fp {
			host = s.Host
			break
		}
	}
	if host == "" {
		b.ack(ctx, v, "这个域名已经不在列表里了", true)
		b.showAdSuspects(ctx, v)
		return
	}
	msg, err := b.Manager.BlockDomain(host)
	if err != nil {
		b.fail(ctx, v, "拦截失败", err, "ad_suspects")
		return
	}
	b.ack(ctx, v, msg, false)
	b.showAdSuspects(ctx, v)
}
