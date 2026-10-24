package bot

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/w0ven/5gpn-next/internal/manage"
)

// appLogo 渲染应用 Logo，不支持 custom emoji 时回落普通 emoji。
func appLogo(st manage.AppStatus) string {
	if st.EmojiID == "" {
		return st.Emoji
	}
	return tgEmoji(icon{st.EmojiID, st.Emoji})
}

func (b *Bot) showApps(ctx context.Context, v view) {
	list := b.Manager.Apps()

	var sb strings.Builder
	sb.WriteString(head("route", "应用分流"))
	sb.WriteString("<i>给常用应用单独选出口。排在自定义规则之后、国内直连之前；广告拦截照常生效。</i>\n")
	var on strings.Builder
	n := 0
	for _, st := range list {
		if st.Egress == "" {
			continue
		}
		if n > 0 {
			on.WriteString("\n")
		}
		n++
		fmt.Fprintf(&on, "%s %s → <b>%s</b>", appLogo(st), esc(st.Name), esc(st.EgressDisplay))
	}
	if n == 0 {
		on.WriteString("还没有单独指定出口的应用。")
	}
	sb.WriteString(card(on.String()))

	var bs []btn
	for _, st := range list {
		label := st.Name
		if st.Egress != "" {
			label += " · " + truncateText(st.EgressDisplay, 6)
		}
		bs = append(bs, btn{Text: label, Data: "app:" + st.Key, Icon: "app:" + st.Key})
	}
	rows := grid(2, bs)
	rows = append(rows, navRow("rules"))
	b.render(ctx, v, sb.String(), inlineKeyboard(rows...))
}

// showApp 是单个应用的出口选择页，extra 作为底部状态行附加。
func (b *Bot) showApp(ctx context.Context, v view, key, extra string) {
	st, ok := b.Manager.App(key)
	if !ok {
		b.showApps(ctx, v)
		return
	}

	var sb strings.Builder
	sb.WriteString(appLogo(st) + " <b>" + esc(st.Name) + "</b>\n")
	var info strings.Builder
	if st.Egress == "" {
		info.WriteString("出口　<b>跟随默认</b>")
	} else {
		fmt.Fprintf(&info, "出口　<b>%s</b>", esc(st.EgressDisplay))
		if st.ListDomains > 0 {
			fmt.Fprintf(&info, "\n域名　清单 <b>%d</b> 条 + 内置 %d 条", st.ListDomains, st.Core)
		} else {
			fmt.Fprintf(&info, "\n%s 清单未下载，先用内置 %d 个核心域名；重选一次出口即可重试", ic("warn"), st.Core)
		}
	}
	sb.WriteString(card(info.String()))
	sb.WriteString(extra)

	choices := append([][2]string{{"", "跟随默认"}}, b.Manager.AppEgressChoices()...)
	var bs []btn
	for _, c := range choices {
		arg := orDefault(c[0], "-")
		e := btn{Text: c[1], Data: "app_set:" + key + ":" + arg}
		if c[0] == st.Egress {
			e.Text, e.Style = "● "+c[1], "primary"
		}
		bs = append(bs, e)
	}
	rows := grid(2, bs)
	if st.Egress != "" {
		rows = append(rows, []btn{{Text: "核对分流", Data: "app_check:" + key, Icon: "probe"}})
	}
	rows = append(rows, navRow("apps"))
	b.render(ctx, v, sb.String(), inlineKeyboard(rows...))
}

func (b *Bot) doSetApp(ctx context.Context, v view, arg string) {
	key, egress, ok := strings.Cut(arg, ":")
	if !ok {
		b.showApps(ctx, v)
		return
	}
	if egress == "-" {
		egress = ""
	}
	if st, ok := b.Manager.App(key); ok && st.Egress == egress {
		b.ack(ctx, v, "已经是这个出口", false)
		return
	}
	if egress != "" && egress != "DIRECT" {
		b.showApp(ctx, v, key, note("loading", "正在验证出口；首次启用还会下载域名清单…"))
	}
	if err := b.Manager.SetAppEgress(key, egress); err != nil {
		b.ack(ctx, v, "设置失败", true)
		b.showApp(ctx, v, key, note("warn", "设置失败："+esc(err.Error())))
		return
	}
	st, _ := b.Manager.App(key)
	if egress == "" {
		b.ack(ctx, v, st.Name+" 已改为跟随默认", false)
	} else {
		b.ack(ctx, v, st.Name+" 已改走 "+st.EgressDisplay, false)
	}
	b.showApp(ctx, v, key, "")
}

func (b *Bot) showAppCheck(ctx context.Context, v view, key string) {
	st, ok := b.Manager.App(key)
	if !ok {
		b.showApps(ctx, v)
		return
	}
	res, err := b.Manager.CheckApp(key)
	if err != nil {
		b.fail(ctx, v, "无法核对", err, "app:"+key)
		return
	}
	names := map[string]string{}
	for _, c := range b.Manager.AppEgressChoices() {
		names[c[0]] = c[1]
	}
	eg := esc(res.EgressDisplay)

	var sb strings.Builder
	sb.WriteString(appLogo(st) + " <b>" + esc(st.Name) + " · 分流核对</b>　<i>选定 " + eg + "</i>\n")

	if len(res.Current) > 0 {
		blocked := 0
		for _, r := range res.Current {
			if r.Blocked {
				blocked++
			}
		}
		if res.CurrentMismatch > 0 {
			fmt.Fprintf(&sb, "\n%s <b>按当前规则</b>　%d 个域名不走 %s\n", ic("warn"), res.CurrentMismatch, eg)
		} else {
			fmt.Fprintf(&sb, "\n%s <b>按当前规则</b>　%d 个域名全部走 %s", ic("ok"), len(res.Current)-blocked, eg)
			if blocked > 0 {
				fmt.Fprintf(&sb, "，%d 个广告域名被拦截", blocked)
			}
			sb.WriteString("\n")
		}
		sb.WriteString(routeCard(res.Current, names))
	}

	fmt.Fprintf(&sb, "\n<b>实际连接</b>　<i>%s</i>\n", windowLabel(res))
	switch {
	case len(res.Domains) == 0:
		sb.WriteString(card(fmt.Sprintf("还没有 %s 的连接。手机走内网卡打开 %s 用一会儿，再来核对。", esc(st.Name), esc(st.Name))))
	case res.Mismatch > 0:
		fmt.Fprintf(&sb, "%s <b>%d</b> 个域名有连接没走 %s\n", ic("warn"), res.Mismatch, eg)
		sb.WriteString(checkCard(res.Domains, names))
	default:
		fmt.Fprintf(&sb, "%s <b>%d</b> 个域名全部经 %s\n", ic("ok"), len(res.Domains), eg)
		sb.WriteString(checkCard(res.Domains, names))
	}
	if len(res.Suspects) > 0 {
		fmt.Fprintf(&sb, "\n%s <b>疑似漏网</b>　<i>带 %s 特征，不在清单里，也没走选定出口</i>\n", ic("probe"), esc(st.Name))
		sb.WriteString(checkCard(res.Suspects, names))
	}

	b.ack(ctx, v, "已核对", false)
	b.render(ctx, v, sb.String(), inlineKeyboard(
		[]btn{{Text: "重新核对", Data: "app_check:" + key}},
		navRow("app:"+key),
	))
}

// routeCard 渲染按当前规则的判定：✓ 走选定出口，✗ 被其它规则截走，⊘ 被拦截。
func routeCard(list []manage.AppRoute, names map[string]string) string {
	var sb strings.Builder
	sb.WriteString("<blockquote expandable>")
	for i, r := range list {
		if i > 0 {
			sb.WriteString("\n")
		}
		switch {
		case r.Blocked:
			fmt.Fprintf(&sb, "⊘ <code>%s</code>　广告拦截", esc(r.Host))
		case r.OK:
			fmt.Fprintf(&sb, "✓ <code>%s</code>", esc(r.Host))
		default:
			fmt.Fprintf(&sb, "✗ <code>%s</code>　→ %s\n　<i>%s</i>", esc(r.Host),
				esc(orDefault(names[r.Egress], r.Egress)), esc(r.Rule))
		}
	}
	sb.WriteString("</blockquote>\n")
	return sb.String()
}

func checkCard(list []manage.AppDomain, names map[string]string) string {
	var sb strings.Builder
	sb.WriteString("<blockquote expandable>")
	for i, d := range list {
		if i > 0 {
			sb.WriteString("\n")
		}
		mark := "✓"
		if !d.OK {
			mark = "✗"
		}
		fmt.Fprintf(&sb, "%s <code>%s</code>　%s", mark, esc(d.Host), esc(egressCounts(d.Egresses, names)))
		if !d.OK && d.Rule != "" {
			fmt.Fprintf(&sb, "\n　<i>%s</i>", esc(d.Rule))
		}
	}
	sb.WriteString("</blockquote>\n")
	return sb.String()
}

func egressCounts(m map[string]int, names map[string]string) string {
	type kv struct {
		name string
		n    int
	}
	var list []kv
	for k, n := range m {
		list = append(list, kv{k, n})
	}
	sort.Slice(list, func(i, j int) bool {
		if list[i].n != list[j].n {
			return list[i].n > list[j].n
		}
		return list[i].name < list[j].name
	})
	parts := make([]string, 0, len(list))
	for _, e := range list {
		parts = append(parts, fmt.Sprintf("%s×%d", orDefault(names[e.name], e.name), e.n))
	}
	return strings.Join(parts, " ")
}

// windowLabel 说明「实际连接」统计的起点。
func windowLabel(res manage.AppCheck) string {
	ago := agoText(time.Since(res.Since))
	switch res.SinceKind {
	case manage.SinceChanged:
		return "改出口后 " + ago
	case manage.SinceStarted:
		return "网关启动后 " + ago
	}
	return "最近 " + ago
}

func agoText(d time.Duration) string {
	if d < time.Hour {
		return fmt.Sprintf("%d 分钟", max(1, int(d.Minutes())))
	}
	return fmt.Sprintf("%d 小时", int(d.Hours()+0.5))
}
