package bot

import (
	"context"
	"encoding/json"
	"fmt"
	"html"
	"sort"
	"strings"
	"time"

	"github.com/w0ven/5gpn-next/internal/apps"
	"github.com/w0ven/5gpn-next/internal/manage"
)

// appLogo 渲染应用 Logo（ZaiHuaNews custom emoji），不支持时回落普通 emoji。
func appLogo(st manage.AppStatus) string {
	if st.EmojiID == "" {
		return st.Emoji
	}
	return fmt.Sprintf(`<tg-emoji emoji-id="%s">%s</tg-emoji>`, st.EmojiID, st.Emoji)
}

const buttonIconField = "icon_custom_emoji_id"

// stripButtonIcons 去掉键盘里的按钮图标；解析失败时原样返回。
func stripButtonIcons(keyboard string) string {
	var kb map[string][][]map[string]any
	if err := json.Unmarshal([]byte(keyboard), &kb); err != nil {
		return keyboard
	}
	for _, row := range kb["inline_keyboard"] {
		for _, b := range row {
			delete(b, buttonIconField)
		}
	}
	out, err := json.Marshal(kb)
	if err != nil {
		return keyboard
	}
	return string(out)
}

// buttonIcon 为打开应用页的按钮配上该应用的 Logo。
func buttonIcon(data string) string {
	if key, ok := strings.CutPrefix(data, "app:"); ok {
		if a, ok := apps.Get(key); ok {
			return a.EmojiID
		}
	}
	return ""
}

func (b *Bot) showApps(ctx context.Context, v view) {
	list := b.Manager.Apps()

	var sb strings.Builder
	sb.WriteString(pageHead("📱", "应用分流"))
	sb.WriteString("<i>给常用应用单独选出口。优先级低于自定义规则、高于默认出口，广告拦截照常生效。</i>\n\n")
	var info strings.Builder
	for i, st := range list {
		if i > 0 {
			info.WriteString("\n")
		}
		if st.Egress == "" {
			fmt.Fprintf(&info, "%s %s　<i>跟随默认</i>", appLogo(st), html.EscapeString(st.Name))
		} else {
			fmt.Fprintf(&info, "%s <b>%s</b>　→ <b>%s</b>", appLogo(st),
				html.EscapeString(st.Name), html.EscapeString(st.EgressDisplay))
		}
	}
	sb.WriteString(card(info.String()))
	sb.WriteString("\n<i>点应用选择出口 ↓</i>")

	var rows [][]btn
	var cur []btn
	for _, st := range list {
		cur = append(cur, btn{st.Name, "app:" + st.Key})
		if len(cur) == 3 {
			rows = append(rows, cur)
			cur = nil
		}
	}
	if len(cur) > 0 {
		rows = append(rows, cur)
	}
	rows = append(rows, []btn{btnBack("rules"), btnHome()})
	b.render(ctx, v, sb.String(), inlineKeyboard(rows...))
}

func (b *Bot) showApp(ctx context.Context, v view, key string) {
	st, ok := b.Manager.App(key)
	if !ok {
		b.showApps(ctx, v)
		return
	}

	var sb strings.Builder
	fmt.Fprintf(&sb, "%s  <b>%s</b>\n", appLogo(st), html.EscapeString(st.Name))
	var info strings.Builder
	if st.Egress == "" {
		info.WriteString("出口　<i>跟随默认规则</i>")
	} else {
		fmt.Fprintf(&info, "出口　<b>%s</b>", html.EscapeString(st.EgressDisplay))
		if st.ListDomains > 0 {
			fmt.Fprintf(&info, "\n清单　<b>%d</b> 条 + 内置 %d 条", st.ListDomains, st.Core)
		} else {
			fmt.Fprintf(&info, "\n⚠️ 清单尚未下载，先用内置 %d 个核心域名\n<i>重新选一次出口即可重试下载</i>", st.Core)
		}
	}
	sb.WriteString(card(info.String()))
	sb.WriteString("\n<i>选择出口：</i>")

	mark := func(name, label string) string {
		if name == st.Egress {
			return "✅ " + label
		}
		return label
	}
	choices := [][2]string{{"", "跟随默认"}}
	choices = append(choices, b.Manager.AppEgressChoices()...)
	var rows [][]btn
	var cur []btn
	for _, c := range choices {
		arg := c[0]
		if arg == "" {
			arg = "-"
		}
		cur = append(cur, btn{mark(c[0], c[1]), "app_set:" + key + ":" + arg})
		if len(cur) == 2 {
			rows = append(rows, cur)
			cur = nil
		}
	}
	if len(cur) > 0 {
		rows = append(rows, cur)
	}
	if st.Egress != "" {
		rows = append(rows, []btn{{"🔍 核对分流", "app_check:" + key}})
	}
	rows = append(rows, []btn{btnBack("apps"), btnHome()})
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
	if egress != "" && egress != "DIRECT" {
		b.render(ctx, v, "⏳ 正在验证出口连通性 …\n\n<i>首次启用还会下载该应用的域名清单，通常几秒内完成。</i>", "")
	}
	if err := b.Manager.SetAppEgress(key, egress); err != nil {
		b.render(ctx, v, errBox("设置失败", err), backTo("app:"+key))
		return
	}
	b.showApp(ctx, v, key)
}

func (b *Bot) showAppCheck(ctx context.Context, v view, key string) {
	st, ok := b.Manager.App(key)
	if !ok {
		b.showApps(ctx, v)
		return
	}
	res, err := b.Manager.CheckApp(key)
	if err != nil {
		b.render(ctx, v, errBox("无法核对", err), backTo("app:"+key))
		return
	}
	names := map[string]string{}
	for _, c := range b.Manager.AppEgressChoices() {
		names[c[0]] = c[1]
	}

	var sb strings.Builder
	fmt.Fprintf(&sb, "%s  <b>%s · 分流核对</b>\n", appLogo(st), html.EscapeString(st.Name))
	fmt.Fprintf(&sb, "<i>%s · 选定 %s</i>\n\n", sinceText(res.Since), html.EscapeString(res.EgressDisplay))
	switch {
	case len(res.Domains) == 0:
		fmt.Fprintf(&sb, "这段时间还没有 %s 的转发记录。\n用手机打开 %s 用一会儿再来核对。",
			html.EscapeString(st.Name), html.EscapeString(st.Name))
	case res.Mismatch > 0:
		fmt.Fprintf(&sb, "⚠️ <b>%d</b> 个域名有连接没走 %s\n", res.Mismatch, html.EscapeString(res.EgressDisplay))
	default:
		fmt.Fprintf(&sb, "✅ <b>%d</b> 个域名全部经 %s\n", len(res.Domains), html.EscapeString(res.EgressDisplay))
	}
	if len(res.Domains) > 0 {
		sb.WriteString(checkCard(res.Domains, names))
	}
	if len(res.Suspects) > 0 {
		fmt.Fprintf(&sb, "\n🔎 <b>疑似漏网</b>　<i>带 %s 特征但不在清单里，也没走选定出口</i>\n",
			html.EscapeString(st.Name))
		sb.WriteString(checkCard(res.Suspects, names))
	}

	b.render(ctx, v, sb.String(), inlineKeyboard(
		[]btn{{"🔄 重新核对", "app_check:" + key}},
		[]btn{btnBack("app:" + key), btnHome()},
	))
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
		fmt.Fprintf(&sb, "%s <code>%s</code>　%s", mark, html.EscapeString(d.Host), html.EscapeString(egressCounts(d.Egresses, names)))
		if !d.OK && d.Rule != "" {
			fmt.Fprintf(&sb, "\n　<i>%s</i>", html.EscapeString(d.Rule))
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
		label := names[e.name]
		if label == "" {
			label = e.name
		}
		parts = append(parts, fmt.Sprintf("%s×%d", label, e.n))
	}
	return strings.Join(parts, " ")
}

func sinceText(t time.Time) string {
	d := time.Since(t)
	switch {
	case d < time.Hour:
		return fmt.Sprintf("最近 %d 分钟", max(1, int(d.Minutes())))
	default:
		return fmt.Sprintf("最近 %d 小时", int(d.Hours()+0.5))
	}
}
