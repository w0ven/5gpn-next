package bot

import (
	"context"
	"fmt"
	"strings"
	"time"

	updatepkg "github.com/w0ven/5gpn-next/internal/update"
)

// showUpdate 是版本页：只展示版本与可用更新，设置、备份、历史收进「设置」子页。
func (b *Bot) showUpdate(ctx context.Context, v view) {
	b.renderUpdate(ctx, v, "")
}

func (b *Bot) renderUpdate(ctx context.Context, v view, extra string) {
	rel, checkedAt, hasCache := b.Manager.CachedUpdate()

	var sb strings.Builder
	sb.WriteString(head("update", "版本"))
	var info strings.Builder
	fmt.Fprintf(&info, "当前　<code>%s</code>", esc(b.Version))
	newTag := ""
	switch {
	case !hasCache || rel == nil:
		info.WriteString("\n尚未检查过")
	case b.Manager.UpdateBanner() != "":
		newTag = rel.Tag
		fmt.Fprintf(&info, "\n最新　<b>%s</b>", esc(rel.Tag))
		if !rel.Published.IsZero() {
			fmt.Fprintf(&info, "　<i>%s 发布</i>", rel.Published.In(beijing).Format("01-02 15:04"))
		}
	case b.Manager.IsIgnoredVersion(rel.Tag) && rel.Tag != b.Version:
		fmt.Fprintf(&info, "\n最新　<code>%s</code>　<i>已忽略</i>", esc(rel.Tag))
	default:
		info.WriteString("\n" + ic("ok") + " 已是最新")
	}
	if hasCache {
		fmt.Fprintf(&info, "\n<i>检查于 %s</i>", checkedAt.In(beijing).Format("01-02 15:04"))
	}
	sb.WriteString(card(info.String()))
	if newTag != "" {
		if notes := truncateText(strings.TrimSpace(rel.Notes), 800); notes != "" {
			sb.WriteString("\n<b>更新内容</b>\n<blockquote expandable>" + esc(notes) + "</blockquote>")
		}
	}
	sb.WriteString(extra)

	var rows [][]btn
	if newTag != "" {
		rows = append(rows,
			[]btn{{Text: "升级到 " + newTag, Data: "update_apply:" + newTag, Icon: "update", Style: "primary"}},
			[]btn{{Text: "忽略此版本", Data: "update_ignore:" + newTag, Icon: "mute"}})
	}
	rows = append(rows,
		[]btn{{Text: "检查更新", Data: "update_check"}, {Text: "设置", Data: "update_settings", Icon: "settings"}},
		navRow("menu"))
	b.render(ctx, v, sb.String(), inlineKeyboard(rows...))
}

func (b *Bot) doUpdateCheck(ctx context.Context, v view) {
	b.renderUpdate(ctx, v, note("loading", "正在查询最新版本…"))
	cctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	has, rel, err := b.Manager.CheckUpdate(cctx)
	cancel()
	switch {
	case err != nil:
		b.ack(ctx, v, "查询失败", true)
		b.renderUpdate(ctx, v, note("warn", "查询失败："+esc(err.Error())))
	case has:
		b.ack(ctx, v, "发现新版本 "+rel.Tag, false)
		b.renderUpdate(ctx, v, "")
	default:
		b.ack(ctx, v, "已是最新版本", false)
		b.renderUpdate(ctx, v, "")
	}
}

func (b *Bot) showUpdateSettings(ctx context.Context, v view) {
	checkOn, autoApply, interval := b.Manager.UpdateSettings()
	ignored := b.Manager.IgnoredVersions()
	backups := b.Manager.UpdateBackups()

	var sb strings.Builder
	sb.WriteString(head("settings", "更新设置"))
	var info strings.Builder
	if checkOn {
		fmt.Fprintf(&info, "自动检查　<b>每 %d 小时</b>", interval)
	} else {
		info.WriteString("自动检查　<b>关</b>")
	}
	fmt.Fprintf(&info, "\n自动安装　<b>%s</b>", onOff(autoApply))
	if len(ignored) > 0 {
		fmt.Fprintf(&info, "\n已忽略　<code>%s</code>", esc(strings.Join(ignored, ", ")))
	}
	sb.WriteString(card(info.String()))

	if len(backups) > 0 {
		var lines strings.Builder
		for i, bk := range backups {
			if i > 0 {
				lines.WriteString("\n")
			}
			fmt.Fprintf(&lines, "<code>%s</code>　%.1f MB", esc(bk.Tag), bk.SizeMB)
			if !bk.ModTime.IsZero() {
				fmt.Fprintf(&lines, "　%s", bk.ModTime.In(beijing).Format("01-02 15:04"))
			}
		}
		sb.WriteString("\n<b>本地备份</b>　<i>升级时自动保留，可回退</i>\n" + card(lines.String()))
	}
	sb.WriteString("\n<i>升级会校验哈希后替换程序并重启；启动失败自动回退。</i>")

	auto := btn{Text: "自动安装：关", Data: "update_toggle_auto"}
	if autoApply {
		auto = btn{Text: "自动安装：开", Data: "update_toggle_auto", Style: "success"}
	}
	rows := [][]btn{
		{auto, {Text: fmt.Sprintf("间隔 %d 小时", interval), Data: "ask_update_interval"}},
		{{Text: "升级历史", Data: "update_history"}},
	}
	if len(b.Manager.RollbackVersions()) > 0 {
		rows[1] = append(rows[1], btn{Text: "回退版本", Data: "update_rollback"})
	}
	if len(ignored) > 0 {
		rows = append(rows, []btn{{Text: fmt.Sprintf("清空忽略（%d）", len(ignored)), Data: "update_clear_ignored"}})
	}
	rows = append(rows, navRow("update"))
	b.render(ctx, v, sb.String(), inlineKeyboard(rows...))
}

// updateStages 是升级阶段的展示顺序与文案。
var updateStages = []struct{ key, label string }{
	{"download", "下载新版本"},
	{"verify", "校验哈希"},
	{"backup", "备份当前版本"},
	{"restart", "重启生效"},
}

// renderUpdateProgress 渲染升级进度：已完成 ✓、进行中 ›、未开始 ·。
func renderUpdateProgress(tag, current string) string {
	var sb strings.Builder
	sb.WriteString(head("update", "正在升级到 "+esc(tag)))
	var lines strings.Builder
	reached := true
	for i, st := range updateStages {
		if i > 0 {
			lines.WriteString("\n")
		}
		switch {
		case st.key == current:
			fmt.Fprintf(&lines, "%s <b>%s</b>", ic("loading"), st.label)
			reached = false
		case reached:
			fmt.Fprintf(&lines, "✓ %s", st.label)
		default:
			fmt.Fprintf(&lines, "· <i>%s</i>", st.label)
		}
	}
	sb.WriteString(card(lines.String()))
	sb.WriteString("\n<i>重启后由独立事务做健康检查，失败自动回退。</i>")
	return sb.String()
}

func (b *Bot) doUpdateApply(ctx context.Context, v view, tag string) {
	b.ack(ctx, v, "开始升级", false)
	b.render(ctx, v, renderUpdateProgress(tag, "download"), "")

	// 阶段回调：每步就地编辑同一条消息。回调来自升级 goroutine，
	// 用独立短超时 context，绝不阻塞升级本身。
	// lastStage 去重：初始渲染已是 download，首个回调不必重复编辑。
	lastStage := "download"
	b.Manager.SetUpdateStageHook(func(stage, _ string) {
		if stage == lastStage {
			return
		}
		lastStage = stage
		sctx, scancel := context.WithTimeout(context.Background(), 10*time.Second)
		b.render(sctx, v, renderUpdateProgress(tag, stage), "")
		scancel()
	})
	defer b.Manager.SetUpdateStageHook(nil)

	// 升级会重启本进程，用独立 context 避免被取消
	cctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	if _, err := b.Manager.ApplyUpdate(cctx, tag); err != nil {
		b.render(ctx, v, errBox("升级失败", err), backTo("update"))
		return
	}
	// 全部准备阶段完成：同一条消息收尾为「重启生效中」。重启后新进程
	// 会继续编辑这条消息写入最终结果——整个升级链路只占一条消息。
	if id := b.render(ctx, v, renderUpdateProgress(tag, "restart"), ""); id != 0 {
		updatepkg.SaveNotifyTarget(v.chatID, id)
	}
}

func (b *Bot) showRollback(ctx context.Context, v view) {
	vs := b.Manager.RollbackVersions()
	if len(vs) == 0 {
		b.ack(ctx, v, "没有可用的版本备份", true)
		return
	}
	var rows [][]btn
	for i, ver := range vs {
		if i >= 6 {
			break
		}
		rows = append(rows, []btn{{Text: "回退到 " + ver, Data: "rollback:" + ver, Style: "danger"}})
	}
	rows = append(rows, navRow("update_settings"))
	b.render(ctx, v, head("update", "回退版本")+
		"<i>回退会替换程序并重启，启动后自动验证服务状态。</i>", inlineKeyboard(rows...))
}

func (b *Bot) doRollback(ctx context.Context, v view, tag string) {
	b.render(ctx, v, head("update", "回退版本")+note("loading", "正在回退到 <code>"+esc(tag)+"</code>…"), "")
	cctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	msg, err := b.Manager.Rollback(cctx, tag)
	if err != nil {
		b.render(ctx, v, errBox("回退失败", err), backTo("update_settings"))
		return
	}
	b.render(ctx, v, head("ok", "回退已开始")+card(esc(msg)), backTo("menu"))
}

func (b *Bot) showUpdateHistory(ctx context.Context, v view) {
	hist := b.Manager.UpdateHistory(10)

	var sb strings.Builder
	sb.WriteString(head("update", "升级历史"))
	if len(hist) == 0 {
		sb.WriteString(card("暂无记录。每次升级完成后（无论成败）都会记在这里。"))
	} else {
		var lines strings.Builder
		for i, r := range hist {
			if i > 0 {
				lines.WriteString("\n")
			}
			mark, label := "·", r.Status
			switch r.Status {
			case "success":
				mark, label = "✓", "成功"
			case "rolled_back":
				mark, label = "↩", "已回退"
			case "install_failed":
				mark, label = "✗", "安装失败"
			case "rollback_failed":
				mark, label = "✗", "回退失败"
			}
			fmt.Fprintf(&lines, "%s %s → <b>%s</b>　%s　<i>%s</i>", mark, esc(r.From), esc(r.To), label,
				time.Unix(r.At, 0).In(beijing).Format("01-02 15:04"))
		}
		sb.WriteString(card(lines.String()))
	}
	b.render(ctx, v, sb.String(), backTo("update_settings"))
}
