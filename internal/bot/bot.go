// Package bot 实现 Telegram 管理机器人（纯标准库，长轮询）。
//
// 交互原则：
//   - 聊天里始终只有一个「屏幕」消息：导航一律就地编辑；新开一屏时删掉
//     旧屏。用户发来的命令与输入在读取后立即删除（节点链接含凭据）。
//   - 轻操作的结果用按钮上方的轻提示反馈，出错用弹窗，不跳转错误页。
//   - 主动推送的通知带「知道了」按钮，点了即删；点通知里的入口，该通知
//     就地变成新的屏幕。
//   - 只接受配置中列出的管理员 ID；其它来源静默忽略，不回任何内容。
//   - 一律使用 HTML parse_mode。域名与节点名常含 - _ . 等字符，
//     MarkdownV2 需逐字符转义，漏一个即整条发送失败。
package bot

import (
	"bytes"
	"context"
	"crypto/subtle"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"mime/multipart"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/w0ven/5gpn-next/internal/manage"
)

// Bot 是 Telegram 管理机器人。
type Bot struct {
	Token   string
	Admins  []int64
	Manager *manage.Manager
	Version string

	// PanelURL 是内网面板地址，供菜单展示
	PanelURL string

	client *http.Client
	offset int64
	// apiBase 与 state 只在测试中替换。
	apiBase string
	state   string

	mu sync.Mutex
	// pending 记录等待用户输入的动作：chatID -> action
	pending map[int64]string
	// promptMsg 记录发出提示的消息 ID，便于输入后就地更新
	promptMsg map[int64]int64
	// greeted 标记已经打过招呼的管理员，避免重复补发欢迎语
	greeted map[int64]bool
	// screens 记录每个会话当前的屏幕消息 ID，落盘以便升级重启后仍能收起旧屏。
	screens map[int64]int64
	// files 记录每个会话最近下发的文件消息（描述文件、二维码），重新获取时先删旧的。
	files map[int64][]int64
	// degrade 是按钮降级级别：1 去掉图标，2 再去掉配色。被拒后保持一小时，
	// 期间不再反复试探；过期后重新尝试完整按钮，避免一次偶发失败永久降级。
	degrade   int
	degradeAt time.Time
	// pendingGreet 为 true 时表示启动通知没送达，等用户首次交互再补
	pendingGreet bool
}

const stateDir = "/var/lib/5gpn-next"

// offsetFile 持久化长轮询 offset。
//
// 升级/回退会重启本进程；若 offset 只存内存，Telegram 会把
// 尚未确认的「立即升级」回调重投给新进程，形成升级→重启→再升级
// 的死循环。落盘后重启不再重放已处理的更新。
const offsetFile = "bot-offset"

const screensFile = "bot-screens.json"

func (b *Bot) statePath(name string) string { return filepath.Join(b.state, name) }

// New 构造 Bot。
func New(token string, admins []int64, m *manage.Manager, version string) *Bot {
	b := &Bot{
		Token:     token,
		Admins:    admins,
		Manager:   m,
		Version:   version,
		client:    &http.Client{Timeout: 70 * time.Second},
		apiBase:   "https://api.telegram.org",
		state:     stateDir,
		pending:   make(map[int64]string),
		promptMsg: make(map[int64]int64),
		screens:   make(map[int64]int64),
		files:     make(map[int64][]int64),
		greeted:   make(map[int64]bool),
	}
	if raw, err := os.ReadFile(b.statePath(offsetFile)); err == nil {
		if n, err := strconv.ParseInt(strings.TrimSpace(string(raw)), 10, 64); err == nil && n > 0 {
			b.offset = n
		}
	}
	if raw, err := os.ReadFile(b.statePath(screensFile)); err == nil {
		_ = json.Unmarshal(raw, &b.screens)
	}
	return b
}

// commands 是输入框左侧的命令菜单。
var commands = []struct{ cmd, desc string }{
	{"start", "主页"},
	{"status", "运行状态"},
	{"egress", "出口"},
	{"rules", "分流"},
	{"probe", "连通诊断"},
}

// Run 启动长轮询，直到 ctx 取消。
func (b *Bot) Run(ctx context.Context) {
	log.Printf("Telegram Bot 已启动，管理员 %v", b.Admins)
	b.setCommands(ctx)
	for {
		select {
		case <-ctx.Done():
			return
		default:
		}
		updates, err := b.getUpdates(ctx)
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			log.Printf("Bot 轮询失败: %v", err)
			time.Sleep(5 * time.Second)
			continue
		}
		for _, u := range updates {
			b.handle(ctx, u)
		}
	}
}

func (b *Bot) setCommands(ctx context.Context) {
	type c struct {
		Command     string `json:"command"`
		Description string `json:"description"`
	}
	list := make([]c, 0, len(commands))
	for _, x := range commands {
		list = append(list, c{x.cmd, x.desc})
	}
	raw, _ := json.Marshal(list)
	p := url.Values{}
	p.Set("commands", string(raw))
	if _, err := b.api(ctx, "setMyCommands", p); err != nil {
		log.Printf("Bot 设置命令菜单失败: %v", err)
	}
}

// ---------- Telegram API ----------

type update struct {
	UpdateID int64 `json:"update_id"`
	Message  *struct {
		MessageID int64 `json:"message_id"`
		From      struct {
			ID int64 `json:"id"`
		} `json:"from"`
		Chat struct {
			ID int64 `json:"id"`
		} `json:"chat"`
		Text string `json:"text"`
	} `json:"message"`
	CallbackQuery *struct {
		ID   string `json:"id"`
		From struct {
			ID int64 `json:"id"`
		} `json:"from"`
		Message *struct {
			MessageID int64 `json:"message_id"`
			Chat      struct {
				ID int64 `json:"id"`
			} `json:"chat"`
		} `json:"message"`
		Data string `json:"data"`
	} `json:"callback_query"`
}

func (b *Bot) api(ctx context.Context, method string, params url.Values) ([]byte, error) {
	endpoint := fmt.Sprintf("%s/bot%s/%s", b.apiBase, b.Token, method)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint,
		strings.NewReader(params.Encode()))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := b.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if err != nil {
		return nil, err
	}
	var r struct {
		OK          bool            `json:"ok"`
		Result      json.RawMessage `json:"result"`
		Description string          `json:"description"`
	}
	if err := json.Unmarshal(body, &r); err != nil {
		return nil, err
	}
	if !r.OK {
		return nil, fmt.Errorf("telegram: %s", r.Description)
	}
	return r.Result, nil
}

func (b *Bot) getUpdates(ctx context.Context) ([]update, error) {
	p := url.Values{}
	p.Set("timeout", "50")
	p.Set("offset", strconv.FormatInt(b.offset, 10))
	p.Set("allowed_updates", `["message","callback_query"]`)
	raw, err := b.api(ctx, "getUpdates", p)
	if err != nil {
		return nil, err
	}
	var ups []update
	if err := json.Unmarshal(raw, &ups); err != nil {
		return nil, err
	}
	advanced := false
	for _, u := range ups {
		if u.UpdateID >= b.offset {
			b.offset = u.UpdateID + 1
			advanced = true
		}
	}
	// 在处理任何更新之前先落盘：即便处理过程中进程被重启
	//（典型：自升级），这批更新也不会被 Telegram 重投。
	if advanced {
		_ = os.MkdirAll(b.state, 0o750)
		_ = os.WriteFile(b.statePath(offsetFile), []byte(strconv.FormatInt(b.offset, 10)+"\n"), 0o640)
	}
	return ups, nil
}

// ---------- 屏幕与消息 ----------

// view 描述一屏内容。
type view struct {
	chatID int64
	// msgID 非 0 时就地编辑该消息，否则新发一条
	msgID int64
	// cb 非空表示由按钮触发，可用轻提示反馈
	cb *callback
}

type callback struct {
	id   string
	once sync.Once
}

// ackGrace 之后仍未给出轻提示，就先应答掉按钮的转圈状态，长操作不让按钮一直转。
const ackGrace = 1200 * time.Millisecond

// ack 应答按钮点击；每次点击只有第一次应答生效。text 为空时只收起转圈。
func (b *Bot) ack(ctx context.Context, v view, text string, alert bool) {
	if v.cb == nil {
		return
	}
	v.cb.once.Do(func() {
		p := url.Values{}
		p.Set("callback_query_id", v.cb.id)
		if text != "" {
			p.Set("text", truncateText(text, 190))
		}
		if alert {
			p.Set("show_alert", "true")
		}
		_, _ = b.api(ctx, "answerCallbackQuery", p)
	})
}

// fail 报告一次操作失败：按钮触发时弹窗、屏幕保持不变；文字输入触发时
// 屏幕换成错误说明并给出返回入口。
func (b *Bot) fail(ctx context.Context, v view, title string, err error, back string) {
	if v.cb != nil {
		b.ack(ctx, v, title+"："+err.Error(), true)
		return
	}
	b.render(ctx, v, errBox(title, err), backTo(back))
}

// render 渲染一屏：能编辑就编辑，否则新发；并把它设为该会话唯一的屏幕。
func (b *Bot) render(ctx context.Context, v view, text, keyboard string) int64 {
	id := b.withDegrade(keyboard, func(kb string) int64 { return b.renderOnce(ctx, v, text, kb) })
	if id != 0 {
		b.setScreen(ctx, v.chatID, id)
	}
	return id
}

// withDegrade 按当前降级级别发送；失败且键盘里还有可降级的字段时逐级降级重试。
// 按钮图标要求 Bot 主人有 Premium，配色要求较新的 Bot API。
func (b *Bot) withDegrade(keyboard string, send func(string) int64) int64 {
	b.mu.Lock()
	if b.degrade > 0 && time.Since(b.degradeAt) > time.Hour {
		b.degrade = 0
	}
	level := b.degrade
	b.mu.Unlock()
	for ; level <= len(buttonExtras); level++ {
		kb := stripButtonExtras(keyboard, buttonExtras[:level]...)
		if id := send(kb); id != 0 {
			b.mu.Lock()
			if level > b.degrade {
				b.degrade, b.degradeAt = level, time.Now()
				log.Printf("Bot 按钮不支持 %v，已降级", buttonExtras[:level])
			}
			b.mu.Unlock()
			return id
		}
		if !hasButtonExtras(kb) {
			break
		}
	}
	return 0
}

func (b *Bot) renderOnce(ctx context.Context, v view, text, keyboard string) int64 {
	if v.msgID != 0 {
		p := url.Values{}
		p.Set("chat_id", strconv.FormatInt(v.chatID, 10))
		p.Set("message_id", strconv.FormatInt(v.msgID, 10))
		p.Set("text", text)
		p.Set("parse_mode", "HTML")
		p.Set("disable_web_page_preview", "true")
		if keyboard != "" {
			p.Set("reply_markup", keyboard)
		}
		if _, err := b.api(ctx, "editMessageText", p); err == nil {
			return v.msgID
		} else if strings.Contains(err.Error(), "message is not modified") {
			// 内容未变不是失败：消息本来就处于目标状态。若在这里退回
			// 新发，会克隆出一条永远没人再编辑的僵尸消息（升级进度页
			// 实测踩坑：初始渲染与第一个阶段回调文本相同，重复发送后
			// 旧消息永远停在「下载中」）。
			return v.msgID
		}
		// 其它编辑失败（消息过旧、被删除等）时退回新发，不让用户卡住
	}
	return b.send(ctx, v.chatID, text, keyboard)
}

// setScreen 把 id 记为当前屏幕，并删掉上一屏。
func (b *Bot) setScreen(ctx context.Context, chatID, id int64) {
	b.mu.Lock()
	old := b.screens[chatID]
	changed := old != id
	if changed {
		b.screens[chatID] = id
	}
	snapshot, _ := json.Marshal(b.screens)
	b.mu.Unlock()
	if !changed {
		return
	}
	if old != 0 {
		b.deleteMessage(ctx, chatID, old)
	}
	_ = os.WriteFile(b.statePath(screensFile), snapshot, 0o640)
}

// dropMessage 删除一条消息；若它正是当前屏幕，同时清掉记录。
func (b *Bot) dropMessage(ctx context.Context, chatID, id int64) {
	b.mu.Lock()
	if b.screens[chatID] == id {
		delete(b.screens, chatID)
	}
	b.mu.Unlock()
	b.deleteMessage(ctx, chatID, id)
}

// deleteMessage 尽力删除消息；失败（过旧、已删）静默忽略。
func (b *Bot) deleteMessage(ctx context.Context, chatID, msgID int64) {
	p := url.Values{}
	p.Set("chat_id", strconv.FormatInt(chatID, 10))
	p.Set("message_id", strconv.FormatInt(msgID, 10))
	_, _ = b.api(ctx, "deleteMessage", p)
}

// sendEphemeral 发送一条定时自毁的瞬态消息（提示、确认类）。
func (b *Bot) sendEphemeral(ctx context.Context, chatID int64, text string, ttl time.Duration) {
	id := b.send(ctx, chatID, text, "")
	if id == 0 {
		return
	}
	time.AfterFunc(ttl, func() {
		dctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		b.deleteMessage(dctx, chatID, id)
	})
}

// send 新发一条消息，返回消息 ID。
func (b *Bot) send(ctx context.Context, chatID int64, text, keyboard string) int64 {
	p := url.Values{}
	p.Set("chat_id", strconv.FormatInt(chatID, 10))
	p.Set("text", text)
	p.Set("parse_mode", "HTML")
	p.Set("disable_web_page_preview", "true")
	if keyboard != "" {
		p.Set("reply_markup", keyboard)
	}
	raw, err := b.api(ctx, "sendMessage", p)
	if err != nil {
		log.Printf("Bot 发送失败: %v", err)
		return 0
	}
	var r struct {
		MessageID int64 `json:"message_id"`
	}
	_ = json.Unmarshal(raw, &r)
	return r.MessageID
}

// EditMessage 编辑指定消息（供升级结果等跨进程场景使用）。
func (b *Bot) EditMessage(ctx context.Context, chatID, msgID int64, text, keyboard string) {
	b.render(ctx, view{chatID: chatID, msgID: msgID}, text, keyboard)
}

// Notify 主动推送给所有管理员，附「知道了」按钮。
//
// 若全部投递失败（常见于 Bot 刚创建、用户尚未 /start），
// 标记待补发，等用户首次交互时再送出。
func (b *Bot) Notify(ctx context.Context, text string) {
	b.notify(ctx, text, inlineKeyboard([]btn{dismissBtn()}))
}

// NotifyAction 推送通知并附一个入口按钮：点击后该通知就地变成对应页面。
func (b *Bot) NotifyAction(ctx context.Context, text, label, cmd, iconName string) {
	b.notify(ctx, text, inlineKeyboard([]btn{{Text: label, Data: cmd, Icon: iconName}, dismissBtn()}))
}

func (b *Bot) notify(ctx context.Context, text, keyboard string) {
	delivered := false
	for _, id := range b.Admins {
		if b.withDegrade(keyboard, func(kb string) int64 { return b.send(ctx, id, text, kb) }) != 0 {
			delivered = true
		}
	}
	if !delivered {
		b.mu.Lock()
		b.pendingGreet = true
		b.mu.Unlock()
		log.Printf("Bot 启动通知未送达（管理员可能尚未与 Bot 对话），将在首次交互时补发")
	}
}

// ---------- 交互 ----------

func (b *Bot) isAdmin(id int64) bool {
	for _, a := range b.Admins {
		if subtle.ConstantTimeCompare(
			[]byte(strconv.FormatInt(a, 10)),
			[]byte(strconv.FormatInt(id, 10))) == 1 {
			return true
		}
	}
	return false
}

func (b *Bot) handle(ctx context.Context, u update) {
	switch {
	case u.CallbackQuery != nil:
		q := u.CallbackQuery
		if !b.isAdmin(q.From.ID) || q.Message == nil {
			return
		}
		v := view{chatID: q.Message.Chat.ID, msgID: q.Message.MessageID, cb: &callback{id: q.ID}}
		// 点了别的按钮就不再等待之前的输入；需要输入的页面会重新登记。
		b.mu.Lock()
		delete(b.pending, v.chatID)
		delete(b.promptMsg, v.chatID)
		b.mu.Unlock()
		t := time.AfterFunc(ackGrace, func() {
			actx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			b.ack(actx, v, "", false)
		})
		b.dispatch(ctx, v, q.Data)
		t.Stop()
		b.ack(ctx, v, "", false)

	case u.Message != nil:
		m := u.Message
		if !b.isAdmin(m.From.ID) {
			return // 静默忽略陌生人
		}
		text := strings.TrimSpace(m.Text)
		if text == "" {
			return
		}
		// 命令只是导航，输入可能含节点凭据：读取后都不留在聊天里。
		b.deleteMessage(ctx, m.Chat.ID, m.MessageID)
		b.maybeGreet(ctx, m.Chat.ID)

		// 等待输入状态优先
		b.mu.Lock()
		action, waiting := b.pending[m.Chat.ID]
		promptID := b.promptMsg[m.Chat.ID]
		if waiting {
			delete(b.pending, m.Chat.ID)
			delete(b.promptMsg, m.Chat.ID)
		}
		b.mu.Unlock()

		if waiting && !strings.HasPrefix(text, "/") {
			b.handleInput(ctx, view{chatID: m.Chat.ID, msgID: promptID}, action, text)
			return
		}
		// 用户主动发命令：在底部新开一屏，旧屏随之删除
		b.dispatch(ctx, view{chatID: m.Chat.ID}, commandOf(text))
	}
}

// commandOf 把 "/probe@MyBot youtube.com" 规整为 "probe youtube.com"。
func commandOf(text string) string {
	cmd, arg, _ := strings.Cut(strings.TrimPrefix(text, "/"), " ")
	cmd, _, _ = strings.Cut(cmd, "@")
	if arg = strings.TrimSpace(arg); arg != "" {
		return cmd + " " + arg
	}
	return cmd
}

// maybeGreet 在首次交互时补发启动通知。
//
// Bot 刚创建时用户往往还没 /start，此时服务端无法主动发消息
// （Telegram 限制：Bot 不能向未开启会话的用户发起对话）。
func (b *Bot) maybeGreet(ctx context.Context, chatID int64) {
	b.mu.Lock()
	need := b.pendingGreet && !b.greeted[chatID]
	if need {
		b.greeted[chatID] = true
	}
	b.mu.Unlock()
	if !need {
		return
	}
	// 瞬态提示：60 秒后自毁，不在聊天里留痕。
	b.sendEphemeral(ctx, chatID, fmt.Sprintf(
		"%s <b>5gpn-NEXT 已就绪</b>　<code>%s</code>", ic("ok"), esc(b.Version)), 60*time.Second)
}

func (b *Bot) dispatch(ctx context.Context, v view, cmd string) {
	verb, arg, _ := strings.Cut(cmd, ":")
	switch verb {
	case "start", "menu":
		b.showMenu(ctx, v)
	case "dismiss":
		b.dropMessage(ctx, v.chatID, v.msgID)
	case "cancel":
		b.mu.Lock()
		delete(b.pending, v.chatID)
		delete(b.promptMsg, v.chatID)
		b.mu.Unlock()
		b.dispatch(ctx, v, orDefault(arg, "menu"))

	// 状态
	case "status":
		b.showStatus(ctx, v, "")
	case "refresh":
		b.ack(ctx, v, "已刷新", false)
		b.dispatch(ctx, v, arg)
	case "traffic":
		b.showTraffic(ctx, v)
	case "health":
		b.showHealth(ctx, v)
	case "health_detail":
		b.showHealthDetail(ctx, v, arg)
	case "monitor_settings":
		b.showMonitorSettings(ctx, v)
	case "monitor_toggle_alerts":
		_, _, disabled := b.Manager.MonitorSettings()
		on := !disabled
		if err := b.Manager.SetMonitorAlerts(0, 0, &on); err != nil {
			b.fail(ctx, v, "设置失败", err, "monitor_settings")
			return
		}
		b.ack(ctx, v, "告警推送已"+onOff(disabled), false)
		b.showMonitorSettings(ctx, v)
	case "ask_monitor_after", "ask_monitor_cooldown", "ask_ad_allow", "ask_update_interval":
		b.askFor(ctx, v, strings.TrimPrefix(verb, "ask_"), "")

	// 出口
	case "egress":
		b.showEgress(ctx, v)
	case "egress_info":
		b.showEgressInfo(ctx, v, arg, "")
	case "switch":
		b.doSwitchEgress(ctx, v, arg)
	case "test_egress":
		b.doTestEgress(ctx, v, arg)
	case "rename_egress":
		b.ask(ctx, v, "egress_rename|"+arg, head("egress", "重命名出口")+
			"发送新的显示名称，支持中文与 emoji，24 个字符以内。", "egress_info:"+arg)
	case "del_egress_ask":
		b.showEgressInfo(ctx, v, arg, "confirm_delete")
	case "del_egress":
		if err := b.Manager.RemoveEgress(arg); err != nil {
			b.fail(ctx, v, "删除失败", err, "egress")
			return
		}
		b.ack(ctx, v, "已删除出口", false)
		b.showEgress(ctx, v)
	case "ask_egress_add":
		b.ask(ctx, v, "egress_add_name", head("egress", "添加出口", "1 / 2")+
			"给出口起个名字，例如 <code>东京家宽</code>。\n"+
			"<i>直接粘贴节点链接可跳过命名，使用节点自带的备注名。</i>", "egress")

	// 分流
	case "rules":
		b.showRules(ctx, v)
	case "rules_builtin":
		b.showBuiltinRules(ctx, v)
	case "ask_rule_add":
		b.askRuleAdd(ctx, v, "")
	case "rule_del_menu":
		b.showRuleDelMenu(ctx, v)
	case "rule_del_ask":
		b.askRuleDelete(ctx, v, arg)
	case "rule_del_do":
		b.doRuleDelete(ctx, v, arg)
	case "apps":
		b.showApps(ctx, v)
	case "app":
		b.showApp(ctx, v, arg, "")
	case "app_set":
		b.doSetApp(ctx, v, arg)
	case "app_check":
		b.showAppCheck(ctx, v, arg)

	// 广告拦截
	case "adblock":
		b.showAdBlock(ctx, v)
	case "adblock_on":
		b.doAdBlockToggle(ctx, v, true)
	case "adblock_off":
		b.doAdBlockToggle(ctx, v, false)
	case "ad_allow_hit":
		b.doAdAllowHit(ctx, v, arg)
	case "ad_allow_list":
		b.showAdAllowlist(ctx, v)
	case "ad_allow_del":
		idx, _ := strconv.Atoi(arg)
		if err := b.Manager.RemoveAdAllow(idx); err != nil {
			b.fail(ctx, v, "移除失败", err, "ad_allow_list")
			return
		}
		b.ack(ctx, v, "已移出白名单", false)
		b.showAdAllowlist(ctx, v)

	// 诊断
	case "probe", "ask_probe":
		b.askProbe(ctx, v)
	case "probe_go":
		b.doProbe(ctx, v, arg)

	// 接入
	case "client", "panel", "android_guide":
		b.showClient(ctx, v)
	case "ios_dns_profile":
		b.sendDNSProfile(ctx, v)

	// 版本
	case "update":
		b.showUpdate(ctx, v)
	case "update_check":
		b.doUpdateCheck(ctx, v)
	case "update_settings", "update_backups":
		b.showUpdateSettings(ctx, v)
	case "update_ignore":
		if err := b.Manager.IgnoreVersion(arg); err != nil {
			b.fail(ctx, v, "忽略失败", err, "update")
			return
		}
		b.ack(ctx, v, "已忽略 "+arg, false)
		b.showUpdate(ctx, v)
	case "update_clear_ignored":
		for _, t := range b.Manager.IgnoredVersions() {
			_ = b.Manager.UnignoreVersion(t)
		}
		b.ack(ctx, v, "已清空忽略列表", false)
		b.showUpdateSettings(ctx, v)
	case "update_toggle_auto":
		_, cur, _ := b.Manager.UpdateSettings()
		if err := b.Manager.SetUpdateAutoApply(!cur); err != nil {
			b.fail(ctx, v, "设置失败", err, "update_settings")
			return
		}
		b.ack(ctx, v, "自动安装已"+onOff(!cur), false)
		b.showUpdateSettings(ctx, v)
	case "update_apply":
		b.doUpdateApply(ctx, v, arg)
	case "update_rollback":
		b.showRollback(ctx, v)
	case "rollback":
		b.doRollback(ctx, v, arg)
	case "update_history":
		b.showUpdateHistory(ctx, v)

	default:
		// "/probe youtube.com" 这类带参数的命令
		if c, target, ok := strings.Cut(cmd, " "); ok && c == "probe" {
			b.doProbe(ctx, v, target)
			return
		}
		b.showMenu(ctx, v)
	}
}

func orDefault(s, def string) string {
	if s == "" {
		return def
	}
	return s
}

// ask 把屏幕换成输入提示，等待用户发送文字。errNote 非空时在提示下方
// 显示上一次输入的问题，继续等待重新输入。
func (b *Bot) ask(ctx context.Context, v view, action, prompt, back string, errNote ...string) {
	text := prompt
	if len(errNote) > 0 && errNote[0] != "" {
		text += "\n" + ic("warn") + " " + errNote[0]
	}
	id := b.render(ctx, v, text, inlineKeyboard([]btn{{Text: "取消", Data: "cancel:" + orDefault(back, "menu")}}))
	b.mu.Lock()
	b.pending[v.chatID] = action
	b.promptMsg[v.chatID] = id
	b.mu.Unlock()
}

// prompts 是简单输入项的提示文案与取消后返回的页面。
var prompts = map[string]struct{ icon, title, body, back string }{
	"monitor_after": {"alert", "连续失败阈值",
		"出口连续几次探测失败才告警？发送 1-60 的整数。\n<i>每 60 秒探测一次，3 表示约 3 分钟无响应才提醒。</i>",
		"monitor_settings"},
	"monitor_cooldown": {"mute", "告警冷却",
		"同一出口两次告警至少间隔几分钟？发送 1-1440 的整数。", "monitor_settings"},
	"ad_allow": {"shield", "加入白名单",
		"某个 App 被误拦（白屏、加载不出来）时，发送它的域名，例如 <code>example.com</code>。\n<i>连同子域名一起放行。</i>",
		"ad_allow_list"},
	"update_interval": {"settings", "检查间隔",
		"发送 1-168 的小时数，例如 <code>1</code> 或 <code>6</code>。\n<i>下次重启起完全生效。</i>", "update_settings"},
}

func (b *Bot) askFor(ctx context.Context, v view, action, errNote string) {
	p := prompts[action]
	b.ask(ctx, v, action, head(p.icon, p.title)+p.body, p.back, errNote)
}

func (b *Bot) handleInput(ctx context.Context, v view, action, text string) {
	text = strings.TrimSpace(text)
	// 带参数的动作：动作串以 | 携带上一步输入。
	if name, ok := strings.CutPrefix(action, "egress_add_link|"); ok {
		b.doEgressAdd(ctx, v, name, text)
		return
	}
	if name, ok := strings.CutPrefix(action, "egress_rename|"); ok {
		if err := b.Manager.RenameEgress(name, text); err != nil {
			b.ask(ctx, v, action, head("egress", "重命名出口")+"发送新的显示名称。", "egress_info:"+name, esc(err.Error()))
			return
		}
		b.showEgressInfo(ctx, v, name, "renamed")
		return
	}
	switch action {
	case "egress_add_name":
		if strings.Contains(text, "://") {
			// 用户直接给了链接：跳过命名，走节点备注名。
			b.doEgressAdd(ctx, v, "", text)
			return
		}
		if len([]rune(text)) > 24 {
			b.ask(ctx, v, action, head("egress", "添加出口", "1 / 2")+"给出口起个名字。", "egress", "名称请控制在 24 个字符以内")
			return
		}
		b.ask(ctx, v, "egress_add_link|"+text, head("egress", "添加出口", "2 / 2")+
			fmt.Sprintf("名称　<b>%s</b>\n\n粘贴节点分享链接。\n", esc(text))+
			"<i>支持 ss · vless · vmess · trojan · hysteria2 · tuic · socks5 · http</i>", "egress")

	case "rule_add":
		if err := b.Manager.AddRule(text); err != nil {
			b.askRuleAdd(ctx, v, err.Error())
			return
		}
		b.showRules(ctx, v)

	case "ad_allow":
		if err := b.Manager.AllowAd(text); err != nil {
			b.askFor(ctx, v, action, esc(err.Error()))
			return
		}
		b.showAdAllowlist(ctx, v)

	case "update_interval":
		hours, err := strconv.Atoi(text)
		if err == nil {
			err = b.Manager.SetUpdateInterval(hours)
		}
		if err != nil {
			b.askFor(ctx, v, action, "请输入 1-168 的整数")
			return
		}
		b.showUpdateSettings(ctx, v)

	case "monitor_after", "monitor_cooldown":
		n, err := strconv.Atoi(text)
		if err == nil {
			if action == "monitor_after" {
				err = b.Manager.SetMonitorAlerts(n, 0, nil)
			} else {
				err = b.Manager.SetMonitorAlerts(0, n, nil)
			}
		}
		if err != nil {
			b.askFor(ctx, v, action, "请输入范围内的整数")
			return
		}
		b.showMonitorSettings(ctx, v)

	case "probe":
		b.doProbe(ctx, v, text)
	}
}

// ---------- 文件 ----------

// sendFile 上传文件或图片，返回消息 ID。
func (b *Bot) sendFile(ctx context.Context, method, field string, chatID int64, filename string, data []byte, caption string) (int64, error) {
	var buf bytes.Buffer
	mw := multipart.NewWriter(&buf)
	_ = mw.WriteField("chat_id", strconv.FormatInt(chatID, 10))
	_ = mw.WriteField("caption", caption)
	_ = mw.WriteField("parse_mode", "HTML")
	fw, err := mw.CreateFormFile(field, filename)
	if err != nil {
		return 0, err
	}
	if _, err := fw.Write(data); err != nil {
		return 0, err
	}
	if err := mw.Close(); err != nil {
		return 0, err
	}

	endpoint := fmt.Sprintf("%s/bot%s/%s", b.apiBase, b.Token, method)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, &buf)
	if err != nil {
		return 0, err
	}
	req.Header.Set("Content-Type", mw.FormDataContentType())
	resp, err := b.client.Do(req)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	var r struct {
		OK          bool   `json:"ok"`
		Description string `json:"description"`
		Result      struct {
			MessageID int64 `json:"message_id"`
		} `json:"result"`
	}
	_ = json.Unmarshal(body, &r)
	if !r.OK {
		return 0, fmt.Errorf("telegram: %s", r.Description)
	}
	return r.Result.MessageID, nil
}
