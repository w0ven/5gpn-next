package bot

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/w0ven/5gpn-next/internal/config"
	"github.com/w0ven/5gpn-next/internal/egress"
	"github.com/w0ven/5gpn-next/internal/manage"
	"github.com/w0ven/5gpn-next/internal/policy"
	"github.com/w0ven/5gpn-next/internal/stats"
)

const admin = 42

type tgCall struct {
	method string
	p      url.Values
}

func (c tgCall) id() int64 {
	n, _ := strconv.ParseInt(c.p.Get("message_id"), 10, 64)
	return n
}

// fakeTG 记录 Bot 发出的每个 API 调用，并像 Telegram 一样为新消息分配 ID。
type fakeTG struct {
	mu          sync.Mutex
	calls       []tgCall
	next        int64
	rejectIcons bool
}

func (f *fakeTG) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	_ = r.ParseMultipartForm(1 << 20)
	_ = r.ParseForm()
	method := r.URL.Path[strings.LastIndex(r.URL.Path, "/")+1:]
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, tgCall{method, r.Form})
	if f.rejectIcons && strings.Contains(r.Form.Get("reply_markup"), "icon_custom_emoji_id") {
		fmt.Fprint(w, `{"ok":false,"description":"Bad Request: custom emoji icons require Premium"}`)
		return
	}
	switch method {
	case "sendMessage", "sendPhoto", "sendDocument":
		f.next++
		fmt.Fprintf(w, `{"ok":true,"result":{"message_id":%d}}`, f.next)
	default:
		fmt.Fprint(w, `{"ok":true,"result":true}`)
	}
}

// take 返回并清空已记录的调用。
func (f *fakeTG) take() []tgCall {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := f.calls
	f.calls = nil
	return out
}

func newTestBot(t *testing.T) (*Bot, *fakeTG, *manage.Manager) {
	t.Helper()
	dir := t.TempDir()
	cfg := config.Default()
	path := filepath.Join(dir, "config.json")
	if err := cfg.Save(path); err != nil {
		t.Fatal(err)
	}
	mgr := manage.New(path, cfg, policy.New(), egress.NewRegistry())
	mgr.Traffic = stats.New(filepath.Join(dir, "traffic.json"))

	tg := &fakeTG{next: 100}
	srv := httptest.NewServer(tg)
	t.Cleanup(srv.Close)

	b := New("TOKEN", []int64{admin}, mgr, "v-test")
	b.apiBase, b.state = srv.URL, dir
	b.screens = map[int64]int64{}
	b.PanelURL = "https://gw.example:443/"
	return b, tg, mgr
}

func message(id int64, from int64, text string) update {
	var u update
	raw := fmt.Sprintf(`{"update_id":1,"message":{"message_id":%d,"from":{"id":%d},"chat":{"id":%d},"text":%q}}`, id, from, from, text)
	_ = json.Unmarshal([]byte(raw), &u)
	return u
}

func press(msgID int64, data string) update {
	var u update
	raw := fmt.Sprintf(`{"update_id":1,"callback_query":{"id":"cb","from":{"id":%d},"message":{"message_id":%d,"chat":{"id":%d}},"data":%q}}`, admin, msgID, admin, data)
	_ = json.Unmarshal([]byte(raw), &u)
	return u
}

func methods(calls []tgCall) string {
	var s []string
	for _, c := range calls {
		if c.method == "deleteMessage" || c.method == "editMessageText" {
			s = append(s, fmt.Sprintf("%s:%d", c.method, c.id()))
		} else {
			s = append(s, c.method)
		}
	}
	return strings.Join(s, " ")
}

func TestCommandDeletesInputAndReplacesScreen(t *testing.T) {
	b, tg, _ := newTestBot(t)
	b.screens[admin] = 50
	b.handle(context.Background(), message(7, admin, "/start"))

	// 先删用户的命令，再发新屏，最后收起旧屏。
	if got := methods(tg.take()); got != "deleteMessage:7 sendMessage deleteMessage:50" {
		t.Fatalf("调用序列 = %s", got)
	}
	if b.screens[admin] != 101 {
		t.Fatalf("当前屏幕应为新消息 101，实际 %d", b.screens[admin])
	}
	raw, _ := os.ReadFile(filepath.Join(b.state, screensFile))
	if !strings.Contains(string(raw), `"42":101`) {
		t.Fatalf("屏幕记录未落盘: %s", raw)
	}
}

func TestButtonEditsInPlace(t *testing.T) {
	b, tg, _ := newTestBot(t)
	b.screens[admin] = 50
	b.handle(context.Background(), press(50, "status"))
	if got := methods(tg.take()); got != "editMessageText:50 answerCallbackQuery" {
		t.Fatalf("按钮导航应只就地编辑并应答一次，实际 %s", got)
	}
}

func TestStrangerIsIgnored(t *testing.T) {
	b, tg, _ := newTestBot(t)
	b.handle(context.Background(), message(7, 999, "/start"))
	var u update
	_ = json.Unmarshal([]byte(`{"update_id":1,"callback_query":{"id":"cb","from":{"id":999},"message":{"message_id":5,"chat":{"id":999}},"data":"menu"}}`), &u)
	b.handle(context.Background(), u)
	if calls := tg.take(); len(calls) != 0 {
		t.Fatalf("陌生人不应触发任何调用: %s", methods(calls))
	}
}

func TestNotificationDismissAndOpen(t *testing.T) {
	b, tg, _ := newTestBot(t)
	ctx := context.Background()
	b.screens[admin] = 50

	b.Notify(ctx, "✅ <b>网关证书已续期</b>")
	calls := tg.take()
	if len(calls) != 1 || !strings.Contains(calls[0].p.Get("reply_markup"), `"callback_data":"dismiss"`) {
		t.Fatalf("通知应带「知道了」按钮: %+v", calls)
	}
	b.handle(ctx, press(101, "dismiss"))
	if got := methods(tg.take()); got != "deleteMessage:101 answerCallbackQuery" {
		t.Fatalf("「知道了」应删除通知本身: %s", got)
	}
	if b.screens[admin] != 50 {
		t.Fatal("关闭通知不应影响当前屏幕")
	}

	b.NotifyAction(ctx, "🔔 <b>发现新版本</b>", "查看并升级", "update", "update")
	tg.take()
	b.handle(ctx, press(102, "update"))
	if got := methods(tg.take()); got != "editMessageText:102 deleteMessage:50 answerCallbackQuery" {
		t.Fatalf("点通知里的入口，通知应就地变成新屏幕并收起旧屏: %s", got)
	}
	if b.screens[admin] != 102 {
		t.Fatalf("当前屏幕应为 102，实际 %d", b.screens[admin])
	}
}

func TestInputPromptRetriesInPlace(t *testing.T) {
	b, tg, mgr := newTestBot(t)
	ctx := context.Background()
	b.screens[admin] = 50

	b.handle(ctx, press(50, "ask_update_interval"))
	tg.take()

	b.handle(ctx, message(8, admin, "abc"))
	calls := tg.take()
	if got := methods(calls); got != "deleteMessage:8 editMessageText:50" {
		t.Fatalf("输错后应删掉输入并在原屏提示: %s", got)
	}
	if !strings.Contains(calls[1].p.Get("text"), "请输入 1-168 的整数") {
		t.Fatalf("缺少错误提示: %s", calls[1].p.Get("text"))
	}

	b.handle(ctx, message(9, admin, "6"))
	if got := methods(tg.take()); got != "deleteMessage:9 editMessageText:50" {
		t.Fatalf("重新输入应仍在原屏完成: %s", got)
	}
	if _, _, iv := mgr.UpdateSettings(); iv != 6 {
		t.Fatalf("间隔未保存，实际 %d", iv)
	}
}

func TestButtonCancelsPendingInput(t *testing.T) {
	b, tg, mgr := newTestBot(t)
	ctx := context.Background()
	b.screens[admin] = 50
	_, _, before := mgr.UpdateSettings()

	b.handle(ctx, press(50, "ask_update_interval"))
	b.handle(ctx, press(50, "menu"))
	tg.take()
	b.handle(ctx, message(8, admin, "6"))
	if _, _, iv := mgr.UpdateSettings(); iv != before {
		t.Fatalf("离开输入页后的文字不应再当作输入，间隔被改成 %d", iv)
	}
}

func TestButtonsDegradeWithoutPremium(t *testing.T) {
	b, tg, _ := newTestBot(t)
	tg.rejectIcons = true
	ctx := context.Background()
	kb := inlineKeyboard([]btn{{Text: "升级", Data: "update", Icon: "update", Style: "primary"}})

	if id := b.render(ctx, view{chatID: admin}, "x", kb); id == 0 {
		t.Fatal("去掉图标后应发送成功")
	}
	calls := tg.take()
	last := calls[len(calls)-1].p.Get("reply_markup")
	if len(calls) != 2 || strings.Contains(last, "icon_custom_emoji_id") || !strings.Contains(last, `"style":"primary"`) {
		t.Fatalf("应只去掉图标、保留配色: %s / %s", methods(calls), last)
	}

	b.render(ctx, view{chatID: admin}, "y", kb)
	if calls := tg.take(); methods(calls) != "sendMessage deleteMessage:101" {
		t.Fatalf("降级后不应再试探带图标的键盘: %s", methods(calls))
	}
}

// 每个页面都必须是合法的 Telegram HTML、长度在上限内、回调数据不超过 64 字节，
// 且总能回到主页或取消。任何一项不满足，Telegram 都会拒绝整条消息或让用户困在页面里。
func TestScreensAreWellFormed(t *testing.T) {
	b, tg, _ := newTestBot(t)
	ctx := context.Background()
	b.screens[admin] = 50
	for _, cmd := range []string{
		"menu", "status", "traffic", "health", "monitor_settings",
		"egress", "egress_info:DIRECT", "del_egress_ask:DIRECT", "ask_egress_add",
		"rules", "rules_builtin", "ask_rule_add", "rule_del_menu",
		"apps", "app:youtube", "app:claude",
		"adblock", "ad_allow_list", "ask_ad_allow",
		"probe", "client", "update", "update_settings", "update_history",
		"ask_update_interval", "ask_monitor_after", "rename_egress:DIRECT",
	} {
		b.handle(ctx, press(50, cmd))
		var edit *tgCall
		for _, c := range tg.take() {
			if c.method == "editMessageText" {
				c := c
				edit = &c
			}
		}
		if edit == nil {
			t.Errorf("%s: 没有渲染页面", cmd)
			continue
		}
		text, kb := edit.p.Get("text"), edit.p.Get("reply_markup")
		t.Run(cmd, func(t *testing.T) {
			assertTelegramHTML(t, text)
			if n := utf8.RuneCountInString(text); n > 4096 {
				t.Errorf("文本 %d 字符，超过 Telegram 上限", n)
			}
			var parsed struct {
				Rows [][]struct {
					Data string `json:"callback_data"`
					URL  string `json:"url"`
				} `json:"inline_keyboard"`
			}
			if err := json.Unmarshal([]byte(kb), &parsed); err != nil {
				t.Fatalf("键盘不是合法 JSON: %v", err)
			}
			exit := false
			for _, row := range parsed.Rows {
				for _, btn := range row {
					if len(btn.Data) > 64 {
						t.Errorf("callback_data 超过 64 字节: %s", btn.Data)
					}
					if btn.Data == "menu" || strings.HasPrefix(btn.Data, "cancel:") || btn.Data == "egress_info:DIRECT" {
						exit = true
					}
				}
			}
			if cmd != "menu" && !exit {
				t.Errorf("页面没有返回或取消入口: %s", kb)
			}
		})
	}
}

func TestRuleExampleUsesFullEgressName(t *testing.T) {
	b, tg, mgr := newTestBot(t)
	mgr.Cfg.Egress = append(mgr.Cfg.Egress, config.EgressConfig{Name: "ctc", Type: "socks5"})
	b.screens[admin] = 50
	b.handle(context.Background(), press(50, "ask_rule_add"))
	for _, c := range tg.take() {
		if c.method == "editMessageText" && !strings.Contains(c.p.Get("text"), "proxy:ctc</code>") {
			t.Fatalf("示例中的出口名不完整: %s", c.p.Get("text"))
		}
	}
}

func TestAppCheckScreen(t *testing.T) {
	b, tg, mgr := newTestBot(t)
	logPath := filepath.Join(b.state, "trace.jsonl")
	line := `{"ts":"` + time.Now().Add(-time.Hour).UTC().Format(time.RFC3339Nano) +
		`","target":"www.youtube.com:443","steps":[{"stage":"policy","status":"ok","detail":"FINAL → 代理:<nuross>"},{"stage":"egress","status":"ok","detail":"nuross"}]}`
	if err := os.WriteFile(logPath, []byte(line+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	mgr.Cfg.LogPath = logPath
	mgr.Cfg.Egress = append(mgr.Cfg.Egress, config.EgressConfig{Name: "ctc", Type: "socks5", DisplayName: "🇭🇰CTC"})
	mgr.Cfg.Apps = map[string]string{"youtube": "ctc"}
	mgr.Cfg.AppsChanged = map[string]int64{"youtube": time.Now().Add(-10 * time.Minute).Unix()}
	b.screens[admin] = 50

	b.handle(context.Background(), press(50, "app_check:youtube"))
	var text string
	for _, c := range tg.take() {
		if c.method == "editMessageText" {
			text = c.p.Get("text")
		}
	}
	assertTelegramHTML(t, text)
	for _, want := range []string{"按当前规则", "实际连接", "改出口后 10 分钟", "还没有 YouTube 的连接", "<code>www.youtube.com</code>"} {
		if !strings.Contains(text, want) {
			t.Errorf("核对页缺少 %q:\n%s", want, text)
		}
	}
}
