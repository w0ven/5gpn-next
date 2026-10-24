package bot

import (
	"strings"
	"testing"
	"time"

	"github.com/w0ven/5gpn-next/internal/manage"
	"github.com/w0ven/5gpn-next/internal/monitor"
)

// telegramTags 是 Telegram HTML parse_mode 支持的标签集合。
var telegramTags = map[string]bool{
	"b": true, "strong": true, "i": true, "em": true, "u": true, "ins": true,
	"s": true, "strike": true, "del": true, "span": true, "tg-spoiler": true,
	"a": true, "code": true, "pre": true, "blockquote": true, "tg-emoji": true,
}

// assertTelegramHTML 校验文本能被 Telegram 的 HTML parse_mode 接受。
//
// 存在理由：Bot 一律用 parse_mode=HTML 发送。文本里出现裸 `<`（比如
// "<0.1ms"）时 Telegram 直接返回 400，整条消息发不出去，用户看到的
// 现象是「点了按钮没反应 / 页面进不去」——完全没有错误提示。
func assertTelegramHTML(t *testing.T, s string) {
	t.Helper()
	var stack []string
	for i := 0; i < len(s); i++ {
		if s[i] != '<' {
			continue
		}
		end := strings.IndexByte(s[i:], '>')
		if end < 0 {
			t.Fatalf("裸 `<` 未闭合（Telegram 会返回 400）: %q", snippet(s, i))
		}
		inner := s[i+1 : i+end]
		closing := strings.HasPrefix(inner, "/")
		name := strings.TrimPrefix(inner, "/")
		if j := strings.IndexAny(name, " \t"); j >= 0 {
			name = name[:j]
		}
		if name == "" || !telegramTags[strings.ToLower(name)] {
			t.Fatalf("非法标签 %q（Telegram 会返回 400，整条消息发不出去）: %q",
				inner, snippet(s, i))
		}
		if closing {
			if len(stack) == 0 || stack[len(stack)-1] != strings.ToLower(name) {
				t.Fatalf("标签闭合不匹配 </%s>: %q", name, snippet(s, i))
			}
			stack = stack[:len(stack)-1]
		} else {
			stack = append(stack, strings.ToLower(name))
		}
		i += end
	}
	if len(stack) > 0 {
		t.Fatalf("标签未闭合: %v", stack)
	}
}

func snippet(s string, i int) string {
	lo := i - 30
	if lo < 0 {
		lo = 0
	}
	hi := i + 30
	if hi > len(s) {
		hi = len(s)
	}
	return s[lo:hi]
}

// 亚毫秒耗时曾被格式化成 "<0.1ms"，直接让健康监控整页发不出去。
func TestEgressHealthLineIsValidTelegramHTML(t *testing.T) {
	cases := []struct {
		name string
		e    monitor.EgressHealth
	}{
		{"亚毫秒桥探测", monitor.EgressHealth{
			Name: "hinet", Kind: monitor.ProbeKindBridge,
			Probe1h:  monitor.Window{Count: 60, AvgUS: 40, P95US: 85},
			Probe24h: monitor.Window{Count: 1440, AvgUS: 43, P95US: 91},
			Fw1h:     monitor.Window{Count: 10, AvgUS: 60, P95US: 90},
		}},
		{"真实链路", monitor.EgressHealth{
			Name: "softbank", Kind: monitor.ProbeKindEndToEnd,
			Probe1h:   monitor.Window{Count: 60, AvgUS: 135_000, P95US: 210_000},
			UpBytes:   1 << 20,
			DownBytes: 5 << 20,
		}},
		{"含失败与尖括号名", monitor.EgressHealth{
			Name: "a<b>&c", Kind: monitor.ProbeKindNode,
			Probe1h: monitor.Window{
				Count: 60, Fail: 3, AvgUS: 36_000, P95US: 99_000,
				LastFailAt: time.Now(),
			},
		}},
		{"无数据", monitor.EgressHealth{Name: "DIRECT"}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			assertTelegramHTML(t, egressHealthLine(c.e))
		})
	}
}

// FormatUS 的输出会被直接拼进 HTML 消息，绝不能含裸尖括号。
func TestFormatUSHasNoHTMLSpecialChars(t *testing.T) {
	for _, us := range []int64{0, 1, 40, 99, 100, 432, 1500, 9999, 36_000, 4_000_000} {
		got := monitor.FormatUS(us)
		if strings.ContainsAny(got, "<>&") {
			t.Fatalf("FormatUS(%d)=%q 含 HTML 特殊字符，会让整条消息发送失败", us, got)
		}
	}
}

// 证书过期时整行曾被隐藏，恰好在最需要提示的时候什么都不显示。
func TestCertHealthLine(t *testing.T) {
	cases := []struct {
		days int
		want string
	}{
		{80, "🔐 证书剩余　<b>80 天</b>"},
		{14, "⚠️ 证书剩余　<b>14 天</b>"},
		{0, "⚠️ 证书剩余　<b>0 天</b>"},
		{-1, "🚨 证书已过期　<b>1 天</b>"},
		{-29, "🚨 证书已过期　<b>29 天</b>"},
	}
	for _, c := range cases {
		got := certHealthLine(c.days)
		if got != c.want {
			t.Errorf("certHealthLine(%d) = %q, want %q", c.days, got, c.want)
		}
		assertTelegramHTML(t, got)
	}
}

func TestAppCheckCardIsValidTelegramHTML(t *testing.T) {
	out := checkCard([]manage.AppDomain{
		{Host: "i.ytimg.com", Egresses: map[string]int{"nuross": 2}, Count: 2, Rule: "FINAL → 代理:<nuross>"},
		{Host: "*.googlevideo.com", Egresses: map[string]int{"ctc": 9}, Count: 9, OK: true},
	}, map[string]string{"ctc": "🇭🇰CTC"})
	assertTelegramHTML(t, out)
	if !strings.Contains(out, "🇭🇰CTC×9") || !strings.Contains(out, "✗ <code>i.ytimg.com</code>") {
		t.Errorf("核对卡片内容不符合预期: %s", out)
	}
}

func TestRouteCardIsValidTelegramHTML(t *testing.T) {
	out := routeCard([]manage.AppRoute{
		{Host: "youtubei.googleapis.com", Egress: "att", Rule: "DOMAIN-SUFFIX,googleapis.com"},
		{Host: "ads.youtube.com", Blocked: true, OK: true},
		{Host: "*.googlevideo.com", Egress: "ctc", OK: true},
	}, map[string]string{"att": "🇺🇸ATT"})
	assertTelegramHTML(t, out)
	for _, want := range []string{"✗ <code>youtubei.googleapis.com</code>　→ 🇺🇸ATT", "⊘ <code>ads.youtube.com</code>　广告拦截", "✓ <code>*.googlevideo.com</code>"} {
		if !strings.Contains(out, want) {
			t.Errorf("缺少 %q: %s", want, out)
		}
	}
}
