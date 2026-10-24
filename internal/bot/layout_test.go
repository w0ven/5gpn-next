package bot

import (
	"regexp"
	"strings"
	"testing"

	"github.com/w0ven/5gpn-next/internal/apps"
)

func TestHeadAndCard(t *testing.T) {
	got := head("egress", "出口", "默认出口")
	if !strings.Contains(got, `<tg-emoji emoji-id="`+icons["egress"].id+`">`) || !strings.Contains(got, "<b>出口</b>") {
		t.Fatalf("head=%q", got)
	}
	assertTelegramHTML(t, got)
	if card("  a\nb  ") != "<blockquote>a\nb</blockquote>" || card(" ") != "" {
		t.Fatalf("card=%q", card("  a\nb  "))
	}
}

func TestNavRow(t *testing.T) {
	if r := navRow("menu"); len(r) != 1 || r[0].Data != "menu" {
		t.Fatalf("上一级是主页时只应有主页按钮: %+v", r)
	}
	if r := navRow("egress"); len(r) != 2 || r[0].Data != "egress" || r[1].Data != "menu" {
		t.Fatalf("nav=%+v", r)
	}
}

var numericID = regexp.MustCompile(`^\d{15,20}$`)

func TestIconsAreCustomEmoji(t *testing.T) {
	for name, i := range icons {
		if !numericID.MatchString(i.id) || i.fb == "" {
			t.Errorf("图标 %s 无效: %+v", name, i)
		}
	}
	if len(brandMark) != 4 {
		t.Fatalf("字标应为 5GPN 四个字符")
	}
	for _, a := range apps.All() {
		if iconID("app:"+a.Key) == "" {
			t.Errorf("应用 %s 没有 Logo", a.Key)
		}
	}
	if iconID("nope") != "" || iconID("app:nope") != "" || ic("nope") != "" {
		t.Fatal("未知图标应为空")
	}
}

func TestKeyboardIconsAndStyle(t *testing.T) {
	kb := inlineKeyboard(
		[]btn{{Text: "YouTube", Data: "app:youtube", Icon: "app:youtube"}, {Text: "规则", Data: "rules"}},
		[]btn{{Text: "删除", Data: "x", Style: "danger"}, {Text: "面板", Data: "url:https://gw.example:443/", Icon: "panel"}},
		nil,
	)
	yt, _ := apps.Get("youtube")
	for _, want := range []string{
		`"callback_data":"app:youtube","icon_custom_emoji_id":"` + yt.EmojiID + `"`,
		`"callback_data":"x","style":"danger"`,
		`"url":"https://gw.example:443/","icon_custom_emoji_id":"` + icons["panel"].id + `"`,
	} {
		if !strings.Contains(kb, want) {
			t.Errorf("键盘缺少 %s: %s", want, kb)
		}
	}
	if strings.Count(kb, "icon_custom_emoji_id") != 2 || strings.Count(kb, "],[") != 1 {
		t.Errorf("只有指定了图标的按钮带图标，空行应被丢弃: %s", kb)
	}
}

func TestStripButtonExtrasByLevel(t *testing.T) {
	kb := inlineKeyboard([]btn{{Text: "升级", Data: "update_apply:v1", Icon: "update", Style: "primary"}}, navRow("update"))
	noIcon := stripButtonExtras(kb, buttonExtras[:1]...)
	if strings.Contains(noIcon, "icon_custom_emoji_id") || !strings.Contains(noIcon, `"style":"primary"`) {
		t.Fatalf("一级降级只去图标、保留配色: %s", noIcon)
	}
	plain := stripButtonExtras(kb, buttonExtras...)
	if hasButtonExtras(plain) {
		t.Fatalf("二级降级应去掉全部可选字段: %s", plain)
	}
	for _, want := range []string{`"callback_data":"update_apply:v1"`, `"callback_data":"update"`, `"callback_data":"menu"`, `"text":"主页"`} {
		if !strings.Contains(plain, want) {
			t.Errorf("降级后丢了按钮 %s: %s", want, plain)
		}
	}
	if stripButtonExtras(kb) != kb {
		t.Fatal("不指定字段时应原样返回")
	}
}

func TestCommandOf(t *testing.T) {
	for in, want := range map[string]string{
		"/start":                      "start",
		"/probe@KFCc1bot youtube.com": "probe youtube.com",
		"/egress@KFCc1bot":            "egress",
		"/probe   claude.ai ":         "probe claude.ai",
	} {
		if got := commandOf(strings.TrimSpace(in)); got != want {
			t.Errorf("commandOf(%q)=%q want %q", in, got, want)
		}
	}
}
