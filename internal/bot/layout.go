package bot

import (
	"encoding/json"
	"fmt"
	"html"
	"strings"
	"time"
)

// head 是每一屏的标题行：图标 + 粗体标题，可带一个灰色副标题。
func head(iconName, title string, sub ...string) string {
	s := ic(iconName) + " <b>" + title + "</b>"
	if len(sub) > 0 && sub[0] != "" {
		s += "　<i>" + sub[0] + "</i>"
	}
	return s + "\n"
}

func card(s string) string {
	s = strings.TrimSpace(s)
	if s == "" {
		return ""
	}
	return "<blockquote>" + s + "</blockquote>"
}

// note 是屏幕底部的一行状态提示（操作结果、进行中提示）。
func note(iconName, text string) string {
	return "\n" + ic(iconName) + " " + text
}

func esc(s string) string { return html.EscapeString(s) }

// beijing 是界面上所有绝对时间的时区。服务器通常跑在 UTC，用本地时区
// 格式化会比用户看到的时间慢 8 小时。
var beijing = time.FixedZone("Asia/Shanghai", 8*60*60)

// btn 是一个 inline 按钮。Data 以 "url:" 开头时为链接按钮。
// Icon 为功能图标名或 "app:<key>"；Style 为 primary / success / danger。
type btn struct {
	Text  string
	Data  string
	Icon  string
	Style string
}

func homeBtn() btn            { return btn{Text: "主页", Data: "menu", Icon: "home"} }
func backBtn(data string) btn { return btn{Text: "返回", Data: data, Icon: "back"} }

// navRow 是页面底部的导航行；上一级就是主页时只放一个主页按钮。
func navRow(back string) []btn {
	if back == "" || back == "menu" {
		return []btn{homeBtn()}
	}
	return []btn{backBtn(back), homeBtn()}
}

func backTo(target string) string { return inlineKeyboard(navRow(target)) }

// HomeKeyboard 是只含主页按钮的键盘，供进程外的结果消息（升级完成等）使用。
func HomeKeyboard() string { return backTo("menu") }

// dismissBtn 删除所在的通知消息。
func dismissBtn() btn { return btn{Text: "知道了", Data: "dismiss"} }

// grid 把按钮按每行 n 个排开。
func grid(n int, bs []btn) [][]btn {
	var rows [][]btn
	for len(bs) > 0 {
		k := min(n, len(bs))
		rows = append(rows, bs[:k])
		bs = bs[k:]
	}
	return rows
}

// buttonExtras 是按钮上的可选字段，按降级顺序排列：图标依赖 Bot 主人的 Premium，
// 配色依赖较新的 Bot API。
var buttonExtras = []string{"icon_custom_emoji_id", "style"}

func inlineKeyboard(rows ...[]btn) string {
	type ib struct {
		Text  string `json:"text"`
		Data  string `json:"callback_data,omitempty"`
		URL   string `json:"url,omitempty"`
		Icon  string `json:"icon_custom_emoji_id,omitempty"`
		Style string `json:"style,omitempty"`
	}
	out := make([][]ib, 0, len(rows))
	for _, r := range rows {
		if len(r) == 0 {
			continue
		}
		row := make([]ib, 0, len(r))
		for _, e := range r {
			b := ib{Text: e.Text, Icon: iconID(e.Icon), Style: e.Style}
			if u, ok := strings.CutPrefix(e.Data, "url:"); ok {
				b.URL = u
			} else {
				b.Data = e.Data
			}
			row = append(row, b)
		}
		out = append(out, row)
	}
	kb, _ := json.Marshal(map[string]any{"inline_keyboard": out})
	return string(kb)
}

// stripButtonExtras 去掉键盘按钮里的指定字段；不指定或解析失败时原样返回。
func stripButtonExtras(keyboard string, fields ...string) string {
	if len(fields) == 0 {
		return keyboard
	}
	var kb map[string][][]map[string]any
	if err := json.Unmarshal([]byte(keyboard), &kb); err != nil {
		return keyboard
	}
	for _, row := range kb["inline_keyboard"] {
		for _, b := range row {
			for _, f := range fields {
				delete(b, f)
			}
		}
	}
	out, err := json.Marshal(kb)
	if err != nil {
		return keyboard
	}
	return string(out)
}

func hasButtonExtras(keyboard string) bool {
	for _, f := range buttonExtras {
		if strings.Contains(keyboard, `"`+f+`"`) {
			return true
		}
	}
	return false
}

func errBox(title string, err error) string {
	return fmt.Sprintf("%s <b>%s</b>\n\n<code>%s</code>", ic("warn"), esc(title), esc(err.Error()))
}

func truncateText(s string, n int) string {
	s = strings.TrimSpace(s)
	r := []rune(s)
	if len(r) <= n {
		return s
	}
	return string(r[:n]) + "…"
}

func onOff(v bool) string {
	if v {
		return "开"
	}
	return "关"
}
