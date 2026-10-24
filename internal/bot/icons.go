package bot

import (
	"fmt"
	"strings"

	"github.com/w0ven/5gpn-next/internal/apps"
)

// icon 是一个 custom emoji。Premium 客户端显示动态图标，其余客户端与
// 通知栏显示 fb。
type icon struct{ id, fb string }

// 功能图标取自 Mix Emoji（https://t.me/addemoji/IslomjonAnimeEmoji）的
// iOS 风格线性图标，品牌字标取自 Colorful Font
// （https://t.me/addemoji/ColorfulFontEmoji），应用 Logo 见 apps 包。
var icons = map[string]icon{
	"home":     {"5350404270032166927", "🏠"},
	"back":     {"5370919202796348364", "◀️"},
	"status":   {"5350710934992069206", "📊"},
	"egress":   {"5188381825701021648", "🌐"},
	"route":    {"5231346165974310893", "🔀"},
	"shield":   {"5352888345972187597", "🛡"},
	"probe":    {"5206473031110631274", "🔎"},
	"device":   {"5350374755016909685", "💻"},
	"panel":    {"5352858062157783478", "🧭"},
	"apple":    {"5352762486250545420", "🍏"},
	"android":  {"5866067063021246815", "🤖"},
	"update":   {"5274182275704039686", "⚡"},
	"new":      {"5233588456730427459", "🆕"},
	"party":    {"5193209274452425995", "🎉"},
	"settings": {"5370935802844946281", "⚙️"},
	"traffic":  {"5199785165735367039", "⚡"},
	"alert":    {"5197304993920616826", "📣"},
	"mute":     {"5350332462473944452", "🔇"},
	"ok":       {"5350486389806868244", "✅"},
	"warn":     {"5188463524568926712", "⚠️"},
	"online":   {"5188234920639632382", "🟢"},
	"loading":  {"5370715282044100355", "🌀"},
	"help":     {"5188540541922480562", "❓"},
}

// brandMark 是主页的「5GPN」字标。
var brandMark = []icon{
	{"5390859675094766802", "5️⃣"},
	{"5364140662071514084", "🔡"},
	{"5370996537977491955", "🔡"},
	{"5364230512787347881", "🔡"},
}

func tgEmoji(i icon) string {
	return fmt.Sprintf(`<tg-emoji emoji-id="%s">%s</tg-emoji>`, i.id, i.fb)
}

// ic 渲染一个功能图标；未知名称返回空串。
func ic(name string) string {
	i, ok := icons[name]
	if !ok {
		return ""
	}
	return tgEmoji(i)
}

func brand() string {
	var sb strings.Builder
	for _, i := range brandMark {
		sb.WriteString(tgEmoji(i))
	}
	return sb.String()
}

// iconID 解析按钮图标：功能图标名，或 "app:<key>" 表示应用 Logo。
func iconID(name string) string {
	if key, ok := strings.CutPrefix(name, "app:"); ok {
		if a, ok := apps.Get(key); ok {
			return a.EmojiID
		}
		return ""
	}
	return icons[name].id
}
