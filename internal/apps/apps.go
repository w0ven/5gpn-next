// Package apps 是「应用分流」目录：常用应用 → 社区维护的域名清单。
//
// 清单来自 MetaCubeX/meta-rules-dat 的 geosite 文本格式：每天自动构建、
// include 已展开，写法与 ruleset 解析器一致。Core 是内置核心域名：清单
// 首次下载失败时，关键流量仍会走选定出口，而不是悄悄落回默认出口。
package apps

import "strings"

const listBase = "https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/meta/geo/geosite/"

// App 是一个可单独选择出口的应用。
type App struct {
	Key   string
	Name  string
	Emoji string // 客户端无法显示自定义表情时的回落
	// EmojiID 是 ZaiHuaNews 表情包（https://t.me/addemoji/ZaiHuaNews）里的 Logo。
	EmojiID string
	Lists   []string
	Core    []string
	// Keywords 用于核对：含这些片段却没命中清单的域名，可能是清单漏掉的。
	Keywords []string
	// Broad 表示清单覆盖了其它应用的域名（Google 清单含 YouTube、Gemini），
	// 必须排在所有具体应用之后匹配。
	Broad bool
}

// catalog 的顺序即展示顺序；匹配顺序见 MatchOrder。
var catalog = []App{
	{
		Key: "google", Name: "Google", Emoji: "🔍", EmojiID: "5855241013836127351",
		Lists:    []string{"google"},
		Core:     []string{"google.com", "googleapis.com", "gstatic.com", "googleusercontent.com", "gvt1.com", "gvt2.com"},
		Keywords: []string{"google"},
		Broad:    true,
	},
	{
		Key: "youtube", Name: "YouTube", Emoji: "▶️", EmojiID: "5818947960364342679",
		Lists: []string{"youtube"},
		// 视频流地址与请求它的出口 IP 绑定：页面、接口与 googlevideo
		// 必须同出口，否则播放 403。youtubei/youtube.googleapis.com 落在
		// googleapis.com 之下，必须显式列出才不会被 Google 规则截走。
		Core: []string{"youtube.com", "googlevideo.com", "ytimg.com", "ggpht.com", "youtu.be",
			"youtube-nocookie.com", "youtubei.googleapis.com", "youtube.googleapis.com",
			"youtubeembeddedplayer.googleapis.com", "yt3.googleusercontent.com"},
		Keywords: []string{"youtube", "googlevideo", "ytimg"},
	},
	{
		Key: "chatgpt", Name: "ChatGPT", Emoji: "🤖", EmojiID: "5861557411784957025",
		Lists:    []string{"openai"},
		Core:     []string{"openai.com", "chatgpt.com", "oaistatic.com", "oaiusercontent.com", "chat.com", "sora.com"},
		Keywords: []string{"openai", "chatgpt", "oaistatic", "oaiusercontent"},
	},
	{
		Key: "claude", Name: "Claude", Emoji: "✳️", EmojiID: "5872779796257184592",
		Lists:    []string{"anthropic"},
		Core:     []string{"claude.ai", "claude.com", "anthropic.com", "claudeusercontent.com"},
		Keywords: []string{"claude", "anthropic"},
	},
	{
		Key: "gemini", Name: "Gemini", Emoji: "✨", EmojiID: "5866057150236727962",
		Lists: []string{"google-gemini"},
		Core: []string{"gemini.google.com", "gemini.google", "generativelanguage.googleapis.com",
			"aistudio.google.com", "bard.google.com", "geminiweb-pa.clients6.google.com",
			"proactivebackend-pa.googleapis.com", "notebooklm.google.com"},
		Keywords: []string{"gemini", "bard", "notebooklm"},
	},
	{
		Key: "grok", Name: "Grok", Emoji: "⚫", EmojiID: "5855218413718215319",
		Lists:    []string{"xai"},
		Core:     []string{"x.ai", "grok.com"},
		Keywords: []string{"grok"},
	},
	{
		Key: "netflix", Name: "Netflix", Emoji: "🎬", EmojiID: "5818843480989899185",
		Lists:    []string{"netflix"},
		Core:     []string{"netflix.com", "netflix.net", "nflxvideo.net", "nflximg.net", "nflximg.com", "nflxext.com", "nflxso.net"},
		Keywords: []string{"netflix", "nflx"},
	},
	{
		Key: "disney", Name: "Disney+", Emoji: "🏰", EmojiID: "5818882157170401237",
		Lists:    []string{"disney"},
		Core:     []string{"disneyplus.com", "disney-plus.net", "bamgrid.com", "dssott.com", "disneystreaming.com"},
		Keywords: []string{"disney", "bamgrid", "dssott"},
	},
	{
		Key: "spotify", Name: "Spotify", Emoji: "🎧", EmojiID: "5818858298627071637",
		Lists:    []string{"spotify"},
		Core:     []string{"spotify.com", "scdn.co", "spotifycdn.com", "spoti.fi"},
		Keywords: []string{"spotify"},
	},
	{
		Key: "tiktok", Name: "TikTok", Emoji: "🎵", EmojiID: "5909018290759408000",
		Lists: []string{"tiktok"},
		// 不收 byteoversea/ibytedtos 等字节公共基础设施：国内应用同样在用。
		Core:     []string{"tiktok.com", "tiktokv.com", "tiktokcdn.com", "tiktokcdn-us.com", "ttwstatic.com"},
		Keywords: []string{"tiktok"},
	},
	{
		Key: "x", Name: "X", Emoji: "🐦", EmojiID: "5819115571463068721",
		Lists:    []string{"twitter"},
		Core:     []string{"x.com", "twitter.com", "twimg.com", "t.co"},
		Keywords: []string{"twitter", "twimg"},
	},
	{
		Key: "meta", Name: "Meta", Emoji: "♾️", EmojiID: "6046128455894965411",
		Lists: []string{"facebook", "instagram", "whatsapp"},
		Core: []string{"facebook.com", "fbcdn.net", "fb.com", "fbsbx.com", "messenger.com",
			"instagram.com", "cdninstagram.com", "whatsapp.com", "whatsapp.net"},
		Keywords: []string{"facebook", "fbcdn", "instagram", "whatsapp"},
	},
	{
		Key: "github", Name: "GitHub", Emoji: "🐙", EmojiID: "5870608651634349775",
		Lists:    []string{"github"},
		Core:     []string{"github.com", "githubusercontent.com", "githubassets.com", "github.io"},
		Keywords: []string{"github"},
	},
	{
		Key: "steam", Name: "Steam", Emoji: "🎮", EmojiID: "5818678889253183626",
		Lists:    []string{"steam"},
		Core:     []string{"steampowered.com", "steamcommunity.com", "steamstatic.com"},
		Keywords: []string{"steampowered", "steamcommunity", "steamstatic"},
	},
}

// All 返回全部应用（展示顺序）。
func All() []App {
	return append([]App(nil), catalog...)
}

// Get 按 Key 查找应用。
func Get(key string) (App, bool) {
	for _, a := range catalog {
		if a.Key == key {
			return a, true
		}
	}
	return App{}, false
}

// MatchOrder 返回匹配顺序：具体应用在前，Broad 应用在后，其余保持展示顺序。
func MatchOrder() []App {
	out := make([]App, 0, len(catalog))
	for _, a := range catalog {
		if !a.Broad {
			out = append(out, a)
		}
	}
	for _, a := range catalog {
		if a.Broad {
			out = append(out, a)
		}
	}
	return out
}

const ruleSetPrefix = "app-"

// RuleSetName 是清单注册到策略引擎时使用的规则集名。
func RuleSetName(list string) string { return ruleSetPrefix + list }

// IsListRuleSet 报告规则集是否为应用清单。
func IsListRuleSet(name string) bool { return strings.HasPrefix(name, ruleSetPrefix) }

// ListURL 是清单的下载地址。
func ListURL(list string) string { return listBase + list + ".list" }

// Rules 生成该应用的分流规则：先内置核心域名，再社区清单。
func (a App) Rules(egress string) []string {
	act := "proxy:" + egress
	out := make([]string, 0, len(a.Core)+len(a.Lists))
	for _, d := range a.Core {
		out = append(out, "DOMAIN-SUFFIX,"+d+","+act)
	}
	for _, l := range a.Lists {
		out = append(out, "RULE-SET,"+RuleSetName(l)+","+act)
	}
	return out
}

// MatchCore 报告 host 是否落在内置核心域名（含子域）之内。
func (a App) MatchCore(host string) bool {
	for _, d := range a.Core {
		if host == d || strings.HasSuffix(host, "."+d) {
			return true
		}
	}
	return false
}

// HasKeyword 报告 host 是否包含该应用的特征片段。
func (a App) HasKeyword(host string) bool {
	for _, k := range a.Keywords {
		if strings.Contains(host, k) {
			return true
		}
	}
	return false
}
