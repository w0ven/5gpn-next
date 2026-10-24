package apps

import (
	"strconv"
	"strings"
	"testing"
)

func TestCatalogIsWellFormed(t *testing.T) {
	seen := map[string]bool{}
	for _, a := range All() {
		if a.Key == "" || seen[a.Key] {
			t.Fatalf("应用 Key 为空或重复: %q", a.Key)
		}
		seen[a.Key] = true
		if a.Name == "" || a.Emoji == "" || len(a.Lists) == 0 || len(a.Core) == 0 || len(a.Keywords) == 0 {
			t.Errorf("%s 缺少名称/回落表情/清单/核心域名/关键词", a.Key)
		}
		if _, err := strconv.ParseUint(a.EmojiID, 10, 64); err != nil {
			t.Errorf("%s 的 EmojiID %q 不是 custom emoji ID", a.Key, a.EmojiID)
		}
		for _, d := range a.Core {
			if d != strings.ToLower(d) || strings.ContainsAny(d, ":/ ,") {
				t.Errorf("%s 核心域名格式错误: %q", a.Key, d)
			}
		}
		// Bot 回调数据上限 64 字节；出口名最长 20 字符。
		if n := len("app_set:" + a.Key + ":" + strings.Repeat("x", 20)); n > 64 {
			t.Errorf("%s 回调数据 %d 字节超过 Telegram 上限", a.Key, n)
		}
	}
}

// Google 清单本身包含 YouTube 与 Gemini 的域名，排在前面会把它们整体截走。
func TestBroadAppsMatchLast(t *testing.T) {
	order := MatchOrder()
	if len(order) != len(All()) {
		t.Fatalf("MatchOrder 丢失应用: %d != %d", len(order), len(All()))
	}
	seenBroad := false
	pos := map[string]int{}
	for i, a := range order {
		pos[a.Key] = i
		if a.Broad {
			seenBroad = true
		} else if seenBroad {
			t.Fatalf("具体应用 %s 排在了 Broad 应用之后", a.Key)
		}
	}
	for _, k := range []string{"youtube", "gemini"} {
		if pos[k] > pos["google"] {
			t.Errorf("%s 必须先于 google 匹配", k)
		}
	}
	// xai 清单含 grok.x.com，必须先于 X 匹配。
	if pos["grok"] > pos["x"] {
		t.Error("grok 必须先于 x 匹配")
	}
}

func TestRulesPutCoreBeforeLists(t *testing.T) {
	a, ok := Get("meta")
	if !ok {
		t.Fatal("缺少 meta")
	}
	rules := a.Rules("ctc")
	if len(rules) != len(a.Core)+len(a.Lists) {
		t.Fatalf("规则数 %d", len(rules))
	}
	if rules[0] != "DOMAIN-SUFFIX,"+a.Core[0]+",proxy:ctc" {
		t.Errorf("首条规则 %q", rules[0])
	}
	if last := rules[len(rules)-1]; last != "RULE-SET,app-whatsapp,proxy:ctc" {
		t.Errorf("末条规则 %q", last)
	}
	if ListURL("youtube") != "https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/meta/geo/geosite/youtube.list" {
		t.Errorf("清单地址 %q", ListURL("youtube"))
	}
}

func TestMatchCoreAndKeyword(t *testing.T) {
	yt, _ := Get("youtube")
	for _, h := range []string{"youtube.com", "www.youtube.com", "rr1---sn-a5m.googlevideo.com", "youtubei.googleapis.com"} {
		if !yt.MatchCore(h) {
			t.Errorf("%s 应命中 YouTube 核心域名", h)
		}
	}
	for _, h := range []string{"notyoutube.com", "googleapis.com", "www.googleapis.com"} {
		if yt.MatchCore(h) {
			t.Errorf("%s 不应命中 YouTube 核心域名", h)
		}
	}
	if !yt.HasKeyword("youtube-ui.l.google.com") || yt.HasKeyword("www.google.com") {
		t.Error("关键词匹配不符合预期")
	}
}
