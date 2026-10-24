package manage

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/w0ven/5gpn-next/internal/apps"
	"github.com/w0ven/5gpn-next/internal/config"
	"github.com/w0ven/5gpn-next/internal/policy"
)

// AppStatus 描述一个应用的分流设置。
type AppStatus struct {
	Key     string `json:"key"`
	Name    string `json:"name"`
	Emoji   string `json:"emoji"`
	EmojiID string `json:"emoji_id"`
	// Egress 为空表示跟随默认规则。
	Egress        string `json:"egress"`
	EgressDisplay string `json:"egress_display"`
	Core          int    `json:"core"`
	// ListDomains 是已载入的社区清单条目数；启用后仍为 0 说明清单尚未下载成功，
	// 此时只有内置核心域名生效。
	ListDomains int `json:"list_domains"`
}

// Apps 返回全部应用的当前设置（展示顺序）。
func (m *Manager) Apps() []AppStatus {
	m.mu.RLock()
	defer m.mu.RUnlock()
	out := make([]AppStatus, 0, len(apps.All()))
	for _, a := range apps.All() {
		st := AppStatus{
			Key: a.Key, Name: a.Name, Emoji: a.Emoji, EmojiID: a.EmojiID,
			Egress: m.Cfg.Apps[a.Key],
			Core:   len(a.Core),
		}
		st.EgressDisplay = m.egressDisplayLocked(st.Egress)
		if m.Policy != nil {
			for _, l := range a.Lists {
				st.ListDomains += m.Policy.DomainSetLen(apps.RuleSetName(l))
			}
		}
		out = append(out, st)
	}
	return out
}

// App 返回单个应用的设置。
func (m *Manager) App(key string) (AppStatus, bool) {
	for _, st := range m.Apps() {
		if st.Key == key {
			return st, true
		}
	}
	return AppStatus{}, false
}

func (m *Manager) egressDisplayLocked(name string) string {
	switch name {
	case "":
		return "跟随默认"
	case "DIRECT":
		return "本机直出"
	}
	for _, e := range m.Cfg.Egress {
		if e.Name == name {
			return displayOf(e)
		}
	}
	return name
}

// SetAppEgress 设置应用出口；egressName 为空表示改回跟随默认。
func (m *Manager) SetAppEgress(key, egressName string) error {
	a, ok := apps.Get(key)
	if !ok {
		return fmt.Errorf("未知应用 %q", key)
	}
	addr := ""
	if egressName != "" && egressName != "DIRECT" {
		m.mu.RLock()
		found := false
		for _, e := range m.Cfg.Egress {
			if e.Name == egressName {
				found = true
				if e.Type == "socks5" {
					addr = e.Addr
				}
				break
			}
		}
		m.mu.RUnlock()
		if !found {
			return fmt.Errorf("出口 %q 不存在", egressName)
		}
	}
	// 与切换默认出口同理：选到坏出口，该应用会当场断网。
	if addr != "" {
		if err := verifyEgress(addr, 8*time.Second); err != nil {
			return fmt.Errorf("出口 %q 验证失败，%s 保持原设置：%v", egressName, a.Name, err)
		}
	}
	// 清单在加锁前下载：热重载只读缓存。下载失败不阻止设置，
	// 内置核心域名先生效，后台刷新或重新选择出口时再补。
	if egressName != "" && m.FetchRuleSet != nil {
		for _, l := range a.Lists {
			ctx, cancel := context.WithTimeout(context.Background(), appListFetchTimeout)
			err := m.FetchRuleSet(ctx, apps.RuleSetName(l), apps.ListURL(l))
			cancel()
			if err != nil {
				log.Printf("应用清单 %s 下载失败（先用内置核心域名）: %v", l, err)
			}
		}
	}

	m.mu.Lock()
	defer m.mu.Unlock()
	if m.Cfg.Apps == nil {
		m.Cfg.Apps = map[string]string{}
	}
	if m.Cfg.AppsChanged == nil {
		m.Cfg.AppsChanged = map[string]int64{}
	}
	if egressName == "" {
		delete(m.Cfg.Apps, key)
		delete(m.Cfg.AppsChanged, key)
	} else {
		m.Cfg.Apps[key] = egressName
		m.Cfg.AppsChanged[key] = time.Now().Unix()
	}
	return m.saveAndReloadLocked()
}

// AppDomain 是核对结果中的一个域名。
type AppDomain struct {
	Host string `json:"host"`
	// Egresses 是实际出口 → 连接次数。
	Egresses map[string]int `json:"egresses"`
	Count    int            `json:"count"`
	// OK 表示全部连接都走了选定出口。
	OK bool `json:"ok"`
	// Rule 是最近一次未走选定出口时命中的规则，便于判断是谁截走了流量。
	Rule string `json:"rule,omitempty"`
}

// AppRoute 是按当前规则对一个域名的判定。
type AppRoute struct {
	Host   string `json:"host"`
	Egress string `json:"egress,omitempty"`
	Rule   string `json:"rule"`
	// Blocked 表示被广告拦截等规则拦下：属预期行为，不算没走选定出口。
	Blocked bool `json:"blocked,omitempty"`
	OK      bool `json:"ok"`
}

// 核对窗口的起点来源。
const (
	SinceChanged = "changed" // 改出口的时刻
	SinceStarted = "started" // 网关启动时刻（变更时间未知时，只能保证此后用的是当前配置）
	SinceWindow  = "window"  // 固定回看窗口
)

// AppCheck 是核对应用分流的结果：Current 用当前规则复核最近见过的域名与
// 内置核心域名，不依赖新流量；Domains 是窗口内真实转发的实际出口。
type AppCheck struct {
	Key           string    `json:"key"`
	Egress        string    `json:"egress"`
	EgressDisplay string    `json:"egress_display"`
	Since         time.Time `json:"since"`
	SinceKind     string    `json:"since_kind"`
	// Current 是按当前规则的判定，异常在前。
	Current         []AppRoute `json:"current"`
	CurrentMismatch int        `json:"current_mismatch"`
	// Domains 是窗口内命中该应用清单的域名。
	Domains []AppDomain `json:"domains"`
	// Suspects 是含该应用特征、却没命中任何已启用应用清单，
	// 也没走选定出口的域名：可能是清单漏掉的。
	Suspects []AppDomain `json:"suspects"`
	Mismatch int         `json:"mismatch"`
}

const (
	appListFetchTimeout = 30 * time.Second
	appCheckWindow      = 24 * time.Hour
	appCheckMaxBytes    = 8 << 20
	appCheckMaxRows     = 30
)

// CheckApp 用最近的转发记录核对应用分流。
func (m *Manager) CheckApp(key string) (AppCheck, error) {
	a, ok := apps.Get(key)
	if !ok {
		return AppCheck{}, fmt.Errorf("未知应用 %q", key)
	}
	m.mu.RLock()
	want := m.Cfg.Apps[key]
	logPath := m.Cfg.LogPath
	eng := m.Policy
	now := time.Now()
	since, kind := now.Add(-appCheckWindow), SinceWindow
	changed, changedKind := m.started, SinceStarted
	if ts := m.Cfg.AppsChanged[key]; ts > 0 {
		changed, changedKind = time.Unix(ts, 0), SinceChanged
	}
	if changed.After(since) {
		since, kind = changed, changedKind
	}
	enabled := make([]apps.App, 0)
	for _, x := range apps.MatchOrder() {
		if m.Cfg.Apps[x.Key] != "" {
			enabled = append(enabled, x)
		}
	}
	res := AppCheck{Key: key, Egress: want, EgressDisplay: m.egressDisplayLocked(want), Since: since, SinceKind: kind}
	m.mu.RUnlock()

	if want == "" {
		return res, fmt.Errorf("%s 当前跟随默认规则，选定出口后才能核对", a.Name)
	}
	if logPath == "" {
		return res, fmt.Errorf("未开启转发日志（log_path），无法核对")
	}
	// 读满整个回看窗口：窗口起点之前的记录不计入实际出口，但其中出现过的
	// 域名仍按当前规则复核。
	recs, err := readTraceTail(logPath, appCheckMaxBytes, now.Add(-appCheckWindow))
	if err != nil {
		return res, fmt.Errorf("读取转发日志失败: %w", err)
	}

	owner := func(host string) string {
		for _, x := range enabled {
			if x.MatchCore(host) {
				return x.Key
			}
			for _, l := range x.Lists {
				if eng != nil && eng.DomainSetMatch(apps.RuleSetName(l), host) {
					return x.Key
				}
			}
		}
		return ""
	}
	domains := map[string]*AppDomain{}
	suspects := map[string]*AppDomain{}
	seen := map[string]string{} // 归并名 → 一个真实主机，供按当前规则复核
	for _, r := range recs {
		o := owner(r.host)
		if o == key {
			if _, ok := seen[collapseHost(r.host)]; !ok {
				seen[collapseHost(r.host)] = r.host
			}
		}
		if r.ts.Before(since) {
			continue
		}
		var bucket map[string]*AppDomain
		switch {
		case o == key:
			bucket = domains
		case o == "" && a.HasKeyword(r.host) && r.egress != want:
			bucket = suspects
		default:
			continue
		}
		name := collapseHost(r.host)
		d := bucket[name]
		if d == nil {
			d = &AppDomain{Host: name, Egresses: map[string]int{}}
			bucket[name] = d
		}
		d.Count++
		d.Egresses[r.egress]++
		if r.egress != want {
			d.Rule = r.rule
		}
	}
	res.Domains, res.Mismatch = finishDomains(domains, want)
	res.Suspects, _ = finishDomains(suspects, want)
	if eng != nil {
		res.Current, res.CurrentMismatch = routeNow(eng, a, seen, want)
	}
	return res, nil
}

// routeNow 用当前规则判定最近见过的域名与应用的内置核心域名。
func routeNow(eng *policy.Engine, a apps.App, seen map[string]string, want string) ([]AppRoute, int) {
	hosts := map[string]string{}
	for name, h := range seen {
		hosts[name] = h
	}
	for _, d := range a.Core {
		covered := false
		for _, h := range seen {
			if h == d || strings.HasSuffix(h, "."+d) {
				covered = true
				break
			}
		}
		if !covered {
			hosts[d] = d
		}
	}
	out := make([]AppRoute, 0, len(hosts))
	bad := 0
	for name, h := range hosts {
		t, err := policy.ParseTarget(h)
		if err != nil {
			continue
		}
		dec := eng.Match(t)
		r := AppRoute{Host: name, Rule: dec.Rule}
		switch dec.Action {
		case policy.ActionBlock:
			r.Blocked, r.OK = true, true
		case policy.ActionDirect:
			r.Egress = "DIRECT"
		default:
			r.Egress = dec.Egress
		}
		if !r.Blocked {
			r.OK = r.Egress == want
		}
		if !r.OK {
			bad++
		}
		out = append(out, r)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].OK != out[j].OK {
			return !out[i].OK
		}
		return out[i].Host < out[j].Host
	})
	if len(out) > appCheckMaxRows {
		out = out[:appCheckMaxRows]
	}
	return out, bad
}

func finishDomains(in map[string]*AppDomain, want string) ([]AppDomain, int) {
	out := make([]AppDomain, 0, len(in))
	bad := 0
	for _, d := range in {
		d.OK = len(d.Egresses) == 1 && d.Egresses[want] > 0
		if !d.OK {
			bad++
		}
		out = append(out, *d)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].OK != out[j].OK {
			return !out[i].OK
		}
		if out[i].Count != out[j].Count {
			return out[i].Count > out[j].Count
		}
		return out[i].Host < out[j].Host
	})
	if len(out) > appCheckMaxRows {
		out = out[:appCheckMaxRows]
	}
	return out, bad
}

// collapseHost 把 Google 这类带节点编号的 CDN 主机（rr3---sn-xxx.googlevideo.com）
// 归并成通配名，避免核对列表被成百上千个边缘节点淹没。
func collapseHost(h string) string {
	if i := strings.IndexByte(h, '.'); i > 0 && strings.Contains(h[:i], "---") {
		return "*" + h[i:]
	}
	return h
}

type traceRec struct {
	ts     time.Time
	host   string
	egress string
	rule   string
}

// readTraceTail 读取转发日志尾部 maxBytes 内、时间不早于 since 的记录。
// 只保留实际建立了出站连接（出口步骤成功）的记录。
func readTraceTail(path string, maxBytes int64, since time.Time) ([]traceRec, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		return nil, err
	}
	off := st.Size() - maxBytes
	if off < 0 {
		off = 0
	}
	if _, err := f.Seek(off, io.SeekStart); err != nil {
		return nil, err
	}
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 64<<10), 1<<20)
	if off > 0 {
		sc.Scan() // 丢弃被截断的首行
	}
	var out []traceRec
	for sc.Scan() {
		line := sc.Bytes()
		if !bytes.Contains(line, []byte(`"egress"`)) {
			continue
		}
		var r struct {
			TS     time.Time `json:"ts"`
			Target string    `json:"target"`
			Steps  []struct {
				Stage  string `json:"stage"`
				Status string `json:"status"`
				Detail string `json:"detail"`
			} `json:"steps"`
		}
		if json.Unmarshal(line, &r) != nil || r.TS.Before(since) {
			continue
		}
		rec := traceRec{ts: r.TS, host: hostOf(r.Target)}
		for _, s := range r.Steps {
			switch s.Stage {
			case "policy":
				rec.rule = s.Detail
			case "egress":
				if s.Status == "ok" {
					rec.egress = s.Detail
				}
			}
		}
		if rec.host != "" && rec.egress != "" {
			out = append(out, rec)
		}
	}
	return out, sc.Err()
}

func hostOf(target string) string {
	h := target
	if host, _, err := net.SplitHostPort(target); err == nil {
		h = host
	}
	return strings.TrimSuffix(strings.ToLower(h), ".")
}

// appEgressNames 返回可供应用选择的出口（DIRECT 在前）。
func appEgressNames(cfg *config.Config) []string {
	out := []string{"DIRECT"}
	for _, e := range cfg.Egress {
		if e.Name != "DIRECT" {
			out = append(out, e.Name)
		}
	}
	return out
}

// AppEgressChoices 返回应用可选的出口名及展示名（DIRECT 在前）。
func (m *Manager) AppEgressChoices() [][2]string {
	m.mu.RLock()
	defer m.mu.RUnlock()
	names := appEgressNames(m.Cfg)
	out := make([][2]string, 0, len(names))
	for _, n := range names {
		out = append(out, [2]string{n, m.egressDisplayLocked(n)})
	}
	return out
}
