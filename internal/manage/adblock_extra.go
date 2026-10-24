package manage

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/w0ven/5gpn-next/internal/config"
	"github.com/w0ven/5gpn-next/internal/policy"
)

const (
	ruleSetDir = "/var/lib/5gpn-next/rulesets"

	adListFetchTimeout = 30 * time.Second

	// 疑似漏网只看最近一天、最多这么多个域名；只存在内存里，重启清空。
	dnsLogWindow = 24 * time.Hour
	dnsLogMax    = 5000
)

// AdBlockExtraStatus 是一个附加列表的状态。
type AdBlockExtraStatus struct {
	config.AdBlockExtra
	Enabled bool `json:"enabled"`
	// Domains 是已载入的条目数；开启后仍为 0 说明列表尚未下载成功。
	Domains int `json:"domains"`
}

func (m *Manager) adBlockExtrasLocked() []AdBlockExtraStatus {
	on := map[string]bool{}
	for _, x := range m.Cfg.AdBlockExtrasOn() {
		on[x.Key] = true
	}
	out := make([]AdBlockExtraStatus, 0, len(config.AdBlockExtras))
	for _, x := range config.AdBlockExtras {
		st := AdBlockExtraStatus{AdBlockExtra: x, Enabled: on[x.Key]}
		if st.Enabled && m.Policy != nil {
			st.Domains = m.Policy.DomainSetLen(config.AdBlockExtraRuleSet(x.Key))
		}
		out = append(out, st)
	}
	return out
}

// ruleSetUpdated 返回规则集缓存最后一次内容变化的时间；缓存只在内容
// 真正变化时才会被替换。
func ruleSetUpdated(name string) int64 {
	st, err := os.Stat(filepath.Join(ruleSetDir, name+".list"))
	if err != nil {
		return 0
	}
	return st.ModTime().Unix()
}

// SetAdBlockExtra 开启或关闭一个附加列表。列表在加锁前下载：热重载只读缓存。
func (m *Manager) SetAdBlockExtra(key string, on bool) (string, error) {
	x, ok := config.AdBlockExtraByKey(key)
	if !ok {
		return "", fmt.Errorf("未知的附加列表 %q", key)
	}
	name := config.AdBlockExtraRuleSet(key)
	if on && m.FetchRuleSet != nil {
		ctx, cancel := context.WithTimeout(context.Background(), adListFetchTimeout)
		err := m.FetchRuleSet(ctx, name, x.URL)
		cancel()
		if err != nil {
			return "", fmt.Errorf("%s 列表下载失败，未开启：%w", x.Name, err)
		}
	}

	m.mu.Lock()
	cur := map[string]bool{}
	for _, k := range m.Cfg.AdBlock.Extras {
		cur[k] = true
	}
	if cur[key] == on {
		m.mu.Unlock()
		if on {
			return x.Name + " 已是开启状态", nil
		}
		return x.Name + " 已是关闭状态", nil
	}
	cur[key] = on
	var next []string
	for _, e := range config.AdBlockExtras {
		if cur[e.Key] {
			next = append(next, e.Key)
		}
	}
	m.Cfg.AdBlock.Extras = next
	err := m.saveAndReloadLocked()
	enabled := m.Cfg.AdBlock.Enabled
	n := 0
	if m.Policy != nil {
		n = m.Policy.DomainSetLen(name)
	}
	m.mu.Unlock()

	switch {
	case err != nil:
		return "", err
	case !on:
		return "已关闭附加列表：" + x.Name, nil
	case !enabled:
		return "已选择 " + x.Name + "，开启广告拦截后生效", nil
	}
	return fmt.Sprintf("已开启附加列表：%s（%d 条）", x.Name, n), nil
}

// ---------- 疑似漏网 ----------

// adWords 是广告与数据上报域名里常见的标签（去掉结尾数字后整段匹配，
// 避免 blog、login、static 这类误判）。
var adWords = map[string]bool{}

func init() {
	for _, w := range strings.Fields(`ad ads adx adv adsdk adserver adservice adsystem advert advertising
		doubleclick googlesyndication googleadservices pangle pangolin mobads gdt umeng
		analytic analytics telemetry track tracker tracking trace metric metrics stat stats
		beacon beacons pixel click collect collector report reports reporting event events
		log logs logging applog rtlog mlog sentry crash crashlytics bugly apm mon monitor`) {
		adWords[w] = true
	}
}

// looksLikeAd 报告域名是否带有广告或数据上报的特征。
func looksLikeAd(host string) bool {
	for _, tok := range strings.FieldsFunc(host, func(r rune) bool { return r == '.' || r == '-' || r == '_' }) {
		if adWords[strings.TrimRight(tok, "0123456789")] {
			return true
		}
	}
	return false
}

type dnsSeen struct {
	count int
	last  time.Time
}

// dnsLog 只记下像广告或上报、且没被拦截的查询，供「疑似漏网」使用。
type dnsLog struct {
	mu sync.Mutex
	m  map[string]*dnsSeen
}

func (l *dnsLog) record(host string, now time.Time) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.m == nil {
		l.m = map[string]*dnsSeen{}
	}
	if e := l.m[host]; e != nil {
		e.count++
		e.last = now
		return
	}
	if len(l.m) >= dnsLogMax {
		l.evictLocked(now)
	}
	l.m[host] = &dnsSeen{count: 1, last: now}
}

// evictLocked 先丢掉窗口外的记录；仍然超限时丢掉最久没出现的四分之一。
func (l *dnsLog) evictLocked(now time.Time) {
	cutoff := now.Add(-dnsLogWindow)
	for h, e := range l.m {
		if e.last.Before(cutoff) {
			delete(l.m, h)
		}
	}
	if len(l.m) < dnsLogMax {
		return
	}
	hosts := make([]string, 0, len(l.m))
	for h := range l.m {
		hosts = append(hosts, h)
	}
	sort.Slice(hosts, func(i, j int) bool { return l.m[hosts[i]].last.Before(l.m[hosts[j]].last) })
	for _, h := range hosts[:len(hosts)/4] {
		delete(l.m, h)
	}
}

func (l *dnsLog) since(cutoff time.Time) map[string]dnsSeen {
	l.mu.Lock()
	defer l.mu.Unlock()
	out := make(map[string]dnsSeen, len(l.m))
	for h, e := range l.m {
		if !e.last.Before(cutoff) {
			out[h] = *e
		}
	}
	return out
}

// RecordDNS 由 DNS 入口在每次应答后调用。
func (m *Manager) RecordDNS(qname, action string) {
	if action == "block" {
		return
	}
	host := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(qname), "."))
	if host == "" || !looksLikeAd(host) {
		return
	}
	m.dns.record(host, time.Now())
}

// AdSuspect 是一个疑似漏网的域名。
type AdSuspect struct {
	Host   string `json:"host"`
	Count  int    `json:"count"`
	LastAt int64  `json:"last_at"`
}

// AdSuspects 返回最近一天里像广告或上报、却没被拦的域名（按查询次数排序）。
// 用当前规则重新判定，已被新规则拦住或在白名单里的不再列出。
func (m *Manager) AdSuspects(limit int) []AdSuspect {
	m.mu.RLock()
	eng := m.Policy
	allow := append([]string(nil), m.Cfg.AdBlock.Allowlist...)
	m.mu.RUnlock()

	var out []AdSuspect
	for host, e := range m.dns.since(time.Now().Add(-dnsLogWindow)) {
		if suffixListed(host, allow) {
			continue
		}
		if eng != nil {
			if t, err := policy.ParseTarget(host); err == nil && eng.Match(t).Action == policy.ActionBlock {
				continue
			}
		}
		out = append(out, AdSuspect{Host: host, Count: e.count, LastAt: e.last.Unix()})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Count != out[j].Count {
			return out[i].Count > out[j].Count
		}
		return out[i].Host < out[j].Host
	})
	if limit > 0 && len(out) > limit {
		out = out[:limit]
	}
	return out
}

func suffixListed(host string, list []string) bool {
	for _, d := range list {
		d = strings.ToLower(strings.TrimPrefix(strings.TrimSpace(d), "."))
		if d != "" && (host == d || strings.HasSuffix(host, "."+d)) {
			return true
		}
	}
	return false
}

// BlockDomain 把域名（含子域）加入自定义拦截规则，可在规则列表里删除撤销。
func (m *Manager) BlockDomain(host string) (string, error) {
	host = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(host), "."))
	if !strings.Contains(host, ".") || strings.ContainsAny(host, ",/ :*") {
		return "", fmt.Errorf("域名格式不正确：%q", host)
	}
	rule := "DOMAIN-SUFFIX," + host + ",block"
	m.mu.RLock()
	for _, r := range m.Cfg.Rules {
		if strings.EqualFold(strings.TrimSpace(r), rule) {
			m.mu.RUnlock()
			return host + " 已在拦截规则里", nil
		}
	}
	m.mu.RUnlock()
	if _, err := m.AddRule(rule); err != nil {
		return "", err
	}
	return "已拦截 " + host + "（可在自定义规则里删除）", nil
}
