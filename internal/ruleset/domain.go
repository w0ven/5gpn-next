// Package ruleset 提供域名与 CIDR 规则集的加载和高速匹配。
package ruleset

import (
	"strings"
	"sync"
)

// DomainSet 以反向标签树存储域名规则，支持精确与后缀匹配。
//
// 规则形态（兼容 clash / mihomo 常见写法）：
//
//	example.com          后缀匹配（含自身及所有子域）
//	+.example.com        同上
//	.example.com         同上
//	full:example.com     仅精确匹配
//	domain:example.com   后缀匹配
//	keyword:foo          子串匹配
type DomainSet struct {
	mu       sync.RWMutex
	root     *node
	exact    map[string]struct{}
	keywords []string
	count    int
}

type node struct {
	// children 懒分配：85%+ 节点为叶子节点（terminal=true 且无子域），
	// 不为叶子预建空 map 可将 10 万级规则集的常驻堆与 GC 扫描对象砍掉大半。
	children map[string]*node
	// terminal 表示到此为止即构成一条后缀规则
	terminal bool
}

func newNode() *node {
	return &node{}
}

// NewDomainSet 返回空集合。
func NewDomainSet() *DomainSet {
	return &DomainSet{
		root:  newNode(),
		exact: make(map[string]struct{}),
	}
}

// Len 返回已载入的规则条数。
func (d *DomainSet) Len() int {
	d.mu.RLock()
	defer d.mu.RUnlock()
	return d.count
}

// AddRule 解析并加入一条规则；空行与 # 注释被忽略。
func (d *DomainSet) AddRule(raw string) {
	line := strings.TrimSpace(raw)
	if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "//") {
		return
	}
	// 去掉行尾注释
	if i := strings.IndexAny(line, "#"); i >= 0 {
		line = strings.TrimSpace(line[:i])
		if line == "" {
			return
		}
	}

	switch {
	case strings.HasPrefix(line, "keyword:"):
		kw := strings.ToLower(strings.TrimSpace(line[len("keyword:"):]))
		if kw == "" {
			return
		}
		d.mu.Lock()
		d.keywords = append(d.keywords, kw)
		d.count++
		d.mu.Unlock()
		return

	case strings.HasPrefix(line, "full:"):
		host := normalizeHost(line[len("full:"):])
		if host == "" {
			return
		}
		d.mu.Lock()
		d.exact[host] = struct{}{}
		d.count++
		d.mu.Unlock()
		return

	case strings.HasPrefix(line, "domain:"):
		line = line[len("domain:"):]
	case strings.HasPrefix(line, "+."):
		line = line[2:]
	case strings.HasPrefix(line, "."):
		line = line[1:]
	}

	host := normalizeHost(line)
	if host == "" {
		return
	}
	d.addSuffix(host)
}

func (d *DomainSet) addSuffix(host string) {
	d.mu.Lock()
	defer d.mu.Unlock()
	cur := d.root
	// 反向插入：com -> example，按需为非叶节点创建 children map，且免去 strings.Split 切片分配。
	for rem := host; rem != ""; {
		var l string
		if idx := strings.LastIndexByte(rem, '.'); idx >= 0 {
			l = rem[idx+1:]
			rem = rem[:idx]
		} else {
			l = rem
			rem = ""
		}
		if l == "" {
			continue
		}
		if cur.children == nil {
			cur.children = make(map[string]*node)
		}
		next, ok := cur.children[l]
		if !ok {
			next = newNode()
			cur.children[l] = next
		}
		cur = next
	}
	if !cur.terminal {
		cur.terminal = true
		d.count++
	}
}

// Match 判断 host 是否命中集合（热路径零堆分配）。
func (d *DomainSet) Match(host string) bool {
	h := normalizeHost(host)
	if h == "" {
		return false
	}

	d.mu.RLock()
	defer d.mu.RUnlock()

	if _, ok := d.exact[h]; ok {
		return true
	}

	cur := d.root
	for rem := h; rem != "" && cur != nil; {
		var l string
		if idx := strings.LastIndexByte(rem, '.'); idx >= 0 {
			l = rem[idx+1:]
			rem = rem[:idx]
		} else {
			l = rem
			rem = ""
		}
		if l == "" {
			continue
		}
		next, ok := cur.children[l]
		if !ok {
			break
		}
		cur = next
		if cur.terminal {
			return true
		}
	}

	for _, kw := range d.keywords {
		if strings.Contains(h, kw) {
			return true
		}
	}
	return false
}

// normalizeHost 统一小写、去尾点、去端口、去 IPv6 方括号。
func normalizeHost(s string) string {
	// 快路径：已是去空白、去尾点、无括号的全小写字符串时直接零分配返回。
	if s != "" && s[0] != '[' && s[len(s)-1] != '.' && s[len(s)-1] != ']' {
		clean := true
		for i := 0; i < len(s); i++ {
			c := s[i]
			if c <= ' ' || (c >= 'A' && c <= 'Z') || c >= 0x80 {
				clean = false
				break
			}
		}
		if clean {
			return s
		}
	}
	h := strings.TrimSpace(strings.ToLower(s))
	h = strings.TrimSuffix(h, ".")
	h = strings.TrimPrefix(h, "[")
	h = strings.TrimSuffix(h, "]")
	return h
}
