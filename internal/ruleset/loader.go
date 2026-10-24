package ruleset

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// LoadDomainFile 从本地文件载入域名规则集。
func LoadDomainFile(path string) (*DomainSet, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return parseDomains(f)
}

// LoadCIDRFile 从本地文件载入 CIDR 规则集。
func LoadCIDRFile(path string) (*CIDRSet, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return parseCIDRs(f)
}

func parseDomains(r io.Reader) (*DomainSet, error) {
	ds := NewDomainSet()
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for sc.Scan() {
		ds.AddRule(sc.Text())
	}
	return ds, sc.Err()
}

func parseCIDRs(r io.Reader) (*CIDRSet, error) {
	cs := NewCIDRSet()
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for sc.Scan() {
		cs.AddRule(sc.Text())
	}
	cs.Finalize()
	return cs, sc.Err()
}

// Fetcher 负责下载并缓存远程规则集。
//
// 缓存策略：下载成功才原子替换缓存；下载失败时回退到已有缓存，
// 保证网络异常不会让分流规则整体失效（fail-safe）。
type Fetcher struct {
	CacheDir string
	Client   *http.Client

	now func() time.Time
}

// NewFetcher 构造 Fetcher。
func NewFetcher(cacheDir string) *Fetcher {
	return &Fetcher{
		CacheDir: cacheDir,
		Client: &http.Client{
			Timeout: 60 * time.Second,
		},
	}
}

// cachePath 返回规则集缓存文件路径。
func (f *Fetcher) cachePath(name string) string {
	safe := strings.NewReplacer("/", "_", ":", "_", " ", "_").Replace(name)
	return filepath.Join(f.CacheDir, safe+".list")
}

// Cached 返回已有缓存的路径；无缓存时 ok=false。
// 用于启动加速：有缓存就先用，联网刷新放到后台做。
func (f *Fetcher) Cached(name string) (string, bool) {
	dst := f.cachePath(name)
	if st, err := os.Stat(dst); err == nil && st.Size() > 0 {
		return dst, true
	}
	return "", false
}

// StaleError 表示下载失败但旧缓存仍可用。调用方可以继续用缓存，但必须
// 把它当作一次失败：只要有缓存就报成功，上游地址失效或被墙时规则会
// 无限期停在旧版本，连续失败告警也永远不会触发。
type StaleError struct{ Err error }

func (e *StaleError) Error() string { return e.Err.Error() + "（继续使用旧缓存）" }
func (e *StaleError) Unwrap() error { return e.Err }

// Fetch 下载规则集到缓存；失败时若已有缓存则返回缓存路径与 nil。
func (f *Fetcher) Fetch(ctx context.Context, name, url string) (string, error) {
	path, _, err := f.FetchChanged(ctx, name, url)
	var stale *StaleError
	if errors.As(err, &stale) {
		return path, nil
	}
	return path, err
}

// FetchChanged 下载规则集并报告内容是否真的发生变化。
//
// changed 语义至关重要：调用方据此决定要不要热重载策略引擎。重载会
// 在旧引擎仍存活时构建一份全新引擎（cn-domain 11 万条 + 广告库 10 万条），
// 内存瞬时翻倍。生产事故：旧实现无论内容是否变化、甚至下载失败回退
// 缓存时都返回“成功”，启动自检那一轮必定触发一次全量重载，峰值撞破
// cgroup 上限被 OOM kill，重启后再次重复，形成 OOM→重启→再 OOM 的
// 死循环（实测 7 天 200 次），期间所有下载连接被反复掐断。
//
// 因此只有字节内容确实不同才返回 changed=true；网络失败回退缓存、
// 内容一致、无 url 走缓存等情况一律 changed=false。
//
// 下载失败但有缓存时返回缓存路径与 *StaleError。每次带 url 的检查结果
// 都记入状态文件，供状态页与失败告警使用。
func (f *Fetcher) FetchChanged(ctx context.Context, name, url string) (path string, changed bool, err error) {
	dst := f.cachePath(name)
	if url == "" {
		if _, err := os.Stat(dst); err == nil {
			return dst, false, nil
		}
		return "", false, fmt.Errorf("规则集 %s 无 url 且无缓存", name)
	}
	defer func() { f.record(name, err) }()

	if err := os.MkdirAll(f.CacheDir, 0o755); err != nil {
		return "", false, err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return "", false, err
	}
	req.Header.Set("User-Agent", "5gpn-next/1.0")

	resp, err := f.Client.Do(req)
	if err != nil {
		err = fmt.Errorf("下载 %s 失败: %w", name, err)
		if _, statErr := os.Stat(dst); statErr == nil {
			return dst, false, &StaleError{err} // fail-safe：回退缓存，未变化
		}
		return "", false, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		err = fmt.Errorf("下载 %s 返回 HTTP %d", name, resp.StatusCode)
		if _, statErr := os.Stat(dst); statErr == nil {
			return dst, false, &StaleError{err}
		}
		return "", false, err
	}

	tmp := dst + ".tmp"
	out, err := os.Create(tmp)
	if err != nil {
		return "", false, err
	}
	// 边写边算摘要，避免为比对再整file读一遍（规则库数 MB）。
	sum := sha256.New()
	// 限制单个规则集大小，防止异常来源撑爆磁盘
	n, err := io.Copy(io.MultiWriter(out, sum), io.LimitReader(resp.Body, 64<<20))
	out.Close()
	if err != nil {
		os.Remove(tmp)
		return "", false, err
	}
	if n == 0 {
		os.Remove(tmp)
		return "", false, fmt.Errorf("规则集 %s 内容为空", name)
	}

	// 内容与现有缓存一致：丢弃临时文件，不动缓存，也不触发重载。
	if old, err := fileSHA256(dst); err == nil && bytes.Equal(old, sum.Sum(nil)) {
		os.Remove(tmp)
		return dst, false, nil
	}

	if err := os.Rename(tmp, dst); err != nil {
		os.Remove(tmp)
		return "", false, err
	}
	return dst, true, nil
}

// fileSHA256 返回文件内容摘要；文件不存在时返回错误。
func fileSHA256(path string) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return nil, err
	}
	return h.Sum(nil), nil
}

// Status 是规则集最近一次联网检查的结果。
type Status struct {
	LastCheck   time.Time `json:"last_check"`
	LastSuccess time.Time `json:"last_success,omitempty"`
	LastError   string    `json:"last_error,omitempty"`
	Fails       int       `json:"fails,omitempty"` // 连续失败次数
}

const statusFile = "status.json"

// 多个 Fetcher 实例共用同一个状态文件。
var statusMu sync.Mutex

// Statuses 返回全部规则集的检查状态；从未检查过的不在其中。
func (f *Fetcher) Statuses() map[string]Status {
	statusMu.Lock()
	defer statusMu.Unlock()
	return f.readStatus()
}

// CacheInfo 返回缓存文件的最后修改时间（即内容最后一次变化的时间）。
func (f *Fetcher) CacheInfo(name string) (time.Time, bool) {
	st, err := os.Stat(f.cachePath(name))
	if err != nil || st.Size() == 0 {
		return time.Time{}, false
	}
	return st.ModTime(), true
}

func (f *Fetcher) readStatus() map[string]Status {
	m := map[string]Status{}
	b, err := os.ReadFile(filepath.Join(f.CacheDir, statusFile))
	if err == nil {
		_ = json.Unmarshal(b, &m)
	}
	return m
}

func (f *Fetcher) record(name string, err error) {
	statusMu.Lock()
	defer statusMu.Unlock()
	m := f.readStatus()
	st := m[name]
	now := time.Now()
	if f.now != nil {
		now = f.now()
	}
	st.LastCheck = now
	if err == nil {
		st.LastSuccess, st.LastError, st.Fails = now, "", 0
	} else {
		st.LastError, st.Fails = err.Error(), st.Fails+1
	}
	m[name] = st
	b, jerr := json.MarshalIndent(m, "", "  ")
	if jerr != nil {
		return
	}
	path := filepath.Join(f.CacheDir, statusFile)
	if os.MkdirAll(f.CacheDir, 0o755) != nil || os.WriteFile(path+".tmp", b, 0o644) != nil {
		return
	}
	_ = os.Rename(path+".tmp", path)
}

// RetryAfterFailure 是检查失败后再次尝试的最短间隔。
const RetryAfterFailure = time.Hour

// Due 报告规则集现在是否该联网检查。intervalHours 为 0 时按 24 小时，
// 为负数时不自动更新。失败后不等满一个周期，隔 RetryAfterFailure 就重试。
func Due(intervalHours int, st Status, now time.Time) bool {
	if intervalHours < 0 {
		return false
	}
	if intervalHours == 0 {
		intervalHours = 24
	}
	if st.LastCheck.IsZero() {
		return true
	}
	return now.Sub(st.LastSuccess) >= time.Duration(intervalHours)*time.Hour &&
		now.Sub(st.LastCheck) >= RetryAfterFailure
}
