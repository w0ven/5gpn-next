package ruleset

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// TestFetchChangedOnlyReportsRealContentChange 锁定线上 OOM 事故：
//
// 旧实现只要下载成功就判定“已刷新”，调用方据此热重载策略引擎。重载会
// 在旧引擎仍存活时构建一份全新引擎（cn-domain 11 万条 + 广告库 10 万条），
// 内存瞬时翻倍，峰值撞破 cgroup 上限被 OOM kill；重启后再次重复，形成
// OOM→重启→再 OOM 的死循环（生产实测 7 天 200 次）。
//
// 正确语义：只有字节内容真的变化才 changed=true。
func TestFetchChangedOnlyReportsRealContentChange(t *testing.T) {
	body := atomic.Value{}
	body.Store("example.com\nfoo.example.net\n")
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(body.Load().(string)))
	}))
	defer srv.Close()

	f := NewFetcher(t.TempDir())
	ctx := context.Background()

	// 首次：无缓存 → 必须视为变化
	p1, ch1, err := f.FetchChanged(ctx, "cn-domain", srv.URL)
	if err != nil {
		t.Fatalf("首次下载失败: %v", err)
	}
	if !ch1 {
		t.Fatal("首次下载必须 changed=true")
	}

	// 第二次：内容相同 → 绝不能报告变化（否则每次启动都触发重载）
	p2, ch2, err := f.FetchChanged(ctx, "cn-domain", srv.URL)
	if err != nil {
		t.Fatalf("二次下载失败: %v", err)
	}
	if ch2 {
		t.Fatal("内容未变却报告 changed=true —— OOM 死循环回归")
	}
	if p1 != p2 {
		t.Fatalf("缓存路径不稳定: %q vs %q", p1, p2)
	}

	// 第三次：内容确实变了 → 必须报告变化
	body.Store("example.com\nfoo.example.net\nbar.example.org\n")
	_, ch3, err := f.FetchChanged(ctx, "cn-domain", srv.URL)
	if err != nil {
		t.Fatalf("三次下载失败: %v", err)
	}
	if !ch3 {
		t.Fatal("内容已变却报告 changed=false —— 规则将永不更新")
	}

	// 第四次：回到稳定态
	if _, ch4, err := f.FetchChanged(ctx, "cn-domain", srv.URL); err != nil || ch4 {
		t.Fatalf("稳定态应 changed=false, 得到 changed=%v err=%v", ch4, err)
	}
}

// TestFetchChangedNetworkFailureFallsBackWithoutChange 网络失败回退缓存时
// 不得报告变化，否则断网会不断触发重载并放大内存峰值。
func TestFetchChangedNetworkFailureFallsBackWithoutChange(t *testing.T) {
	dir := t.TempDir()
	f := NewFetcher(dir)

	// 预置缓存
	cache := filepath.Join(dir, "cn-domain.list")
	if err := os.WriteFile(cache, []byte("example.com\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	// 指向一个立即失败的地址
	p, ch, err := f.FetchChanged(context.Background(), "cn-domain", "http://127.0.0.1:1/nope")
	var stale *StaleError
	if !errors.As(err, &stale) {
		t.Fatalf("有缓存时网络失败应报 StaleError（继续用缓存但要计为失败）: %v", err)
	}
	if _, ferr := f.Fetch(context.Background(), "cn-domain", "http://127.0.0.1:1/nope"); ferr != nil {
		t.Fatalf("Fetch 有缓存时应继续可用: %v", ferr)
	}
	if ch {
		t.Fatal("网络失败回退缓存却报告 changed=true —— 断网会触发重载风暴")
	}
	if p != cache {
		t.Fatalf("应回退到缓存 %q, 得到 %q", cache, p)
	}
}

// TestFetchChangedUpstreamErrorKeepsCache 上游 5xx 时保留缓存且不报告变化。
func TestFetchChangedUpstreamErrorKeepsCache(t *testing.T) {
	dir := t.TempDir()
	f := NewFetcher(dir)
	cache := filepath.Join(dir, "ad-block.list")
	if err := os.WriteFile(cache, []byte("ads.example.com\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	_, ch, err := f.FetchChanged(context.Background(), "ad-block", srv.URL)
	var stale *StaleError
	if !errors.As(err, &stale) {
		t.Fatalf("有缓存时上游 5xx 应报 StaleError: %v", err)
	}
	if ch {
		t.Fatal("上游 5xx 却报告 changed=true")
	}
	b, _ := os.ReadFile(cache)
	if string(b) != "ads.example.com\n" {
		t.Fatalf("缓存被破坏: %q", string(b))
	}
}

// TestFetchChangedEmptyBodyKeepsCache 空响应不得覆盖已有缓存。
func TestFetchChangedEmptyBodyKeepsCache(t *testing.T) {
	dir := t.TempDir()
	f := NewFetcher(dir)
	cache := filepath.Join(dir, "ad-block.list")
	if err := os.WriteFile(cache, []byte("ads.example.com\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer srv.Close()

	if _, ch, err := f.FetchChanged(context.Background(), "ad-block", srv.URL); err == nil || ch {
		t.Fatalf("空内容应报错且 changed=false, 得到 changed=%v err=%v", ch, err)
	}
	b, _ := os.ReadFile(cache)
	if string(b) != "ads.example.com\n" {
		t.Fatalf("空响应破坏了缓存: %q", string(b))
	}
}

// TestFetchWrapperStillWorks 兼容旧签名。
func TestFetchWrapperStillWorks(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("example.com\n"))
	}))
	defer srv.Close()
	f := NewFetcher(t.TempDir())
	p, err := f.Fetch(context.Background(), "cn-domain", srv.URL)
	if err != nil || p == "" {
		t.Fatalf("Fetch 包装失效: p=%q err=%v", p, err)
	}
}

// TestFetchRecordsStatus 每次检查都记入状态文件：失败累计次数，成功清零。
func TestFetchRecordsStatus(t *testing.T) {
	dir := t.TempDir()
	f := NewFetcher(dir)
	fail := true
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if fail {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		_, _ = w.Write([]byte("a.com\n"))
	}))
	defer srv.Close()

	for i := 0; i < 2; i++ {
		_, _, _ = f.FetchChanged(context.Background(), "x", srv.URL)
	}
	st := f.Statuses()["x"]
	if st.Fails != 2 || !strings.Contains(st.LastError, "404") || !st.LastSuccess.IsZero() {
		t.Fatalf("失败状态不对: %+v", st)
	}
	fail = false
	if _, _, err := f.FetchChanged(context.Background(), "x", srv.URL); err != nil {
		t.Fatal(err)
	}
	st = f.Statuses()["x"]
	if st.Fails != 0 || st.LastError != "" || st.LastSuccess.IsZero() {
		t.Fatalf("成功后状态不对: %+v", st)
	}
}

func TestDue(t *testing.T) {
	now := time.Date(2026, 10, 25, 12, 0, 0, 0, time.UTC)
	ok := Status{LastCheck: now.Add(-2 * time.Hour), LastSuccess: now.Add(-2 * time.Hour)}
	failing := Status{LastCheck: now.Add(-90 * time.Minute), LastSuccess: now.Add(-30 * time.Hour), Fails: 3}
	justFailed := Status{LastCheck: now.Add(-10 * time.Minute), LastSuccess: now.Add(-30 * time.Hour), Fails: 1}
	for _, tc := range []struct {
		name string
		iv   int
		st   Status
		want bool
	}{
		{"从未检查", 24, Status{}, true},
		{"两小时前刚成功", 24, ok, false},
		{"两小时前成功但间隔 1 小时", 1, ok, true},
		{"间隔未填按 24 小时", 0, ok, false},
		{"负数不自动更新", -1, Status{}, false},
		{"失败一小时后重试", 24, failing, true},
		{"刚失败不立刻重试", 24, justFailed, false},
	} {
		if got := Due(tc.iv, tc.st, now); got != tc.want {
			t.Errorf("%s: Due = %v, 期望 %v", tc.name, got, tc.want)
		}
	}
}
