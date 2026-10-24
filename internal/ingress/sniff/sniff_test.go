package sniff

import (
	"bufio"
	"context"
	"errors"
	"io"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/w0ven/5gpn-next/internal/egress"
	"github.com/w0ven/5gpn-next/internal/policy"
)

func TestAllowedClientEnforcesConfiguredCIDR(t *testing.T) {
	s := &Server{ClientCIDR: netip.MustParsePrefix("172.22.0.0/16")}
	for _, tc := range []struct {
		name string
		addr net.Addr
		want bool
	}{
		{"client", &net.TCPAddr{IP: net.ParseIP("172.22.7.9"), Port: 1234}, true},
		{"public", &net.TCPAddr{IP: net.ParseIP("203.0.113.8"), Port: 1234}, false},
		{"ipv6", &net.TCPAddr{IP: net.ParseIP("2001:db8::1"), Port: 1234}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := s.allowedClient(tc.addr); got != tc.want {
				t.Fatalf("allowedClient(%s)=%v, want %v", tc.addr, got, tc.want)
			}
		})
	}
}

// TestPeekHTTPHostDoesNotBlockOnShortRequest 锁定线上事故：
//
// 旧实现一次性 br.Peek(4096)，而 bufio.Peek(n) 会阻塞到凑满 n 字节。
// 普通 HTTP 请求头只有一两百字节，永远凑不满，于是每条 HTTP 连接都
// 干等到读超时（实测固定 8s）才继续，Play 的明文回源下载卡在“等待中”。
//
// 本用例用一条不再写入、也不关闭的真实连接复现该场景：若实现会阻塞，
// 测试超时失败；正确实现应立刻解析出 Host。
func TestPeekHTTPHostDoesNotBlockOnShortRequest(t *testing.T) {
	c1, c2 := net.Pipe()
	defer c1.Close()
	defer c2.Close()

	go func() {
		_, _ = c1.Write([]byte(
			"GET /generate_204 HTTP/1.1\r\n" +
				"Host: connectivitycheck.gstatic.com\r\n" +
				"User-Agent: probe\r\n" +
				"Connection: close\r\n\r\n"))
		// 关键：不再写入，也不关闭，模拟客户端等待响应。
	}()

	type result struct {
		host string
		port int
		err  error
	}
	done := make(chan result, 1)
	go func() {
		br := bufio.NewReaderSize(c2, 8*1024)
		h, p, err := peekHost(br, false)
		done <- result{h, p, err}
	}()

	select {
	case got := <-done:
		if got.err != nil {
			t.Fatalf("解析 Host 失败: %v", got.err)
		}
		if got.host != "connectivitycheck.gstatic.com" {
			t.Fatalf("Host = %q, 期望 connectivitycheck.gstatic.com", got.host)
		}
		if got.port != 80 {
			t.Fatalf("port = %d, 期望 80", got.port)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("peekHTTPHost 在短请求上阻塞了——4096 字节 Peek 回归")
	}
}

// TestPeekHTTPHostHeaderSplitAcrossSegments 头部跨 TCP 段到达时仍应解析成功。
func TestPeekHTTPHostHeaderSplitAcrossSegments(t *testing.T) {
	c1, c2 := net.Pipe()
	defer c1.Close()
	defer c2.Close()

	go func() {
		_, _ = c1.Write([]byte("GET /path HTTP/1.1\r\n"))
		time.Sleep(30 * time.Millisecond)
		_, _ = c1.Write([]byte("Host: dl.goo"))
		time.Sleep(30 * time.Millisecond)
		_, _ = c1.Write([]byte("gle.com\r\n\r\n"))
	}()

	done := make(chan string, 1)
	errc := make(chan error, 1)
	go func() {
		br := bufio.NewReaderSize(c2, 8*1024)
		h, err := peekHTTPHost(br)
		if err != nil {
			errc <- err
			return
		}
		done <- h
	}()

	select {
	case h := <-done:
		if h != "dl.google.com" {
			t.Fatalf("Host = %q, 期望 dl.google.com", h)
		}
	case err := <-errc:
		t.Fatalf("解析失败: %v", err)
	case <-time.After(3 * time.Second):
		t.Fatal("跨段头部解析阻塞")
	}
}

// TestPeekHTTPHostIgnoresPortInHost Host 里的端口不能决定目标端口：
// 否则客户端可借 HTTP 接管入口访问网关本机任意端口。
func TestPeekHTTPHostIgnoresPortInHost(t *testing.T) {
	cases := map[string]string{
		"example.com:8080": "example.com",
		"127.0.0.1:9095":   "127.0.0.1",
		"[::1]:9095":       "::1",
		"[::1]":            "::1",
		"example.com":      "example.com",
	}
	for in, wantHost := range cases {
		br := bufio.NewReaderSize(strings.NewReader(
			"GET / HTTP/1.1\r\nHost: "+in+"\r\n\r\n"), 8*1024)
		h, p, err := peekHost(br, false)
		if err != nil {
			t.Fatalf("%s: 解析失败: %v", in, err)
		}
		if h != wantHost || p != 80 {
			t.Fatalf("%s: 得到 %s:%d, 期望 %s:80", in, h, p, wantHost)
		}
	}
}

// TestHandleRefusesLoopbackTarget 接管入口不得替客户端连接网关本机回环服务。
func TestHandleRefusesLoopbackTarget(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	var accepted atomic.Int32
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			accepted.Add(1)
			c.Close()
		}
	}()

	eng := policy.New()
	reg := egress.NewRegistry()
	s := &Server{
		Policy: func() *policy.Engine { return eng },
		Egress: func() *egress.Registry { return reg },
	}
	for _, host := range []string{ln.Addr().String(), "127.0.0.1", "169.254.169.254", "[::1]:80"} {
		cli, srv := net.Pipe()
		done := make(chan struct{})
		go func() {
			s.handle(context.Background(), srv, false)
			close(done)
		}()
		_, _ = cli.Write([]byte("GET / HTTP/1.1\r\nHost: " + host + "\r\n\r\n"))
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			t.Fatalf("%s: handle 未结束", host)
		}
		cli.Close()
	}
	if n := accepted.Load(); n != 0 {
		t.Fatalf("回环服务被连接了 %d 次", n)
	}
	if got := s.Failed.Load(); got != 4 {
		t.Fatalf("Failed = %d, 期望 4", got)
	}
}

// TestPeekHTTPHostNoHostHeader 无 Host 头应返回 ErrNoHost，交由 DNS 线索兜底。
func TestPeekHTTPHostNoHostHeader(t *testing.T) {
	br := bufio.NewReaderSize(strings.NewReader(
		"GET / HTTP/1.0\r\nUser-Agent: x\r\n\r\n"), 8*1024)
	_, err := peekHTTPHost(br)
	if !errors.Is(err, ErrNoHost) {
		t.Fatalf("err = %v, 期望 ErrNoHost", err)
	}
}

// TestPeekHTTPHostDoesNotConsume 窥探不得消费数据，否则转发给上游的请求会缺头。
func TestPeekHTTPHostDoesNotConsume(t *testing.T) {
	raw := "GET /x HTTP/1.1\r\nHost: dl.google.com\r\n\r\n"
	br := bufio.NewReaderSize(strings.NewReader(raw), 8*1024)
	if _, err := peekHTTPHost(br); err != nil {
		t.Fatalf("解析失败: %v", err)
	}
	rest, err := br.Peek(len(raw))
	if err != nil {
		t.Fatalf("窥探后数据缺失: %v", err)
	}
	if string(rest) != raw {
		t.Fatalf("窥探消费了数据：\n得到 %q\n期望 %q", string(rest), raw)
	}
}

// TestServeACMEOnlyChallengeFiles 网段外的来源只能拿到挑战文件，其余 404，
// 不能借此走网关转发。
func TestServeACMEOnlyChallengeFiles(t *testing.T) {
	dir := t.TempDir()
	cd := filepath.Join(dir, ".well-known", "acme-challenge")
	if err := os.MkdirAll(cd, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(cd, "tok_EN-1"), []byte("tok_EN-1.thumb"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "secret"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	s := &Server{ACMEDir: dir}
	get := func(path string) string {
		cli, srv := net.Pipe()
		go s.serveACME(srv)
		_, _ = cli.Write([]byte("GET " + path + " HTTP/1.1\r\nHost: gw.example\r\n\r\n"))
		b, _ := io.ReadAll(cli)
		cli.Close()
		return string(b)
	}
	if r := get("/.well-known/acme-challenge/tok_EN-1"); !strings.HasPrefix(r, "HTTP/1.1 200") || !strings.HasSuffix(r, "tok_EN-1.thumb") {
		t.Fatalf("挑战文件应 200: %q", r)
	}
	for _, p := range []string{"/.well-known/acme-challenge/../../secret", "/.well-known/acme-challenge/missing", "/", "http://127.0.0.1:9095/"} {
		if r := get(p); !strings.HasPrefix(r, "HTTP/1.1 404") {
			t.Fatalf("%s 应 404: %q", p, r)
		}
	}
}
