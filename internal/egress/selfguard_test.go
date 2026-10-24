package egress

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"testing"
	"time"
)

// TestSelfConnectGuard 锁定 OOM 事故根因：网关连回自身接管端口形成环路。
//
// 生产实测：trace 中 target=<网关IP>:80 累计 25 万次，系统 TIME_WAIT
// 被打满 tcp_max_tw_buckets(4096)，每个 socket 在内核 slab 各占一份，
// cgroup 内存由 51MB 暴涨至 511MB 触发 OOM kill。
func TestSelfConnectGuard(t *testing.T) {
	old, hadOld := GatewayIP()
	t.Cleanup(func() {
		if hadOld {
			SetGatewayIP(old)
		} else {
			SetGatewayIP(netip.Addr{})
		}
	})

	SetGatewayIP(netip.MustParseAddr("203.0.113.37"))

	blocked := []string{
		"203.0.113.37:80",  // HTTP 接管
		"203.0.113.37:443", // TLS/QUIC 接管
		"203.0.113.37:853", // DoT
	}
	for _, addr := range blocked {
		if !IsSelfTakeover(addr) {
			t.Errorf("%s 应被判定为自连接", addr)
		}
	}

	allowed := []string{
		"203.0.113.37:20443", // 内网面板，不发起出站，不构成环路
		"203.0.113.37:22",    // SSH
		"8.8.8.8:443",        // 外部地址
		"1.1.1.1:80",
		"example.com:80", // 域名形式在本层不判定
	}
	for _, addr := range allowed {
		if IsSelfTakeover(addr) {
			t.Errorf("%s 不应被拦截", addr)
		}
	}
}

// TestSelfConnectGuardIPv4MappedIPv6 内核常以 ::ffff:a.b.c.d 形式呈现，
// 必须同样识别，否则环路会从 IPv6 路径漏过去。
func TestSelfConnectGuardIPv4Mapped(t *testing.T) {
	t.Cleanup(func() { SetGatewayIP(netip.Addr{}) })
	SetGatewayIP(netip.MustParseAddr("203.0.113.37"))

	if !IsSelfTakeover("[::ffff:203.0.113.37]:80") {
		t.Fatal("IPv4-mapped IPv6 形式的自连接未被拦截 —— 环路会从此漏过")
	}
}

// TestSelfConnectGuardDisabledWhenUnset 未登记网关 IP 时不得误拦任何流量。
func TestSelfConnectGuardDisabledWhenUnset(t *testing.T) {
	t.Cleanup(func() { SetGatewayIP(netip.Addr{}) })
	SetGatewayIP(netip.Addr{})

	for _, addr := range []string{"203.0.113.37:80", "8.8.8.8:443"} {
		if IsSelfTakeover(addr) {
			t.Errorf("未登记网关 IP 时 %s 不应被拦截", addr)
		}
	}
}

// TestDirectDialRejectsSelfConnect 拨号层必须真正拒绝，而不只是判定函数正确。
func TestDirectDialRejectsSelfConnect(t *testing.T) {
	t.Cleanup(func() { SetGatewayIP(netip.Addr{}) })
	SetGatewayIP(netip.MustParseAddr("127.0.0.1"))

	d := NewDirect("DIRECT")
	if _, err := d.DialContext(context.Background(), "tcp", "127.0.0.1:80"); !errors.Is(err, ErrSelfConnect) {
		t.Fatalf("TCP 拨号应返回 ErrSelfConnect, 得到 %v", err)
	}
	if _, err := d.DialUDP(context.Background(), "127.0.0.1:443"); !errors.Is(err, ErrSelfConnect) {
		t.Fatalf("UDP 拨号应返回 ErrSelfConnect, 得到 %v", err)
	}
}

// TestMalformedAddrDoesNotPanic 畸形地址不得导致崩溃或误拦。
func TestMalformedAddrDoesNotPanic(t *testing.T) {
	t.Cleanup(func() {
		SetGatewayIP(netip.Addr{})
		SetGatewayHost("")
	})
	SetGatewayIP(netip.MustParseAddr("203.0.113.37"))
	SetGatewayHost("gw.example.com")

	for _, addr := range []string{"", "no-port", "203.0.113.37", ":::", "203.0.113.37:abc"} {
		if IsSelfTakeover(addr) {
			t.Errorf("畸形地址 %q 不应被判定为自连接", addr)
		}
	}
}

// TestGatewayHostnameBlockedAcrossEgresses 锁定 v0.13.8 的残余环路：
// IsSelfTakeover 只识别 IP 字面量，域名直接返回 false；且注释声称
// “解析后再检查”，实际没有第二次检查。生产用网关自身域名各发一次
// HTTP/HTTPS 请求，分别递归 1024 条连接并撞上并发闸门，cgroup 峰值
// 从约 59MB 抬到 140MB。
func TestGatewayHostnameBlockedAcrossEgresses(t *testing.T) {
	t.Cleanup(func() {
		SetGatewayIP(netip.Addr{})
		SetGatewayHost("")
	})
	SetGatewayIP(netip.MustParseAddr("203.0.113.37"))
	SetGatewayHost("GW.EXAMPLE.COM.")

	for _, addr := range []string{
		"gw.example.com:80",
		"GW.EXAMPLE.COM:443",
		"gw.example.com.:853",
	} {
		if !IsSelfTakeover(addr) {
			t.Errorf("网关域名 %s 应被判定为自连接", addr)
		}
	}
	if IsSelfTakeover("gw.example.com:20443") {
		t.Fatal("面板端口不发起出站，不应误拦")
	}
	if IsSelfTakeover("other.example:443") {
		t.Fatal("无关域名不应误拦")
	}

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	direct := NewDirect("DIRECT")
	socks := NewSocks5("proxy", "127.0.0.1:1", false)

	checks := []struct {
		name string
		call func() error
	}{
		{"direct_tcp", func() error {
			_, err := direct.DialContext(ctx, "tcp", "gw.example.com:443")
			return err
		}},
		{"direct_udp", func() error {
			_, err := direct.DialUDP(ctx, "gw.example.com:443")
			return err
		}},
		{"socks_tcp", func() error {
			_, err := socks.DialContext(ctx, "tcp", "gw.example.com:443")
			return err
		}},
		{"socks_udp", func() error {
			_, err := socks.DialUDP(ctx, "gw.example.com:443")
			return err
		}},
	}
	for _, tc := range checks {
		t.Run(tc.name, func(t *testing.T) {
			if err := tc.call(); !errors.Is(err, ErrSelfConnect) {
				t.Fatalf("应在发起任何网络连接前返回 ErrSelfConnect，得到 %v", err)
			}
		})
	}
}

// TestDirectDialRejectsHostnameResolvedToSelf 验证 ControlContext 的关键语义：
// 传入的是域名，前置检查无法知道其 IP；net.Dialer 解析为 127.0.0.1 后，
// 必须在 socket connect 前用实际 IP 再检查。TCP 和 UDP 都要覆盖。
func TestDirectDialRejectsHostnameResolvedToSelf(t *testing.T) {
	t.Cleanup(func() {
		SetGatewayIP(netip.Addr{})
		SetGatewayHost("")
	})
	SetGatewayIP(netip.MustParseAddr("127.0.0.1"))
	SetGatewayHost("") // 故意不登记域名，确保命中的是解析后防线。

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	direct := NewDirect("DIRECT")

	conn, err := direct.DialContext(ctx, "tcp4", "localhost:80")
	if conn != nil {
		conn.Close()
	}
	if !errors.Is(err, ErrSelfConnect) {
		t.Fatalf("TCP 域名解析回网关后应返回 ErrSelfConnect，得到 %v", err)
	}

	// 直接走同一个 dialer 的 udp4，避免测试机 localhost 同时含 ::1 时
	// 通用 udp 的地址选择不确定；生产 Direct.DialUDP 复用的正是该 dialer。
	conn, err = direct.dialer.DialContext(ctx, "udp4", "localhost:443")
	if conn != nil {
		conn.Close()
	}
	if !errors.Is(err, ErrSelfConnect) {
		t.Fatalf("UDP 域名解析回网关后应返回 ErrSelfConnect，得到 %v", err)
	}
}

// TestPublicOnlyBlocksResolvedLoopback 接管拨号连域名也不能落到回环：
// 公网域名完全可以把 A 记录指向 127.0.0.1。网关自身的出站不受影响。
func TestPublicOnlyBlocksResolvedLoopback(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			c.Close()
		}
	}()
	_, port, _ := net.SplitHostPort(ln.Addr().String())
	d := NewDirect("DIRECT")

	ctx := PublicOnly(context.Background())
	for _, target := range []string{"localhost:" + port, ln.Addr().String()} {
		if c, err := d.DialContext(ctx, "tcp", target); !errors.Is(err, ErrNonPublicTarget) {
			if c != nil {
				c.Close()
			}
			t.Fatalf("%s: err = %v, 期望 ErrNonPublicTarget", target, err)
		}
	}
	if _, err := d.DialUDP(ctx, "127.0.0.1:443"); !errors.Is(err, ErrNonPublicTarget) {
		t.Fatalf("UDP: err = %v, 期望 ErrNonPublicTarget", err)
	}

	c, err := d.DialContext(context.Background(), "tcp", "localhost:"+port)
	if err != nil {
		t.Fatalf("非接管拨号不应受限: %v", err)
	}
	c.Close()
}

func TestIsPublicAddr(t *testing.T) {
	for s, want := range map[string]bool{
		"1.1.1.1": true, "142.250.1.1": true, "2606:4700::1111": true,
		"127.0.0.1": false, "10.1.2.3": false, "172.22.0.5": false, "192.168.1.1": false,
		"169.254.169.254": false, "100.64.0.1": false, "0.0.0.0": false, "::1": false,
		"fe80::1": false, "fd00::1": false, "::ffff:127.0.0.1": false, "224.0.0.1": false,
	} {
		if got := IsPublicAddr(netip.MustParseAddr(s)); got != want {
			t.Errorf("IsPublicAddr(%s) = %v, 期望 %v", s, got, want)
		}
	}
}
