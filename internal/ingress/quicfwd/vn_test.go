package quicfwd

import (
	"context"
	"encoding/binary"
	"net"
	"sync"
	"testing"
	"time"
)

type capturePC struct {
	mu   sync.Mutex
	sent [][]byte
	to   []net.Addr
}

func (c *capturePC) ReadFrom([]byte) (int, net.Addr, error) { select {} }
func (c *capturePC) WriteTo(b []byte, a net.Addr) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.sent = append(c.sent, append([]byte(nil), b...))
	c.to = append(c.to, a)
	return len(b), nil
}
func (c *capturePC) Close() error                     { return nil }
func (c *capturePC) LocalAddr() net.Addr              { return &net.UDPAddr{IP: net.IPv4(10, 0, 0, 1), Port: 443} }
func (c *capturePC) SetDeadline(time.Time) error      { return nil }
func (c *capturePC) SetReadDeadline(time.Time) error  { return nil }
func (c *capturePC) SetWriteDeadline(time.Time) error { return nil }

// 未知版本的首包不能静默丢弃：客户端会一直重试到超时（TikTok 的 h3-29
// 曾因此刷几个视频就卡住）。网关应回复版本协商，让客户端立即改用支持的版本。
func TestUnknownVersionGetsVersionNegotiation(t *testing.T) {
	s := &Server{sessions: map[string]*session{}}
	pc := &capturePC{}
	client := &net.UDPAddr{IP: net.IPv4(172, 22, 2, 92), Port: 50000}

	dg := make([]byte, 1250)
	dg[0] = 0xc3
	binary.BigEndian.PutUint32(dg[1:5], 0x51303530)
	dg[5] = 8
	copy(dg[6:14], []byte{1, 2, 3, 4, 5, 6, 7, 8})
	dg[14] = 0

	s.dispatch(context.Background(), pc, client, dg)

	if len(pc.sent) != 1 || pc.to[0].String() != client.String() {
		t.Fatalf("应向客户端回复一个版本协商包，实际 %d 个", len(pc.sent))
	}
	vn := pc.sent[0]
	if binary.BigEndian.Uint32(vn[1:5]) != 0 {
		t.Fatalf("回复不是版本协商包: %x", vn[:5])
	}
	if s.NoHost.Load() != 1 || len(s.sessions) != 0 {
		t.Fatalf("会话应结束并计入无法接管: nohost=%d sessions=%d", s.NoHost.Load(), len(s.sessions))
	}
}
