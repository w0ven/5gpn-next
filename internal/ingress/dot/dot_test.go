package dot

import (
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/miekg/dns"

	"github.com/w0ven/5gpn-next/internal/policy"
)

type captureDNSWriter struct {
	remote net.Addr
	msg    *dns.Msg
}

func (w *captureDNSWriter) LocalAddr() net.Addr         { return &net.TCPAddr{} }
func (w *captureDNSWriter) RemoteAddr() net.Addr        { return w.remote }
func (w *captureDNSWriter) Close() error                { return nil }
func (w *captureDNSWriter) TsigStatus() error           { return nil }
func (w *captureDNSWriter) TsigTimersOnly(bool)         {}
func (w *captureDNSWriter) Hijack()                     {}
func (w *captureDNSWriter) Write(b []byte) (int, error) { return len(b), nil }
func (w *captureDNSWriter) WriteMsg(m *dns.Msg) error {
	w.msg = m.Copy()
	return nil
}

func TestNonClientIsRefusedInsteadOfOpenRecursion(t *testing.T) {
	s := &Server{ClientCIDR: netip.MustParsePrefix("172.22.0.0/16")}
	w := &captureDNSWriter{remote: &net.TCPAddr{IP: net.ParseIP("203.0.113.9"), Port: 53000}}
	req := new(dns.Msg)
	req.SetQuestion("example.com.", dns.TypeA)

	s.handle(w, req)
	if w.msg == nil {
		t.Fatal("non-client request received no response")
	}
	if w.msg.Rcode != dns.RcodeRefused {
		t.Fatalf("rcode=%s, want REFUSED", dns.RcodeToString[w.msg.Rcode])
	}
}

func TestAnswerAddrsAndCachedLookup(t *testing.T) {
	qname := "unknown.example."
	cached := new(dns.Msg)
	cached.SetQuestion(qname, dns.TypeA)
	cached.Id = 1
	cached.Answer = []dns.RR{&dns.A{
		Hdr: dns.RR_Header{Name: qname, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60},
		A:   net.ParseIP("39.156.66.10").To4(),
	}}

	s := &Server{cache: map[string]cacheEntry{
		"unknown.example|1": {msg: cached, expire: time.Now().Add(time.Minute)},
	}}
	req := new(dns.Msg)
	req.SetQuestion(qname, dns.TypeA)
	req.Id = 4242

	resp, err := s.lookup(req, "unknown.example")
	if err != nil {
		t.Fatal(err)
	}
	if resp.Id != req.Id {
		t.Fatalf("cached response ID=%d, want %d", resp.Id, req.Id)
	}
	addrs := answerAddrs(resp)
	want := netip.MustParseAddr("39.156.66.10")
	if len(addrs) != 1 || addrs[0] != want {
		t.Fatalf("answerAddrs=%v, want [%s]", addrs, want)
	}
}

// FINAL 兜底的 direct（Index=-1）语义是“国外流量从网关本机出去”，
// 绝不能向手机返回真实 IP；否则国外域名会在国内蜂窝上直连失败
// （YouTube/TikTok 全挂的事故根因）。
func TestRealIPOnlyForExplicitDirectRules(t *testing.T) {
	cases := []struct {
		name string
		dec  policy.Decision
		want bool
	}{
		{"国内规则命中→真实 IP", policy.Decision{Action: policy.ActionDirect, Rule: "GEOIP,cn", Index: 6}, true},
		{"自定义 direct→真实 IP", policy.Decision{Action: policy.ActionDirect, Rule: "DOMAIN-SUFFIX,example.cn", Index: 0}, true},
		{"FINAL direct→改写到网关", policy.Decision{Action: policy.ActionDirect, Rule: "FINAL", Index: -1}, false},
		{"FINAL proxy→改写到网关", policy.Decision{Action: policy.ActionProxy, Egress: "hinet", Rule: "FINAL", Index: -1}, false},
		{"规则 proxy→改写到网关", policy.Decision{Action: policy.ActionProxy, Egress: "hinet", Rule: "DOMAIN-SUFFIX,openai.com", Index: 1}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := realIPForClient(tc.dec); got != tc.want {
				t.Fatalf("realIPForClient(%+v)=%v, want %v", tc.dec, got, tc.want)
			}
		})
	}
}

func TestShortCircuitSkipsUpstreamForBlockAndProxy(t *testing.T) {
	eng := policy.New()
	_ = eng.AddRule(policy.Rule{Kind: policy.KindIPCIDR, Value: "127.0.0.0/8", Action: policy.ActionDirect})
	_ = eng.AddRule(policy.Rule{Kind: policy.KindDomainSuffix, Value: "ads.example", Action: policy.ActionBlock})
	_ = eng.AddRule(policy.Rule{Kind: policy.KindDomainSuffix, Value: "openai.com", Action: policy.ActionProxy, Egress: "jp"})
	eng.SetFinal(policy.ActionProxy, "jp")

	upstreamCalled := 0
	s := &Server{
		GatewayIP:  netip.MustParseAddr("172.22.0.1"),
		ClientCIDR: netip.MustParsePrefix("172.22.0.0/16"),
		Upstream:   []string{"127.0.0.1:1"}, // 若触发上游查询会报错或记入 OnUpstream
		client:     &dns.Client{Net: "udp", Timeout: 50 * time.Millisecond},
		Policy:     func() *policy.Engine { return eng },
		OnUpstream: func(bool, int64) { upstreamCalled++ },
	}

	for _, tc := range []struct {
		qname string
		rcode int
		wantA string
	}{
		{"sub.ads.example.", dns.RcodeNameError, ""},
		{"chat.openai.com.", dns.RcodeSuccess, "172.22.0.1"},
	} {
		w := &captureDNSWriter{remote: &net.TCPAddr{IP: net.ParseIP("172.22.2.9"), Port: 53000}}
		req := new(dns.Msg)
		req.SetQuestion(tc.qname, dns.TypeA)
		s.handle(w, req)
		if upstreamCalled != 0 {
			t.Fatalf("%s triggered %d upstream lookups; want 0", tc.qname, upstreamCalled)
		}
		if w.msg == nil || w.msg.Rcode != tc.rcode {
			t.Fatalf("%s rcode=%v, want %d", tc.qname, w.msg, tc.rcode)
		}
		if tc.wantA != "" {
			got := answerAddrs(w.msg)
			if len(got) != 1 || got[0].String() != tc.wantA {
				t.Fatalf("%s A=%v, want [%s]", tc.qname, got, tc.wantA)
			}
		}
	}
}

func TestLoopbackPoisonDoesNotMisrouteUnknownDomainToDirect(t *testing.T) {
	eng := policy.New()
	_ = eng.AddRule(policy.Rule{Kind: policy.KindIPCIDR, Value: "127.0.0.0/8", Action: policy.ActionDirect})
	eng.SetFinal(policy.ActionProxy, "jp")

	poisoned := new(dns.Msg)
	poisoned.SetQuestion("blocked-overseas.io.", dns.TypeA)
	poisoned.Answer = []dns.RR{&dns.A{
		Hdr: dns.RR_Header{Name: "blocked-overseas.io.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60},
		A:   net.ParseIP("127.0.0.1").To4(),
	}}

	s := &Server{
		GatewayIP:  netip.MustParseAddr("172.22.0.1"),
		ClientCIDR: netip.MustParsePrefix("172.22.0.0/16"),
		Policy:     func() *policy.Engine { return eng },
		cache: map[string]cacheEntry{
			"blocked-overseas.io|1": {msg: poisoned, expire: time.Now().Add(time.Minute)},
		},
	}
	w := &captureDNSWriter{remote: &net.TCPAddr{IP: net.ParseIP("172.22.2.9"), Port: 53000}}
	req := new(dns.Msg)
	req.SetQuestion("blocked-overseas.io.", dns.TypeA)
	s.handle(w, req)

	got := answerAddrs(w.msg)
	if len(got) != 1 || got[0] != netip.MustParseAddr("172.22.0.1") {
		t.Fatalf("poisoned 127.0.0.1 should be rewritten to gateway IP, got %v", got)
	}
}
