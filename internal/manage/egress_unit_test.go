package manage

import (
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/w0ven/5gpn-next/internal/config"
)

// TestFreeLocalPortSkipsOccupied 新出口不能分到仍被别的进程占着的端口，
// 否则联通校验连到的是那个进程。
func TestFreeLocalPortSkipsOccupied(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	busy := ln.Addr().(*net.TCPAddr).Port
	got, err := freeLocalPort(busy)
	if err != nil {
		t.Fatal(err)
	}
	if got == busy {
		t.Fatalf("分到了被占用的端口 %d", busy)
	}
}

func TestStripMihomoControllerRewritesConfig(t *testing.T) {
	dir := t.TempDir()
	old := egressDir
	egressDir = dir
	defer func() { egressDir = old }()

	if err := os.MkdirAll(filepath.Join(dir, "jp"), 0o750); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "jp", "config.yaml")
	orig := "socks-port: 7891\nexternal-controller: 127.0.0.1:9095\nproxies:\n"
	if err := os.WriteFile(path, []byte(orig), 0o600); err != nil {
		t.Fatal(err)
	}
	var calls []string
	oldCtl := systemctl
	systemctl = func(args ...string) error {
		calls = append(calls, strings.Join(args, " "))
		return nil
	}
	defer func() { systemctl = oldCtl }()

	m := &Manager{Cfg: &config.Config{Egress: []config.EgressConfig{
		{Name: "DIRECT", Type: "direct"},
		{Name: "jp", Type: "socks5", Addr: "127.0.0.1:7891"},
	}}}
	m.StripMihomoController()
	b, _ := os.ReadFile(path)
	if strings.Contains(string(b), "external-controller") || !strings.Contains(string(b), "socks-port: 7891") {
		t.Fatalf("改写结果不对:\n%s", b)
	}
	if len(calls) != 1 || calls[0] != "try-restart mihomo-5gpn@jp.service" {
		t.Fatalf("systemctl 调用 = %v", calls)
	}
	calls = nil
	m.StripMihomoController()
	if len(calls) != 0 {
		t.Fatalf("配置已干净时不应重启: %v", calls)
	}
}
