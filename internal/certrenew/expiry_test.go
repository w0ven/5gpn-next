package certrenew

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func writeCert(t *testing.T, path string, notAfter time.Time) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "gw.example"},
		NotBefore:    notAfter.Add(-90 * 24 * time.Hour),
		NotAfter:     notAfter,
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600); err != nil {
		t.Fatal(err)
	}
}

type fakeClock struct{ t time.Time }

func (c *fakeClock) now() time.Time { return c.t }

func newWatcher(t *testing.T, notAfter time.Time, clock *fakeClock) (*ExpiryWatcher, *[]string) {
	t.Helper()
	dir := t.TempDir()
	cert := filepath.Join(dir, "fullchain.pem")
	writeCert(t, cert, notAfter)
	var sent []string
	w := &ExpiryWatcher{
		CertFile:  cert,
		StateFile: filepath.Join(dir, "cert-alert"),
		Notify:    func(text string) { sent = append(sent, text) },
		now:       clock.now,
	}
	return w, &sent
}

func TestExpiryWatcherQuietWhenHealthy(t *testing.T) {
	clock := &fakeClock{time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC)}
	w, sent := newWatcher(t, clock.t.Add(40*24*time.Hour), clock)
	if err := w.Check(); err != nil {
		t.Fatal(err)
	}
	if len(*sent) != 0 {
		t.Fatalf("证书剩余 40 天不应告警: %q", *sent)
	}
}

func TestExpiryWatcherRemindsDailyAndRecovers(t *testing.T) {
	clock := &fakeClock{time.Date(2026, 9, 15, 0, 0, 0, 0, time.UTC)}
	notAfter := clock.t.Add(10 * 24 * time.Hour)
	w, sent := newWatcher(t, notAfter, clock)

	if err := w.Check(); err != nil {
		t.Fatal(err)
	}
	if len(*sent) != 1 || !strings.Contains((*sent)[0], "10 天后过期") {
		t.Fatalf("剩余 10 天应告警一次: %q", *sent)
	}

	// 12 小时后的周期检查，以及网关被续期钩子重启后的新实例，都不应重复推送。
	clock.t = clock.t.Add(12 * time.Hour)
	restarted := &ExpiryWatcher{CertFile: w.CertFile, StateFile: w.StateFile, Notify: w.Notify, now: clock.now}
	if err := restarted.Check(); err != nil {
		t.Fatal(err)
	}
	if len(*sent) != 1 {
		t.Fatalf("20 小时内不应重复提醒: %q", *sent)
	}

	clock.t = clock.t.Add(12 * time.Hour)
	if err := restarted.Check(); err != nil {
		t.Fatal(err)
	}
	if len(*sent) != 2 {
		t.Fatalf("隔天应再次提醒: %q", *sent)
	}

	clock.t = notAfter.Add(time.Hour)
	if err := restarted.Check(); err != nil {
		t.Fatal(err)
	}
	if len(*sent) != 3 || !strings.Contains((*sent)[2], "已过期") {
		t.Fatalf("过期后应发送过期告警: %q", *sent)
	}

	writeCert(t, w.CertFile, clock.t.Add(90*24*time.Hour))
	if err := restarted.Check(); err != nil {
		t.Fatal(err)
	}
	if len(*sent) != 4 || !strings.Contains((*sent)[3], "已续期") {
		t.Fatalf("续期后应发一次恢复通知: %q", *sent)
	}
	if _, err := os.Stat(w.StateFile); !os.IsNotExist(err) {
		t.Fatalf("恢复后应清除告警状态: %v", err)
	}
	if err := restarted.Check(); err != nil {
		t.Fatal(err)
	}
	if len(*sent) != 4 {
		t.Fatalf("恢复通知只发一次: %q", *sent)
	}
}

func TestNotAfterRejectsNonPEM(t *testing.T) {
	p := filepath.Join(t.TempDir(), "bad.pem")
	if err := os.WriteFile(p, []byte("not a cert"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := NotAfter(p); err == nil {
		t.Fatal("非 PEM 内容应返回错误")
	}
}
