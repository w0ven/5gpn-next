package manage

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
	"testing"
	"time"
)

func writeTestCert(t *testing.T, notAfter time.Time) string {
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
	p := filepath.Join(t.TempDir(), "fullchain.pem")
	if err := os.WriteFile(p, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

// 过期证书曾与「读取失败」共用 -1，健康页因此在过期后整行消失。
func TestCertDaysLeftDistinguishesExpiredFromUnknown(t *testing.T) {
	now := time.Date(2026, 10, 24, 9, 0, 0, 0, time.UTC)
	cases := []struct {
		name     string
		notAfter time.Time
		want     int
	}{
		{"剩余 89.9 天", now.Add(89*24*time.Hour + 22*time.Hour), 89},
		{"剩余半天", now.Add(12 * time.Hour), 0},
		{"刚过期", now.Add(-time.Hour), -1},
		{"过期 28.8 天", time.Date(2026, 9, 25, 14, 44, 4, 0, time.UTC), -29},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			days, ok := certDaysLeft(writeTestCert(t, c.notAfter), now)
			if !ok || days != c.want {
				t.Fatalf("certDaysLeft = (%d, %v), want (%d, true)", days, ok, c.want)
			}
		})
	}

	for _, p := range []string{"", filepath.Join(t.TempDir(), "missing.pem")} {
		if days, ok := certDaysLeft(p, now); ok {
			t.Errorf("certDaysLeft(%q) = (%d, true)，读不到证书应返回 ok=false", p, days)
		}
	}
}
