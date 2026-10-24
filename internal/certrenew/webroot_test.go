package certrenew

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

const kfcConf = `# renew_before_expiry = 30 days
version = 2.1.0
archive_dir = /etc/letsencrypt/archive/gw.example
cert = /etc/letsencrypt/live/gw.example/cert.pem
privkey = /etc/letsencrypt/live/gw.example/privkey.pem
chain = /etc/letsencrypt/live/gw.example/chain.pem
fullchain = /etc/letsencrypt/live/gw.example/fullchain.pem

# Options used in the renewal process
[renewalparams]
account = 0123456789abcdef
authenticator = standalone
server = https://acme-v02.api.letsencrypt.org/directory
key_type = ecdsa
`

// writeKeyPair 写出带域名的自签证书与私钥，NotBefore/NotAfter 可控。
func writeKeyPair(t *testing.T, certPath, keyPath string, notBefore, notAfter time.Time) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: "gw.example"},
		DNSNames:     []string{"gw.example"},
		NotBefore:    notBefore,
		NotAfter:     notAfter,
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(certPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600); err != nil {
		t.Fatal(err)
	}
	kb, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	if keyPath != "" {
		if err := os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: kb}), 0o600); err != nil {
			t.Fatal(err)
		}
	}
}

func TestWebrootConfMatchesCertbotFormat(t *testing.T) {
	got := webrootConf(kfcConf, "/var/lib/5gpn-next/acme", []string{"gw.example"})
	for _, want := range []string{
		"\nauthenticator = webroot\nwebroot_path = /var/lib/5gpn-next/acme,\nserver = ",
		"key_type = ecdsa\n[[webroot_map]]\ngw.example = /var/lib/5gpn-next/acme\n",
		"account = 0123456789abcdef\n",
	} {
		if !strings.Contains(got, want) {
			t.Fatalf("缺少 %q:\n%s", want, got)
		}
	}
	if strings.Contains(got, "standalone") {
		t.Fatalf("仍含 standalone:\n%s", got)
	}
}

// TestEnsureWebrootConvertsOnceAndRestores 只改 standalone；原配置备份，
// 回退时原样还原。
func TestEnsureWebrootConvertsOnceAndRestores(t *testing.T) {
	root := t.TempDir()
	live := filepath.Join(root, "live")
	// lineageName 依赖 liveDir 前缀，测试里直接用真实前缀拼出路径并改写读取位置。
	certFile := liveDir + "gw.example/fullchain.pem"
	confDir := filepath.Join(root, "renewal")
	webroot := filepath.Join(root, "acme")
	stage := filepath.Join(root, "stage")
	for _, d := range []string{live, confDir, stage} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	realCert := filepath.Join(live, "fullchain.pem")
	writeKeyPair(t, realCert, "", time.Now().Add(-time.Hour), time.Now().Add(80*24*time.Hour))
	conf := filepath.Join(confDir, "gw.example.conf")
	if err := os.WriteFile(conf, []byte(kfcConf), 0o644); err != nil {
		t.Fatal(err)
	}

	oldDomains := certDomainsFn
	certDomainsFn = func(string) ([]string, error) { return certDomains(realCert) }
	defer func() { certDomainsFn = oldDomains }()

	changed, err := ensureWebroot(context.Background(), certFile, confDir, webroot, stage, runBash)
	if err != nil || !changed {
		t.Fatalf("changed=%v err=%v", changed, err)
	}
	b, _ := os.ReadFile(conf)
	if !strings.Contains(string(b), "authenticator = webroot") {
		t.Fatalf("未改写:\n%s", b)
	}
	if bk, _ := os.ReadFile(conf + standaloneBackupSuffix); string(bk) != kfcConf {
		t.Fatalf("备份不是原配置:\n%s", bk)
	}
	if st, err := os.Stat(filepath.Join(webroot, ".well-known", "acme-challenge")); err != nil || !st.IsDir() {
		t.Fatalf("挑战目录未建立: %v", err)
	}
	if changed, err := ensureWebroot(context.Background(), certFile, confDir, webroot, stage, runBash); err != nil || changed {
		t.Fatalf("已是 webroot 时不应再改: changed=%v err=%v", changed, err)
	}

	if ok, err := restoreStandalone(context.Background(), certFile, confDir, runBash, stage); err != nil || !ok {
		t.Fatalf("还原失败: ok=%v err=%v", ok, err)
	}
	if b, _ := os.ReadFile(conf); string(b) != kfcConf {
		t.Fatalf("还原后内容不一致:\n%s", b)
	}
}

// TestEnsureWebrootLeavesUserWebrootAlone 用户自己配的 webroot（如 nginx）不动。
func TestEnsureWebrootLeavesUserWebrootAlone(t *testing.T) {
	root := t.TempDir()
	conf := filepath.Join(root, "gw.example.conf")
	orig := strings.Replace(kfcConf, "authenticator = standalone", "authenticator = webroot\nwebroot_path = /var/www/html,", 1)
	if err := os.WriteFile(conf, []byte(orig), 0o644); err != nil {
		t.Fatal(err)
	}
	changed, err := ensureWebroot(context.Background(), liveDir+"gw.example/fullchain.pem", root, filepath.Join(root, "acme"), root, runBash)
	if err != nil || changed {
		t.Fatalf("changed=%v err=%v", changed, err)
	}
	if b, _ := os.ReadFile(conf); string(b) != orig {
		t.Fatal("用户的 webroot 配置被改动")
	}
}

func TestCheckRenewal(t *testing.T) {
	now := time.Now()
	dir := t.TempDir()
	cert := filepath.Join(dir, "fullchain.pem")
	var sent []string
	w := &ExpiryWatcher{CertFile: cert, StateFile: filepath.Join(dir, "cert-alert"),
		Notify: func(s string) { sent = append(sent, s) }}
	stamp := func(name string, t time.Time) {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(strconv.FormatInt(t.Unix(), 10)), 0o600); err != nil {
			panic(err)
		}
	}

	// 剩 25 天、续期跑完证书仍是旧的：失败，告警一次。
	writeKeyPair(t, cert, "", now.Add(-65*24*time.Hour), now.Add(25*24*time.Hour))
	stamp("cert-renew-attempt", now.Add(-5*time.Minute))
	stamp("cert-renew-finished", now.Add(-4*time.Minute))
	if err := w.CheckRenewal(); err != nil {
		t.Fatal(err)
	}
	if len(sent) != 1 || !strings.Contains(sent[0], "续期失败") {
		t.Fatalf("sent = %v", sent)
	}
	if err := w.CheckRenewal(); err != nil || len(sent) != 1 {
		t.Fatalf("同一次失败不应重复告警: %v %v", err, sent)
	}

	// 续期成功：证书换新，发恢复通知。
	writeKeyPair(t, cert, "", now.Add(-time.Hour), now.Add(89*24*time.Hour))
	if err := w.CheckRenewal(); err != nil {
		t.Fatal(err)
	}
	if len(sent) != 2 || !strings.Contains(sent[1], "已续期") {
		t.Fatalf("sent = %v", sent)
	}

	// 证书还剩 60 天时 certbot 只是在续同机别的证书：不算失败。
	sent = nil
	writeKeyPair(t, cert, "", now.Add(-30*24*time.Hour), now.Add(60*24*time.Hour))
	if err := w.CheckRenewal(); err != nil || len(sent) != 0 {
		t.Fatalf("未到续期窗口不应告警: %v %v", err, sent)
	}
}

// TestKeyPairReloadsRenewedCert 续期后不重启也能用上新证书。
func TestKeyPairReloadsRenewedCert(t *testing.T) {
	dir := t.TempDir()
	cf, kf := filepath.Join(dir, "cert.pem"), filepath.Join(dir, "key.pem")
	writeKeyPair(t, cf, kf, time.Now().Add(-time.Hour), time.Now().Add(10*24*time.Hour))
	kp, err := LoadKeyPair(cf, kf)
	if err != nil {
		t.Fatal(err)
	}
	first, _ := kp.GetCertificate(&tls.ClientHelloInfo{})

	writeKeyPair(t, cf, kf, time.Now().Add(-time.Hour), time.Now().Add(90*24*time.Hour))
	future := time.Now().Add(time.Minute)
	if err := os.Chtimes(cf, future, future); err != nil {
		t.Fatal(err)
	}
	kp.checked = time.Time{}
	second, _ := kp.GetCertificate(&tls.ClientHelloInfo{})
	if second == first {
		t.Fatal("证书文件已更新却仍返回旧证书")
	}

	// 只换了一半（私钥对不上）时继续用当前证书，不能让握手失败。
	writeKeyPair(t, cf, "", time.Now().Add(-time.Hour), time.Now().Add(90*24*time.Hour))
	later := future.Add(time.Minute)
	_ = os.Chtimes(cf, later, later)
	kp.checked = time.Time{}
	third, err := kp.GetCertificate(&tls.ClientHelloInfo{})
	if err != nil || third != second {
		t.Fatal("新证书与私钥不匹配时应继续用旧证书")
	}
}
