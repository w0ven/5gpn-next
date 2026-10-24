package certrenew

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

// ACMEWebroot 是 webroot 续期的挑战目录。网关在 :80 直接应答其中的
// /.well-known/acme-challenge/ 文件，续期全程不用停服。
const ACMEWebroot = stateDir + "/acme"

const renewalDir = "/etc/letsencrypt/renewal"

// standaloneBackupSuffix 是改写前原配置的备份后缀。certbot 只读取
// renewal 目录下的 *.conf，这个后缀不会被当成另一张证书。
const standaloneBackupSuffix = ".5gpn-standalone"

var authenticatorLine = regexp.MustCompile(`(?m)^[ \t]*authenticator[ \t]*=[ \t]*(\S+)[ \t]*$`)

// EnsureWebroot 把证书的续期方式从 standalone 改为 webroot。
//
// standalone 要求 certbot 自己占用 :80，续期钩子只能先停网关，每次续期
// 断网十几秒；续期一旦连续失败，每天两次的重试就意味着每天断网两次。
// 只处理 standalone：用户自己配了 webroot（例如前面有 nginx）时不动。
// 原配置备份为 <name>.conf.5gpn-standalone，卸载与版本回退时还原。
func EnsureWebroot(ctx context.Context, certFile string) (bool, error) {
	return ensureWebroot(ctx, certFile, renewalDir, ACMEWebroot, stateDir, runOutsideSandbox)
}

func ensureWebroot(ctx context.Context, certFile, confDir, webroot, stage string, run func(context.Context, string) error) (bool, error) {
	name, ok := lineageName(certFile)
	if !ok {
		return false, nil
	}
	conf := filepath.Join(confDir, name+".conf")
	raw, err := os.ReadFile(conf)
	if err != nil {
		if os.IsNotExist(err) {
			return false, nil
		}
		return false, err
	}
	m := authenticatorLine.FindSubmatch(raw)
	if m == nil || string(m[1]) != "standalone" {
		return false, nil
	}
	domains, err := certDomainsFn(certFile)
	if err != nil {
		return false, err
	}
	if err := os.MkdirAll(filepath.Join(webroot, ".well-known", "acme-challenge"), 0o755); err != nil {
		return false, err
	}
	next := webrootConf(string(raw), webroot, domains)

	tmp, err := os.MkdirTemp(stage, "certconf-")
	if err != nil {
		return false, err
	}
	defer os.RemoveAll(tmp)
	src := filepath.Join(tmp, "renewal.conf")
	if err := os.WriteFile(src, []byte(next), 0o600); err != nil {
		return false, err
	}
	backup := conf + standaloneBackupSuffix
	script := fmt.Sprintf("#!/bin/bash\nset -eu\n[ -e %s ] || cp -p %s %s\ninstall -m 644 %s %s\n",
		shellQuote(backup), shellQuote(conf), shellQuote(backup), shellQuote(src), shellQuote(conf))
	scriptPath := filepath.Join(tmp, "install.sh")
	if err := os.WriteFile(scriptPath, []byte(script), 0o700); err != nil {
		return false, err
	}
	if err := run(ctx, scriptPath); err != nil {
		return false, err
	}
	got, err := os.ReadFile(conf)
	if err != nil || string(got) != next {
		return true, fmt.Errorf("续期配置写入后校验不一致")
	}
	return true, nil
}

// RestoreStandalone 还原改写前的续期配置。回退到不会应答 webroot 挑战的
// 旧版本前必须调用，否则旧版续期时既不停服、也没人应答，续期必然失败。
func RestoreStandalone(ctx context.Context, certFile string) (bool, error) {
	return restoreStandalone(ctx, certFile, renewalDir, runOutsideSandbox, stateDir)
}

func restoreStandalone(ctx context.Context, certFile, confDir string, run func(context.Context, string) error, stage string) (bool, error) {
	name, ok := lineageName(certFile)
	if !ok {
		return false, nil
	}
	conf := filepath.Join(confDir, name+".conf")
	backup := conf + standaloneBackupSuffix
	if _, err := os.Stat(backup); err != nil {
		return false, nil
	}
	tmp, err := os.MkdirTemp(stage, "certconf-")
	if err != nil {
		return false, err
	}
	defer os.RemoveAll(tmp)
	scriptPath := filepath.Join(tmp, "restore.sh")
	script := fmt.Sprintf("#!/bin/bash\nset -eu\nmv -f %s %s\n", shellQuote(backup), shellQuote(conf))
	if err := os.WriteFile(scriptPath, []byte(script), 0o700); err != nil {
		return false, err
	}
	if err := run(ctx, scriptPath); err != nil {
		return false, err
	}
	return true, nil
}

// webrootConf 把 [renewalparams] 里的 standalone 换成 webroot，并按 certbot
// 自己写出的格式补上 webroot_path 与 [[webroot_map]]。
func webrootConf(raw, webroot string, domains []string) string {
	out := authenticatorLine.ReplaceAllString(raw,
		"authenticator = webroot\nwebroot_path = "+webroot+",")
	out = strings.TrimRight(out, "\n") + "\n[[webroot_map]]\n"
	for _, d := range domains {
		out += d + " = " + webroot + "\n"
	}
	return out
}

func lineageName(certFile string) (string, bool) {
	clean := filepath.Clean(certFile)
	if !strings.HasPrefix(clean, liveDir) {
		return "", false
	}
	name, _, ok := strings.Cut(strings.TrimPrefix(clean, liveDir), "/")
	return name, ok && name != ""
}

var certDomainsFn = certDomains

func certDomains(path string) ([]string, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(raw)
	if block == nil {
		return nil, fmt.Errorf("%s 不是 PEM 证书", path)
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, err
	}
	if len(cert.DNSNames) == 0 {
		return nil, fmt.Errorf("证书 %s 没有域名", path)
	}
	return cert.DNSNames, nil
}
