// Package certrenew 维护 Let's Encrypt 续期钩子，并在证书临近过期时主动告警。
//
// 自更新只替换二进制，不会重跑 install.sh，老机器上的续期钩子因此停留在
// 安装当时的版本。新版启动时会把公网 TCP/80 纳入兜底 drop，旧钩子只停服
// 让出端口、不放行 ACME，续期必然超时失败；证书过期后 DoT 握手全部失败，
// 手机侧表现为除 Telegram 等直连 IP 的应用外全部断网。
package certrenew

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

const (
	hooksDir = "/etc/letsencrypt/renewal-hooks"
	liveDir  = "/etc/letsencrypt/live/"
	stateDir = "/var/lib/5gpn-next"
	hookName = "5gpn-next.sh"
)

// 以下三段必须与 install.sh 写出的钩子逐字节一致，由测试校验。

// PreHook 续期前临时放行公网 ACME；仅在仍有 standalone 续期时停服让出 :80。
const PreHook = `#!/bin/bash
# 续期前把 ACME 临时放行插到公网兜底 drop 之前。网关自己在 :80 应答
# webroot 挑战，不用停服；只有续期配置仍是 standalone（certbot 要自己
# 占用 :80）时才停服让出端口，并记录状态以便续期后恢复。
set -u
STATE=/run/5gpn-next-cert-renew.state
date +%s > /var/lib/5gpn-next/cert-renew-attempt 2>/dev/null || true
rm_rules() {
  local handle
  while read -r handle; do
    [ -n "$handle" ] || continue
    nft delete rule inet fgpn input handle "$handle" 2>/dev/null || true
  done < <(nft -a list chain inet fgpn input 2>/dev/null \
    | awk '/comment "5gpn-acme-tmp"/ { for (i=1; i<=NF; i++) if ($i=="handle") print $(i+1) }')
}
rm_rules
if grep -qsE '^[[:space:]]*authenticator[[:space:]]*=[[:space:]]*standalone' /etc/letsencrypt/renewal/*.conf \
  && systemctl is-active --quiet 5gpn-next.service; then
  echo stopped-by-certbot > "$STATE"
  systemctl stop 5gpn-next.service
else
  rm -f "$STATE"
fi
if nft list chain inet fgpn input >/dev/null 2>&1; then
  if ! nft insert rule inet fgpn input tcp dport 80 accept comment '"5gpn-acme-tmp"'; then
    [ -f "$STATE" ] && systemctl start 5gpn-next.service || true
    rm -f "$STATE"
    exit 1
  fi
fi
exit 0
`

// PostHook 收回 ACME 临时放行，恢复被停的网关，并记录本次续期已结束。
const PostHook = `#!/bin/bash
# 无论续期成功与否都先收回 ACME 临时公网放行，再恢复网关服务。
set -u
STATE=/run/5gpn-next-cert-renew.state
date +%s > /var/lib/5gpn-next/cert-renew-finished 2>/dev/null || true
while read -r handle; do
  [ -n "$handle" ] || continue
  nft delete rule inet fgpn input handle "$handle" 2>/dev/null || true
done < <(nft -a list chain inet fgpn input 2>/dev/null \
  | awk '/comment "5gpn-acme-tmp"/ { for (i=1; i<=NF; i++) if ($i=="handle") print $(i+1) }')
if [ -f "$STATE" ]; then
  rm -f "$STATE"
  systemctl start 5gpn-next.service || true
fi
# 兜底：状态文件异常丢失但服务已停时仍尝试拉起。
if ! systemctl is-active --quiet 5gpn-next.service; then
  systemctl start 5gpn-next.service || true
fi
exit 0
`

// DeployHook 无需动作：网关检测到证书文件变化后自行加载新证书。
const DeployHook = `#!/bin/bash
# 网关会检测证书文件变化并自动加载新证书，无需重启。
exit 0
`

var hooks = []struct{ kind, body string }{
	{"pre", PreHook},
	{"post", PostHook},
	{"deploy", DeployHook},
}

// EnsureHooks 在证书由 certbot 管理时把续期钩子更新为当前版本。
// 内容一致时不做任何改动；只有确实写入过才返回 changed=true。
func EnsureHooks(ctx context.Context, certFile string) (changed bool, err error) {
	if certFile == "" || !strings.HasPrefix(filepath.Clean(certFile), liveDir) {
		return false, nil
	}
	return ensureHooks(ctx, hooksDir, stateDir, runOutsideSandbox)
}

func ensureHooks(ctx context.Context, dir, stage string, run func(context.Context, string) error) (bool, error) {
	if st, err := os.Stat(dir); err != nil || !st.IsDir() {
		return false, nil
	}
	var stale []int
	for i, h := range hooks {
		got, err := os.ReadFile(filepath.Join(dir, h.kind, hookName))
		if err == nil && string(got) == h.body {
			continue
		}
		if err != nil && !errors.Is(err, fs.ErrNotExist) {
			return false, err
		}
		stale = append(stale, i)
	}
	if len(stale) == 0 {
		return false, nil
	}

	// staging 必须在 ReadWritePaths 下：服务开启了 PrivateTmp，
	// 沙箱外的 systemd-run 看不到私有 /tmp。
	tmp, err := os.MkdirTemp(stage, "certhooks-")
	if err != nil {
		return false, err
	}
	defer os.RemoveAll(tmp)
	var script strings.Builder
	script.WriteString("#!/bin/bash\nset -eu\n")
	for _, i := range stale {
		h := hooks[i]
		src := filepath.Join(tmp, h.kind+".sh")
		if err := os.WriteFile(src, []byte(h.body), 0o600); err != nil {
			return false, err
		}
		dst := filepath.Join(dir, h.kind, hookName)
		fmt.Fprintf(&script, "install -d -m 755 %s\ninstall -m 755 %s %s\n",
			shellQuote(filepath.Dir(dst)), shellQuote(src), shellQuote(dst))
	}
	scriptPath := filepath.Join(tmp, "install.sh")
	if err := os.WriteFile(scriptPath, []byte(script.String()), 0o700); err != nil {
		return false, err
	}
	if err := run(ctx, scriptPath); err != nil {
		return false, err
	}
	for _, i := range stale {
		h := hooks[i]
		got, err := os.ReadFile(filepath.Join(dir, h.kind, hookName))
		if err != nil || string(got) != h.body {
			return true, fmt.Errorf("%s 钩子写入后校验不一致", h.kind)
		}
	}
	return true, nil
}

// runOutsideSandbox 经由 transient unit 执行脚本：服务单元的
// ProtectSystem=full 让进程内的 /etc 只读。
func runOutsideSandbox(ctx context.Context, script string) error {
	unit := fmt.Sprintf("5gpn-next-certhooks-%d", time.Now().UnixNano())
	out, err := exec.CommandContext(ctx, "systemd-run",
		"--quiet", "--collect", "--wait",
		"--unit="+unit,
		"--property=Type=oneshot",
		"/bin/bash", script).CombinedOutput()
	if err != nil {
		return fmt.Errorf("systemd-run 更新续期钩子失败: %v: %s", err, strings.TrimSpace(string(out)))
	}
	return nil
}

func shellQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", "'\\''") + "'"
}
