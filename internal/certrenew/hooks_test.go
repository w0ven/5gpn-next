package certrenew

import (
	"bufio"
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// installerHook 从 install.sh 中取出写入指定钩子的 heredoc 正文。
func installerHook(t *testing.T, kind string) string {
	t.Helper()
	f, err := os.Open("../../install.sh")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	start := "cat > /etc/letsencrypt/renewal-hooks/" + kind + "/5gpn-next.sh <<'EOF'"
	var body strings.Builder
	in := false
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := sc.Text()
		switch {
		case line == start:
			in = true
		case in && line == "EOF":
			return body.String()
		case in:
			body.WriteString(line + "\n")
		}
	}
	t.Fatalf("install.sh 中找不到 %s 钩子", kind)
	return ""
}

func TestHooksMatchInstaller(t *testing.T) {
	for _, h := range hooks {
		if got := installerHook(t, h.kind); got != h.body {
			t.Errorf("%s 钩子与 install.sh 不一致：两处必须同步修改", h.kind)
		}
	}
}

func TestPreHookOpensACMEPort(t *testing.T) {
	if !strings.Contains(PreHook, `tcp dport 80 accept comment '"5gpn-acme-tmp"'`) {
		t.Fatal("pre 钩子必须临时放行公网 80，否则公网兜底 drop 会让 HTTP-01 超时")
	}
	if !strings.Contains(PostHook, `5gpn-acme-tmp`) {
		t.Fatal("post 钩子必须收回 ACME 临时放行")
	}
}

func runBash(ctx context.Context, script string) error {
	return exec.CommandContext(ctx, "/bin/bash", script).Run()
}

func TestEnsureHooksReplacesStale(t *testing.T) {
	dir := t.TempDir()
	stage := t.TempDir()
	for _, kind := range []string{"pre", "post", "deploy"} {
		if err := os.MkdirAll(filepath.Join(dir, kind), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	// 生产老机器的状态：pre 只停服不放行，deploy 已是新版，post 缺失。
	oldPre := "#!/bin/bash\nsystemctl stop 5gpn-next.service\nexit 0\n"
	if err := os.WriteFile(filepath.Join(dir, "pre", hookName), []byte(oldPre), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "deploy", hookName), []byte(DeployHook), 0o755); err != nil {
		t.Fatal(err)
	}
	other := filepath.Join(dir, "deploy", "99-other.sh")
	if err := os.WriteFile(other, []byte("#!/bin/bash\n"), 0o755); err != nil {
		t.Fatal(err)
	}

	changed, err := ensureHooks(context.Background(), dir, stage, runBash)
	if err != nil {
		t.Fatal(err)
	}
	if !changed {
		t.Fatal("存在旧钩子时应返回 changed=true")
	}
	for _, h := range hooks {
		p := filepath.Join(dir, h.kind, hookName)
		got, err := os.ReadFile(p)
		if err != nil {
			t.Fatal(err)
		}
		if string(got) != h.body {
			t.Errorf("%s 钩子未更新为当前版本", h.kind)
		}
		st, _ := os.Stat(p)
		if st.Mode().Perm() != 0o755 {
			t.Errorf("%s 钩子权限 %v，certbot 需要可执行", h.kind, st.Mode().Perm())
		}
	}
	if _, err := os.Stat(other); err != nil {
		t.Fatal("不应触碰其它项目的钩子")
	}
	if left, _ := os.ReadDir(stage); len(left) != 0 {
		t.Fatalf("staging 未清理: %d 项", len(left))
	}

	called := false
	changed, err = ensureHooks(context.Background(), dir, stage, func(context.Context, string) error {
		called = true
		return nil
	})
	if err != nil || changed || called {
		t.Fatalf("钩子已是当前版本时不应改动: changed=%v called=%v err=%v", changed, called, err)
	}
}

func TestEnsureHooksSkipsWithoutCertbot(t *testing.T) {
	called := false
	run := func(context.Context, string) error {
		called = true
		return nil
	}
	changed, err := ensureHooks(context.Background(), filepath.Join(t.TempDir(), "missing"), t.TempDir(), run)
	if err != nil || changed || called {
		t.Fatalf("没有 renewal-hooks 目录时不应改动: changed=%v called=%v err=%v", changed, called, err)
	}

	for _, cert := range []string{"", "/etc/5gpn-next/fullchain.pem", "/etc/letsencrypt/livex/a/fullchain.pem"} {
		changed, err := EnsureHooks(context.Background(), cert)
		if err != nil || changed {
			t.Errorf("非 certbot 证书 %q 不应处理: changed=%v err=%v", cert, changed, err)
		}
	}
}
