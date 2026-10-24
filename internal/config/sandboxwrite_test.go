package config

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestWriteFileSandboxSafeKeepsContentOffCommandLine 沙箱外代写时，内容
// 只能经暂存文件传递：systemd 会把 transient unit 的命令行写进日志。
func TestWriteFileSandboxSafeKeepsContentOffCommandLine(t *testing.T) {
	stage := t.TempDir()
	oldStage, oldRun := SandboxStageDir, runSystemd
	defer func() { SandboxStageDir, runSystemd = oldStage, oldRun }()
	SandboxStageDir = stage

	secret := `{"bot":{"token":"123456:SECRET-TOKEN"}}`
	var args []string
	var staged string
	runSystemd = func(_ context.Context, a ...string) ([]byte, error) {
		args = a
		ents, _ := os.ReadDir(stage)
		for _, e := range ents {
			b, _ := os.ReadFile(filepath.Join(stage, e.Name()))
			staged = string(b)
		}
		return nil, nil
	}

	target := filepath.Join(t.TempDir(), "missing-dir", "config.json")
	if err := WriteFileSandboxSafe(target, []byte(secret), 0o600); err != nil {
		t.Fatal(err)
	}
	joined := strings.Join(args, " ")
	if strings.Contains(joined, "SECRET") || strings.Contains(joined, "eyJ") {
		t.Fatalf("命令行带出了内容: %s", joined)
	}
	if !strings.Contains(joined, "--description=") {
		t.Fatalf("缺少 --description，systemd 会用命令行当描述: %s", joined)
	}
	if staged != secret {
		t.Fatalf("暂存文件内容 = %q", staged)
	}
	if ents, _ := os.ReadDir(stage); len(ents) != 0 {
		t.Fatalf("暂存文件未清理: %v", ents)
	}
}
