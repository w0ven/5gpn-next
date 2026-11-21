package fw

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestCleanPortsDeduplicatesAndRejectsInvalid(t *testing.T) {
	got := cleanPorts([]int{443, 80, 443, 0, -1, 65536, 853})
	want := []int{80, 443, 853}
	if len(got) != len(want) {
		t.Fatalf("ports=%v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("ports=%v, want %v", got, want)
		}
	}
}

func TestEnsureIngressRestrictionsMigratesLegacyAllowOnlyRules(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "calls")
	script := `#!/bin/sh
if [ "$1" = "-a" ]; then
cat <<'EOF'
table inet fgpn {
  chain input {
    type filter hook input priority filter - 10; policy accept;
    ip saddr 172.22.0.0/16 tcp dport 20443 accept comment "5gpn-next" # handle 2
    ip saddr 172.22.0.0/16 tcp dport { 53, 80, 443, 853 } accept comment "5gpn-android" # handle 4
    ip saddr 172.22.0.0/16 udp dport 443 accept comment "5gpn-quic-takeover" # handle 7
  }
}
EOF
exit 0
fi
printf '%s\n' "$*" >> "$NFT_TEST_LOG"
`
	fake := filepath.Join(dir, "nft")
	if err := os.WriteFile(fake, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir+":/usr/bin:/bin")
	t.Setenv("NFT_TEST_LOG", logPath)

	changed, err := EnsureIngressRestrictions(context.Background(), "172.22.0.0/16",
		[]int{20443, 80, 443, 853}, []int{443})
	if err != nil {
		t.Fatal(err)
	}
	if !changed {
		t.Fatal("legacy allow-only rules should receive public drop rules")
	}
	b, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatal(err)
	}
	calls := string(b)
	for _, port := range []string{"80", "443", "853", "20443"} {
		if !strings.Contains(calls, "tcp dport "+port+" drop") {
			t.Fatalf("missing tcp/%s drop in calls:\n%s", port, calls)
		}
	}
	if !strings.Contains(calls, "udp dport 443 drop") {
		t.Fatalf("missing udp/443 drop in calls:\n%s", calls)
	}
	if !strings.Contains(calls, `iif lo accept comment "5gpn-loopback"`) {
		t.Fatalf("missing loopback accept in calls:\n%s", calls)
	}
	if strings.Contains(calls, " saddr ") {
		t.Fatalf("legacy client allows should not be duplicated:\n%s", calls)
	}
}

func TestEnsureQUICAcceptRemovesLegacyAndroidQuicAndPDG(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "calls")
	script := `#!/bin/sh
if [ "$1" = "-a" ] && [ "$5" = "fgpn" ]; then
cat <<'EOF'
table inet fgpn {
  chain input {
    type filter hook input priority filter - 10; policy accept;
    ip saddr 172.22.0.0/16 udp dport 443 accept comment "5gpn-quic-takeover" # handle 12
    ip saddr 172.22.0.0/16 udp dport 443 reject with icmp port-unreachable comment "5gpn-android-quic" # handle 6
    udp dport 443 drop comment "5gpn-runtime-deny-udp-443" # handle 11
  }
}
EOF
exit 0
fi
if [ "$1" = "-a" ] && [ "$5" = "pdg" ]; then
cat <<'EOF'
table inet pdg {
  chain input {
    type filter hook input priority filter; policy drop;
    iif "lo" accept # handle 2
    ip saddr 172.22.0.0/16 udp dport 443 reject with icmp port-unreachable # handle 8
  }
}
EOF
exit 0
fi
printf '%s\n' "$*" >> "$NFT_TEST_LOG"
`
	fake := filepath.Join(dir, "nft")
	if err := os.WriteFile(fake, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir+":/usr/bin:/bin")
	t.Setenv("NFT_TEST_LOG", logPath)

	changed, err := EnsureQUICAccept(context.Background(), "172.22.0.0/16")
	if err != nil {
		t.Fatal(err)
	}
	if !changed {
		t.Fatal("expected legacy android-quic and pdg rules to be updated")
	}
	b, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatal(err)
	}
	calls := string(b)
	for _, want := range []string{
		"delete rule inet fgpn input handle 6",
		`insert rule inet pdg input ip saddr 172.22.0.0/16 udp dport 443 accept comment "5gpn-quic-takeover"`,
		"delete rule inet pdg input handle 8",
	} {
		if !strings.Contains(calls, want) {
			t.Fatalf("missing %q in calls:\n%s", want, calls)
		}
	}
}

func TestEnsureIngressRestrictionsAllowsPanelPortInLegacyPDG(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "calls")
	script := `#!/bin/sh
if [ "$1" = "-a" ] && [ "$5" = "fgpn" ]; then
cat <<'EOF'
table inet fgpn {
  chain input {
    type filter hook input priority filter - 10; policy accept;
    iif "lo" accept comment "5gpn-loopback" # handle 1
    ip saddr 172.22.0.0/16 tcp dport 20443 accept comment "5gpn-next" # handle 2
    ip saddr 172.22.0.0/16 tcp dport { 80, 443, 853 } accept comment "5gpn-dns" # handle 3
    ip saddr 172.22.0.0/16 udp dport 443 accept comment "5gpn-quic-takeover" # handle 4
    tcp dport { 80, 443, 853 } drop comment "5gpn-deny-public-tcp" # handle 5
    udp dport 443 drop comment "5gpn-deny-public-udp" # handle 6
    tcp dport 20443 drop comment "5gpn-deny-public-panel" # handle 7
  }
}
EOF
exit 0
fi
if [ "$1" = "-a" ] && [ "$5" = "pdg" ]; then
cat <<'EOF'
table inet pdg {
  chain input {
    type filter hook input priority filter; policy drop;
    iif "lo" accept # handle 2
    ip saddr 172.22.0.0/16 tcp dport { 53, 80, 81, 443, 853, 8445 } accept # handle 5
  }
}
EOF
exit 0
fi
printf '%s\n' "$*" >> "$NFT_TEST_LOG"
`
	fake := filepath.Join(dir, "nft")
	if err := os.WriteFile(fake, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir+":/usr/bin:/bin")
	t.Setenv("NFT_TEST_LOG", logPath)

	changed, err := EnsureIngressRestrictions(context.Background(), "172.22.0.0/16",
		[]int{20443, 80, 443, 853}, []int{443})
	if err != nil {
		t.Fatal(err)
	}
	if !changed {
		t.Fatal("expected missing 20443 in legacy pdg table to be added")
	}
	b, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatal(err)
	}
	calls := string(b)
	want := `insert rule inet pdg input ip saddr 172.22.0.0/16 tcp dport 20443 accept comment "5gpn-runtime-allow-tcp-20443"`
	if strings.TrimSpace(calls) != want {
		t.Fatalf("unexpected calls:\ngot:  %s\nwant: %s", strings.TrimSpace(calls), want)
	}
}
