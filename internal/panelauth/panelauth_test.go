package panelauth

import (
	"testing"
	"time"
)

func TestTokenIsSingleUseAndExpires(t *testing.T) {
	s := New(t.TempDir())
	tok, err := s.IssueToken()
	if err != nil {
		t.Fatal(err)
	}
	sid, err := s.Redeem(tok)
	if err != nil {
		t.Fatal(err)
	}
	if !s.Valid(sid) {
		t.Fatal("兑换后的会话应有效")
	}
	if _, err := s.Redeem(tok); err == nil {
		t.Fatal("同一链接不能用第二次")
	}

	now := time.Now()
	s.now = func() time.Time { return now }
	old, _ := s.IssueToken()
	s.now = func() time.Time { return now.Add(TokenTTL + time.Second) }
	if _, err := s.Redeem(old); err == nil {
		t.Fatal("过期链接应拒绝")
	}
}

func TestSessionSurvivesRestartAndRevoke(t *testing.T) {
	dir := t.TempDir()
	s := New(dir)
	tok, _ := s.IssueToken()
	sid, err := s.Redeem(tok)
	if err != nil {
		t.Fatal(err)
	}
	restarted := New(dir)
	if !restarted.Valid(sid) {
		t.Fatal("重启后会话应仍有效")
	}
	restarted.Revoke(sid)
	if New(dir).Valid(sid) {
		t.Fatal("注销后会话应失效")
	}
	if s2 := New(dir); s2.Valid("") || s2.Valid("zz") || s2.Valid(tok) {
		t.Fatal("非法或非会话值不应通过")
	}
}

func TestSessionExpires(t *testing.T) {
	s := New(t.TempDir())
	tok, _ := s.IssueToken()
	sid, _ := s.Redeem(tok)
	s.now = func() time.Time { return time.Now().Add(SessionTTL + time.Hour) }
	if s.Valid(sid) {
		t.Fatal("会话过期后应失效")
	}
}
