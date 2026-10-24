// Package panelauth 管理内网面板的登录：一次性登录链接与浏览器会话。
//
// 面板只对客户端网段开放，但这个网段里不一定只有管理员自己的设备，
// 面板又能切换出口、添加节点。查看保持免登录，修改需要先用 Bot 或
// 服务器命令行签发的一次性链接登录。
package panelauth

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"
)

// DefaultDir 是登录状态目录。命令行签发链接与网关进程共用它。
const DefaultDir = "/var/lib/5gpn-next/panel-auth"

const (
	// TokenTTL 是一次性登录链接的有效期。
	TokenTTL = 10 * time.Minute
	// SessionTTL 是登录后浏览器会话的有效期。
	SessionTTL = 30 * 24 * time.Hour
	// CookieName 是会话 Cookie 名。
	CookieName = "5gpn_session"
)

// ErrInvalidToken 表示登录链接无效、已用过或已过期。
var ErrInvalidToken = errors.New("登录链接无效或已过期")

// Store 保存一次性令牌（文件，跨进程）与会话（内存 + 落盘，重启不掉线）。
// 磁盘上只存令牌和会话的 SHA-256，不存原文。
type Store struct {
	Dir string

	mu       sync.Mutex
	sessions map[string]time.Time
	loaded   bool
	now      func() time.Time
}

// New 构造 Store。
func New(dir string) *Store { return &Store{Dir: dir} }

func (s *Store) clock() time.Time {
	if s.now != nil {
		return s.now()
	}
	return time.Now()
}

// IssueToken 签发一次性登录令牌，返回原文。
func (s *Store) IssueToken() (string, error) {
	tok, err := randomHex(24)
	if err != nil {
		return "", err
	}
	dir := filepath.Join(s.Dir, "tokens")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", err
	}
	exp := strconv.FormatInt(s.clock().Add(TokenTTL).Unix(), 10)
	if err := os.WriteFile(filepath.Join(dir, digest(tok)), []byte(exp), 0o600); err != nil {
		return "", err
	}
	s.pruneTokens(dir)
	return tok, nil
}

// Redeem 兑换一次性令牌并建立会话，返回会话原文（写进 Cookie）。
func (s *Store) Redeem(tok string) (string, error) {
	if !isHex(tok) {
		return "", ErrInvalidToken
	}
	path := filepath.Join(s.Dir, "tokens", digest(tok))
	raw, err := os.ReadFile(path)
	if err != nil {
		return "", ErrInvalidToken
	}
	// 先删再判断：同一链接只能用一次，即使已过期。
	if err := os.Remove(path); err != nil {
		return "", ErrInvalidToken
	}
	exp, err := strconv.ParseInt(strings.TrimSpace(string(raw)), 10, 64)
	if err != nil || s.clock().Unix() > exp {
		return "", ErrInvalidToken
	}
	sid, err := randomHex(32)
	if err != nil {
		return "", err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.loadLocked()
	s.sessions[digest(sid)] = s.clock().Add(SessionTTL)
	s.saveLocked()
	return sid, nil
}

// Valid 报告会话是否有效。
func (s *Store) Valid(sid string) bool {
	if !isHex(sid) {
		return false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.loadLocked()
	exp, ok := s.sessions[digest(sid)]
	return ok && s.clock().Before(exp)
}

// Revoke 注销会话。
func (s *Store) Revoke(sid string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.loadLocked()
	if _, ok := s.sessions[digest(sid)]; ok {
		delete(s.sessions, digest(sid))
		s.saveLocked()
	}
}

func (s *Store) loadLocked() {
	if s.loaded {
		return
	}
	s.loaded = true
	s.sessions = map[string]time.Time{}
	if b, err := os.ReadFile(filepath.Join(s.Dir, "sessions.json")); err == nil {
		_ = json.Unmarshal(b, &s.sessions)
	}
}

func (s *Store) saveLocked() {
	now := s.clock()
	for k, exp := range s.sessions {
		if now.After(exp) {
			delete(s.sessions, k)
		}
	}
	b, err := json.Marshal(s.sessions)
	if err != nil || os.MkdirAll(s.Dir, 0o700) != nil {
		return
	}
	path := filepath.Join(s.Dir, "sessions.json")
	if os.WriteFile(path+".tmp", b, 0o600) == nil {
		_ = os.Rename(path+".tmp", path)
	}
}

// pruneTokens 清掉过期未用的令牌文件。
func (s *Store) pruneTokens(dir string) {
	ents, err := os.ReadDir(dir)
	if err != nil {
		return
	}
	now := s.clock().Unix()
	for _, e := range ents {
		p := filepath.Join(dir, e.Name())
		raw, err := os.ReadFile(p)
		if err != nil {
			continue
		}
		if exp, err := strconv.ParseInt(strings.TrimSpace(string(raw)), 10, 64); err != nil || now > exp {
			_ = os.Remove(p)
		}
	}
}

func randomHex(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

func digest(s string) string {
	h := sha256.Sum256([]byte(s))
	return hex.EncodeToString(h[:])
}

func isHex(s string) bool {
	if s == "" || len(s) > 128 {
		return false
	}
	_, err := hex.DecodeString(s)
	return err == nil
}
