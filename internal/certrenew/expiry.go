package certrenew

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io/fs"
	"log"
	"os"
	"strconv"
	"strings"
	"time"
)

// WarnDays 是主动告警阈值。certbot 在剩余 30 天时开始续期，
// 剩 14 天仍未续上说明自动续期已连续失败两周。
const WarnDays = 14

// AlertStateFile 记录上次告警时间。续期失败时 certbot 钩子每天会重启
// 网关两次，只靠内存去重会在每次重启后重复推送。
const AlertStateFile = stateDir + "/cert-alert"

const remindEvery = 20 * time.Hour

// NotAfter 读取 PEM 证书链中首张证书的到期时间。
func NotAfter(path string) (time.Time, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return time.Time{}, err
	}
	block, _ := pem.Decode(raw)
	if block == nil || block.Type != "CERTIFICATE" {
		return time.Time{}, fmt.Errorf("%s 不是 PEM 证书", path)
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return time.Time{}, err
	}
	return cert.NotAfter, nil
}

// ExpiryWatcher 在证书临近或已经过期时主动告警，续期后发一次恢复通知。
type ExpiryWatcher struct {
	CertFile  string
	StateFile string
	Notify    func(text string)

	now func() time.Time
}

// Run 在 first 之后首次检查，此后按 interval 周期检查，直到 ctx 结束。
func (w *ExpiryWatcher) Run(ctx context.Context, first, interval time.Duration) {
	wait := first
	for {
		select {
		case <-ctx.Done():
			return
		case <-time.After(wait):
		}
		if err := w.Check(); err != nil {
			log.Printf("证书到期检查失败: %v", err)
		}
		wait = interval
	}
}

// Check 执行一次检查。
func (w *ExpiryWatcher) Check() error {
	notAfter, err := NotAfter(w.CertFile)
	if err != nil {
		return err
	}
	now := time.Now()
	if w.now != nil {
		now = w.now()
	}
	left := notAfter.Sub(now)
	last, alerted, err := w.lastAlert()
	if err != nil {
		return err
	}

	if left > WarnDays*24*time.Hour {
		if !alerted {
			return nil
		}
		if err := os.Remove(w.StateFile); err != nil && !errors.Is(err, fs.ErrNotExist) {
			return err
		}
		w.Notify(fmt.Sprintf("✅ <b>网关证书已续期</b>\n\n有效期至 <code>%s</code>", notAfter.Format("2006-01-02")))
		return nil
	}
	if alerted && now.Sub(last) < remindEvery {
		return nil
	}
	if err := os.WriteFile(w.StateFile, []byte(strconv.FormatInt(now.Unix(), 10)), 0o600); err != nil {
		return err
	}
	w.Notify(expiryText(left, notAfter))
	return nil
}

func (w *ExpiryWatcher) lastAlert() (time.Time, bool, error) {
	raw, err := os.ReadFile(w.StateFile)
	if errors.Is(err, fs.ErrNotExist) {
		return time.Time{}, false, nil
	}
	if err != nil {
		return time.Time{}, false, err
	}
	sec, err := strconv.ParseInt(strings.TrimSpace(string(raw)), 10, 64)
	if err != nil {
		// 内容损坏时视为已告警但需要立即重新提醒。
		return time.Time{}, true, nil
	}
	return time.Unix(sec, 0), true, nil
}

func expiryText(left time.Duration, notAfter time.Time) string {
	date := notAfter.Format("2006-01-02")
	if left <= 0 {
		return fmt.Sprintf("🚨 <b>网关证书已过期</b>\n\n"+
			"已于 <code>%s</code> 过期。手机加密 DNS 握手会全部失败，"+
			"除 Telegram 等直连 IP 的应用外都会断网。\n\n"+
			"请在服务器上执行 <code>certbot renew</code>，"+
			"并查看 <code>/var/log/letsencrypt/letsencrypt.log</code>。", date)
	}
	when := fmt.Sprintf("%d 天后", int(left.Hours()/24))
	if left < 24*time.Hour {
		when = "24 小时内"
	}
	return fmt.Sprintf("⚠️ <b>网关证书%s过期</b>\n\n"+
		"到期 <code>%s</code>。certbot 本应在剩余 30 天时自动续期，"+
		"说明续期一直在失败。\n\n"+
		"请在服务器上执行 <code>certbot renew --dry-run</code> 排查。", when, date)
}
