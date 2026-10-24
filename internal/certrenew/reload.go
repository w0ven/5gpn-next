package certrenew

import (
	"crypto/tls"
	"log"
	"os"
	"sync"
	"time"
)

// KeyPair 按需重新加载证书：续期后不必重启网关。
//
// 每次握手最多每 reloadEvery 检查一次文件修改时间，变化了才重新解析；
// 新文件解析失败（例如证书与私钥只换了一半）时继续用旧证书。
type KeyPair struct {
	certFile, keyFile string

	mu      sync.Mutex
	cert    *tls.Certificate
	mtime   time.Time
	checked time.Time
}

const reloadEvery = 30 * time.Second

// LoadKeyPair 首次加载证书；失败直接返回错误，与 tls.LoadX509KeyPair 一致。
func LoadKeyPair(certFile, keyFile string) (*KeyPair, error) {
	c, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return nil, err
	}
	kp := &KeyPair{certFile: certFile, keyFile: keyFile, cert: &c, checked: time.Now()}
	kp.mtime = kp.newestMTime()
	return kp, nil
}

// GetCertificate 供 tls.Config.GetCertificate 使用。
func (kp *KeyPair) GetCertificate(*tls.ClientHelloInfo) (*tls.Certificate, error) {
	kp.mu.Lock()
	defer kp.mu.Unlock()
	if time.Since(kp.checked) < reloadEvery {
		return kp.cert, nil
	}
	kp.checked = time.Now()
	mt := kp.newestMTime()
	if mt.IsZero() || !mt.After(kp.mtime) {
		return kp.cert, nil
	}
	c, err := tls.LoadX509KeyPair(kp.certFile, kp.keyFile)
	if err != nil {
		log.Printf("证书文件已变化但加载失败，继续使用旧证书: %v", err)
		return kp.cert, nil
	}
	kp.cert, kp.mtime = &c, mt
	log.Printf("已加载续期后的新证书 %s", kp.certFile)
	return kp.cert, nil
}

// newestMTime 取证书与私钥中较新的修改时间。certbot 的 live 目录是指向
// archive 的符号链接，os.Stat 会跟随到实际文件。
func (kp *KeyPair) newestMTime() time.Time {
	var newest time.Time
	for _, p := range []string{kp.certFile, kp.keyFile} {
		if st, err := os.Stat(p); err == nil && st.ModTime().After(newest) {
			newest = st.ModTime()
		}
	}
	return newest
}
