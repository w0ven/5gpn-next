package quicsni

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"encoding/binary"
	"encoding/hex"
	"testing"
)

func mustHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// 初始密钥必须与规范附录给出的向量逐字节一致：RFC 9001 A.1（v1）与
// draft-ietf-quic-tls-29 A.1（h3-29），两者使用同一个连接 ID。
func TestInitialKeysMatchSpecVectors(t *testing.T) {
	dcid := mustHex(t, "8394c8f03e515708")
	for _, c := range []struct {
		name         string
		vp           quicVersion
		key, iv, hpk string
	}{
		{"v1", versionV1, "1f369613dd76d5467730efcbe3b1a22d", "fa044b2f42a3fd3b46fb255c", "9f50449e04a0e810283a1e9933adedd2"},
		{"draft-29", versionDraft29, "175257a31eb09dea9366d8bb79ad80ba", "6b26114b9cba2b63a9e8dd4f", "9ddd12c994c0698b89374a9c077a3077"},
	} {
		key, iv, hp := deriveClientInitialKeys(c.vp, dcid)
		if hex.EncodeToString(key) != c.key || hex.EncodeToString(iv) != c.iv || hex.EncodeToString(hp) != c.hpk {
			t.Errorf("%s 初始密钥与规范向量不符: key=%x iv=%x hp=%x", c.name, key, iv, hp)
		}
	}
}

// sealInitial 按给定版本加密一个客户端 Initial 包（4 字节包号），并补齐到 1200 字节。
func sealInitial(t *testing.T, version uint32, vp quicVersion, dcid, frames []byte) []byte {
	t.Helper()
	const pnLen = 4
	payloadLen := len(frames)
	hdrLen := 1 + 4 + 1 + len(dcid) + 1 + 1 + 2 + pnLen
	if pad := 1200 - (hdrLen + payloadLen + 16); pad > 0 {
		frames = append(append([]byte(nil), frames...), make([]byte, pad)...)
	}
	length := pnLen + len(frames) + 16
	hdr := []byte{0xc0 | vp.initialType<<4 | (pnLen - 1)}
	hdr = binary.BigEndian.AppendUint32(hdr, version)
	hdr = append(hdr, byte(len(dcid)))
	hdr = append(hdr, dcid...)
	hdr = append(hdr, 0, 0) // SCID 长度 0、token 长度 0
	hdr = append(hdr, 0x40|byte(length>>8), byte(length))
	pnOffset := len(hdr)
	hdr = append(hdr, 0, 0, 0, 2)

	key, iv, hp := deriveClientInitialKeys(vp, dcid)
	block, _ := aes.NewCipher(key)
	aead, _ := cipher.NewGCM(block)
	nonce := append([]byte(nil), iv...)
	nonce[len(nonce)-1] ^= 2
	pkt := aead.Seal(append([]byte(nil), hdr...), nonce, frames, hdr)

	hpBlock, _ := aes.NewCipher(hp)
	var mask [16]byte
	hpBlock.Encrypt(mask[:], pkt[pnOffset+4:pnOffset+20])
	pkt[0] ^= mask[0] & 0x0f
	for i := 0; i < pnLen; i++ {
		pkt[pnOffset+i] ^= mask[1+i]
	}
	return pkt
}

// 把 RFC 9001 向量里的明文按 h3-29 重新加密：网关必须能同样还原出 SNI。
func TestDraft29ClientInitialSNI(t *testing.T) {
	frames, _, err := decryptInitial(rfcPacket(t))
	if err != nil {
		t.Fatal(err)
	}
	for _, v := range []uint32{0xff00001d, 0xff000020} {
		pkt := sealInitial(t, v, versionDraft29, mustHex(t, "8394c8f03e515708"), frames)
		sni, ok, err := NewDecoder().Feed(pkt)
		if err != nil || !ok || sni != "example.com" {
			t.Fatalf("版本 0x%08x: sni=%q ok=%v err=%v", v, sni, ok, err)
		}
		if VersionNegotiation(pkt) != nil {
			t.Fatalf("已支持的版本不应回复版本协商")
		}
	}
}

func TestVersionNegotiation(t *testing.T) {
	pkt := append([]byte(nil), rfcPacket(t)...)
	if len(pkt) < minInitialDatagram {
		pkt = append(pkt, make([]byte, minInitialDatagram-len(pkt))...)
	}
	binary.BigEndian.PutUint32(pkt[1:5], 0x51303530) // gQUIC Q050
	vn := VersionNegotiation(pkt)
	if vn == nil {
		t.Fatal("未知版本的首包应回复版本协商")
	}
	if vn[0]&0x80 == 0 || binary.BigEndian.Uint32(vn[1:5]) != 0 {
		t.Fatalf("版本协商包头部错误: %x", vn[:5])
	}
	// 客户端的 SCID（空）成为 DCID，客户端的 DCID 成为 SCID。
	if vn[5] != 0 || vn[6] != 8 || !bytes.Equal(vn[7:15], mustHex(t, "8394c8f03e515708")) {
		t.Fatalf("连接 ID 未互换: %x", vn)
	}
	var got []uint32
	for i := 15; i+4 <= len(vn); i += 4 {
		got = append(got, binary.BigEndian.Uint32(vn[i:]))
	}
	if len(got) != 3 || got[0] != 1 || got[2] != 0xff00001d {
		t.Fatalf("支持的版本列表错误: %x", got)
	}

	if VersionNegotiation(pkt[:600]) != nil {
		t.Fatal("小于 1200 字节的数据报不应回复（防放大）")
	}
	binary.BigEndian.PutUint32(pkt[1:5], 0)
	if VersionNegotiation(pkt) != nil {
		t.Fatal("版本协商包本身不应再被回复")
	}
	short := append([]byte{0x40}, pkt[1:]...)
	if VersionNegotiation(short) != nil {
		t.Fatal("短包头不应回复")
	}
}
