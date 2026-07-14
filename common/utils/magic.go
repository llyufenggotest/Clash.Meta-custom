package utils

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"io"
	"time"
)

// GenerateMagicSNI 实时计算闪连动态暗号
func GenerateMagicSNI() string {
	now := time.Now()
	tSec := now.Unix()
	tMs := now.UnixMilli()

	// 1. 生成 AES 密钥
	seedBytes := make([]byte, 8)
	binary.BigEndian.PutUint64(seedBytes, uint64(tSec))
	key := sha256.Sum256(seedBytes)

	// 2. 构造明文 (tMs * 10)
	plainBytes := make([]byte, 8)
	binary.BigEndian.PutUint64(plainBytes, uint64(tMs*10))

	// 3. 生成 12 字节随机 Nonce
	nonce := make([]byte, 12)
	io.ReadFull(rand.Reader, nonce)

	// 4. 执行 AES-256-GCM
	block, _ := aes.NewCipher(key[:])
	aesgcm, _ := cipher.NewGCM(block)
	sealed := aesgcm.Seal(nil, nonce, plainBytes, nil)
	
	// 5. 拼接：密文(8) + Tag(16) + Nonce(12)
	finalPayload := append(sealed, nonce...)

	return base64.StdEncoding.EncodeToString(finalPayload)
}