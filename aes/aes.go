package aes

import (
	"crypto/aes"
	"encoding/hex"
)

// OozAes
type OozAes struct {
	// aes加密key
	Key string
	// 需解密的数据(被加密)
	EncryptData []byte
	// 需加密的数据(未被加密)
	DecodeData []byte
}

// NewAes
func NewAes(key string) *OozAes {
	return &OozAes{
		Key: key,
	}
}

// Decode 解密数据
func (xaes *OozAes) Decode() ([]byte, error) {
	decrypted, err := aesDecryptData(xaes.Key, xaes.EncryptData)
	if err != nil {
		return nil, err
	}
	return decrypted, nil
}

// Encrypt 加密数据
func (xaes *OozAes) Encrypt() []byte {
	return aesEncryptData(xaes.Key, xaes.DecodeData)
}

// Decode 解密数据
func Decode(key string, data []byte) ([]byte, error) {
	decrypted, err := aesDecryptData(key, data)
	if err != nil {
		return nil, err
	}
	return decrypted, nil
}

// Encrypt 加密数据
func Encrypt(key string, data []byte) []byte {
	return aesEncryptData(key, data)
}

// AESEncrypt encrypts a piece of data.
// The cipherkey argument should be the AES key,
// either 16, 24, or 32 bytes to select
// AES-128, AES-192, or AES-256.
func aesEncryptData(key string, src []byte) []byte {
	cipherkey := []byte(key)

	block, err := aes.NewCipher(cipherkey)
	if err != nil {
		panic(err)
	}
	bs := block.BlockSize()
	src = padData(src, bs)
	r := make([]byte, len(src))
	dst := r
	for len(src) > 0 {
		block.Encrypt(dst, src)
		src = src[bs:]
		dst = dst[bs:]
	}
	dst = make([]byte, hex.EncodedLen(len(r)))
	hex.Encode(dst, r)
	return dst
}

// AESDecrypt decrypts a piece of data.
// The cipherkey argument should be the AES key,
// either 16, 24, or 32 bytes to select
// AES-128, AES-192, or AES-256.
func aesDecryptData(key string, ciphertext []byte) ([]byte, error) {
	cipherkey := []byte(key)

	block, err := aes.NewCipher(cipherkey)
	if err != nil {
		return nil, err
	}
	src := make([]byte, hex.DecodedLen(len(ciphertext)))
	_, err = hex.Decode(src, ciphertext)
	if err != nil {
		return nil, err
	}
	bs := block.BlockSize()
	r := make([]byte, len(src))
	dst := r
	for len(src) > 0 {
		block.Decrypt(dst, src)
		src = src[bs:]
		dst = dst[bs:]
	}
	return removePad(r)
}
