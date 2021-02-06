package utils

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"io"
)

// EncryptAES encrypts data by AES with GCM mode
func EncryptAES(key, data, aad []byte) (iv, authenTag, result []byte, err error) {
	var (
		aesgcm cipher.AEAD
		block  cipher.Block
	)

	block, err = aes.NewCipher(key)
	if err != nil {
		return
	}

	iv = make([]byte, 12)
	if _, err = io.ReadFull(rand.Reader, iv); err != nil {
		return
	}

	aesgcm, err = cipher.NewGCMWithTagSize(block, 16)
	if err != nil {
		return
	}

	result = aesgcm.Seal(nil, iv, data, aad)
	authenTag = make([]byte, 16)
	copy(authenTag, result[len(result)-16:])
	result = result[:len(result)-16]
	return
}

// DecryptAES decrypts data by AES with GCM mode
func DecryptAES(key, iv, authenTag, data, aad []byte) (result []byte, err error) {
	var (
		aesgcm cipher.AEAD
		block  cipher.Block
	)

	block, err = aes.NewCipher(key)
	if err != nil {
		return
	}

	aesgcm, err = cipher.NewGCMWithTagSize(block, 16)
	if err != nil {
		return
	}

	lenData := len(data)
	lenBuffer := lenData + len(authenTag)
	buffer := make([]byte, lenBuffer, lenBuffer)
	copy(buffer, data)
	copy(buffer[lenData:], authenTag)
	result, err = aesgcm.Open(nil, iv, buffer, aad)
	return
}
