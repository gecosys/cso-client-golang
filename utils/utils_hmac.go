package utils

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"errors"
)

func CalcHMAC(key, data []byte) ([]byte, error) {
	mac := hmac.New(sha256.New, key)
	n, err := mac.Write(data)
	if err != nil {
		return nil, err
	}
	if n != len(data) {
		return nil, errors.New("invalid hmac")
	}
	return mac.Sum(nil), nil
}

func ValidateHMAC(key, data, expectedHMAC []byte) bool {
	result, err := CalcHMAC(key, data)
	if err != nil {
		return false
	}
	return bytes.Equal(result, expectedHMAC)
}
