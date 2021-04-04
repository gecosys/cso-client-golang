package utils

import (
	"crypto/hmac"
	"crypto/sha256"
)

func CalcHMAC(key, data []byte) ([]byte, error) {
	mac := hmac.New(sha256.New, key)
	_, err := mac.Write(data)
	if err != nil {
		return nil, err
	}
	return mac.Sum(nil), nil
}

func ValidateHMAC(key, data, expectedHMAC []byte) bool {
	result, err := CalcHMAC(key, data)
	if err != nil || len(result) != len(expectedHMAC) {
		return false
	}
	for idx, val := range expectedHMAC {
		if val != result[idx] {
			return false
		}
	}
	return true
}
