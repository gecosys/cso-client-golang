package utils

import (
	"crypto/rand"
	"crypto/sha256"
	"math/big"
)

// GenerateDHPrivateKey generates private DH key
func GenerateDHPrivateKey() (*big.Int, error) {
	min := new(big.Int).Exp(big.NewInt(2), big.NewInt(100), nil)
	max := new(big.Int).Exp(big.NewInt(2), big.NewInt(180), nil)
	val, err := rand.Int(rand.Reader, max.Sub(max, min))
	if err != nil {
		return nil, err
	}
	return val.Add(val, min), nil
}

// CalcDHKeys calculates DH keys
func CalcDHKeys(gKey, nKey, privKey *big.Int) (pubKey *big.Int, err error) {
	pubKey = new(big.Int).Exp(gKey, privKey, nKey)
	return
}

// CalcSecretKey calculates secret key by DH keys
func CalcSecretKey(nKey, clientPrivKey, serverPubKey *big.Int) ([]byte, error) {
	secretKey := new(big.Int).Exp(serverPubKey, clientPrivKey, nKey)
	hashed := sha256.Sum256([]byte(secretKey.String()))
	return hashed[:], nil
}
