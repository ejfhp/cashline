package address

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"fmt"
)

// Key is a BitcoinCash private key as used in CashAddress format
type Key string

func decodeKey(key Key) (privKey *ecdsa.PrivateKey) {
	fmt.Println("decodeKey", key)
	curve := elliptic.P256()
	randomReader := rand.Reader
	privKey, err := ecdsa.GenerateKey(curve, randomReader)
	if err != nil {
		fmt.Println("Cannot generate private key")
	}
	return privKey
}
