package address

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"fmt"
)

// Key is a BitcoinCash private key as used in CashAddress format
type Key string

func decodeKey(key Key) (privKey ecdsa.PrivateKey) {
	fmt.Println("decodeKey", key)
	curve := elliptic.P256()
	privKey = ecdsa.GenerateKey(curve, rand.Reader)
	return privKey
}
