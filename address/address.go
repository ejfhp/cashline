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

func derivatePublicKey(key []byte, curve elliptic.Curve) ecdsa.PublicKey {
	fmt.Printf("PrivateKey is %x of length=%d\n", key, len(key))
	bigNumberKey := new(big.Int)
	bigNumberKey.SetBytes(key)
	fmt.Printf("Big.Int HEX %x\n", bigNumberKey.Bytes())
	fmt.Printf("Big.Int num %v\n", bigNumberKey)

	privKey := new(ecdsa.PrivateKey)
	privKey.D = bigNumberKey
	privKey.PublicKey.Curve = curve
	privKey.PublicKey.X, privKey.PublicKey.Y = curve.ScalarBaseMult(bigNumberKey.Bytes())
	publicKey := privKey.PublicKey
	return publicKey
}
