package address

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"github.com/btcsuite/btcutil/base58"
	"golang.org/x/crypto/ripemd160"
	"math/big"
	"testing"
)

type secp256k1 struct {
	*elliptic.CurveParams
}

func derivatePublicKey(key []byte, curve elliptic.Curve) (uncompressedPubKey []byte) {
	fmt.Printf("PrivateKey is %x of length=%d\n", key, len(key))
	bigNumberKey := new(big.Int)
	bigNumberKey.SetBytes(key)
	fmt.Printf("Big.Int HEX %x\n", bigNumberKey.Bytes())
	fmt.Printf("Big.Int num %v\n", bigNumberKey)

	privKey := new(ecdsa.PrivateKey)
	privKey.D = bigNumberKey
	privKey.PublicKey.Curve = curve
	privKey.PublicKey.X, privKey.PublicKey.Y = curve.ScalarBaseMult(bigNumberKey.Bytes())
	//Append 0x04 X and Y to build public key
	uncompressedPubKey = []byte{0x04}
	byteX := privKey.PublicKey.X.Bytes()
	byteY := privKey.PublicKey.Y.Bytes()
	fmt.Printf("X: %x  Y:%x \n", byteX, byteY)
	uncompressedPubKey = append(uncompressedPubKey, byteX...)
	uncompressedPubKey = append(uncompressedPubKey, byteY...)
	return uncompressedPubKey
}

func makeSecp256k1Curve() elliptic.Curve {
	bchCurveParams := new(elliptic.CurveParams)
	bchCurveParams.Name = "secp256k1"
	bchCurveParams.P, _ = new(big.Int).SetString("fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f", 16)
	bchCurveParams.N, _ = new(big.Int).SetString("fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141", 16) // A valid key must me less than N
	bchCurveParams.B, _ = new(big.Int).SetString("0000000000000000000000000000000000000000000000000000000000000007", 16)
	bchCurveParams.Gx, _ = new(big.Int).SetString("79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798", 16)
	bchCurveParams.Gy, _ = new(big.Int).SetString("483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8", 16)
	bchCurveParams.BitSize = 256
	bchCurve := secp256k1{bchCurveParams}
	return bchCurve
}

func decodeBase58Example() {
	// Example from http://gobittest.appspot.com/PrivateKey
	encodedKey := Key("5HueCGU8rMjxEXxiPuD5BDku4MkFqeZyd4dZ1jvhTVqvbTLvyTJ")
	fmt.Printf("BCH private key is %v\n", encodedKey)

	// Decoding key using base58
	decoded, version, err := base58.CheckDecode(string(encodedKey))
	if err != nil {
		fmt.Println("Cannot decode private key", err)
	}
	fmt.Printf("Key version is: %d\n", version)
	fmt.Printf("Base58 decoded []byte: %v\n", decoded)
	fmt.Printf("Base58 decoded []byte: %v\n", hex.EncodeToString(decoded))

}

// Key example from https://en.bitcoin.it/wiki/Technical_background_of_version_1_Bitcoin_addresses
// ECDSA KEY PAIR GENERATOR https://kjur.github.io/jsrsasign/sample/sample-ecdsa.html
func TestDecodeKey(t *testing.T) {
	fmt.Println("FROM KEY TO ADDRESS ---------------------------------------------------")
	fmt.Println("")

	// PRIV "0c4d19b8b6383e6c9641f6769707798b20f30bc98b0bae5d14c1f5088b24566c"
	// PUB  "04bfcc0a1c403baffaeef9320c7312ea23a7f1acc046d74b82728985e659727a63a2a17ac02f53401dc22b4fe86e64d6d188b551bcb3b4bbdc8e3d473b7ea4c945"
	// Works with elliptic.P256()

	// PRIV "5ded643a8edce629a5d2559a984959924295d02c4610d02b0606ac6787c6351d"
	// PUB  "042aca47a09b249f9c8bb3bdfe47a228c7a656872b9c3292df2a68de52a3fddca03d7efbcb74b387a1b42626d6f0e4edbb2c827431cc6369dfa92c8c4c692b1324"

	privKeyHexString := "5ded643a8edce629a5d2559a984959924295d02c4610d02b0606ac6787c6351d"
	// privKeyHexString := "0c4d19b8b6383e6c9641f6769707798b20f30bc98b0bae5d14c1f5088b24566c"
	// privKeyHexString := "18E14A7B6A307F426A94F8114701E7C8E774E7F9A47E2C2035DB29A206321725"
	privKeyByte, err := hex.DecodeString(privKeyHexString)
	if err != nil {
		panic(err)
	}
	bchCurve := makeSecp256k1Curve()
	// bchCurve := elliptic.P256()
	publicKey := derivatePublicKey(privKeyByte, bchCurve)

	fmt.Printf("Pubkey is %x  len: %v\n", publicKey, len(publicKey))

	fmt.Println("FROM KEY TO ADDRESS --------------------------------------------------- END")
	fmt.Println("")
	fmt.Println("")

	//Sha256 of public key
	pkSha256 := sha256.Sum256(publicKey)
	fmt.Printf("Sha256 of PubKey: %[1]T %[1]x %d\n", pkSha256, len(pkSha256))

	// Ripe160
	ripemd160 := ripemd160.New()
	fmt.Printf("Ripemd160 return size is %d\n", ripemd160.Size())
	pkRip160 := ripemd160.Sum(pkSha256[:])
	fmt.Printf("Ripemd160 of PubKey Sha256 is %x %d\n", pkRip160[20:], len(pkRip160))
	// var ecKey *ecdsa.PrivateKey = decodeKey(commonKey)
	// if ecKey == nil {
	// 	t.Error("The key is nil")
	// }
	// fmt.Println("Private KeyBig int", privKeyNum)
	// if ecKey.D != &privKeyNum {
	// 	t.Error("Key doesn't match")
	// }
	// fmt.Printf("ECSDA KEY: %v\n", ecKey)
}
