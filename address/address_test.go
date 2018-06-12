package address

import (
	"encoding/hex"
	"fmt"
	"github.com/btcsuite/btcutil/base58"
	"math/big"
	"testing"
)

// Key example from http://gobittest.appspot.com/PrivateKey
// Encoded key should unmarshal to correct number
func TestDecodeKey(t *testing.T) {
	encodedKey := Key("5HueCGU8rMjxEXxiPuD5BDku4MkFqeZyd4dZ1jvhTVqvbTLvyTJ")
	fmt.Printf("BCH private key is %v\n", encodedKey)
	textNumber := "0C28FCA386C7A227600B2FE50B7CAE11EC86D3BF1FBE471BE89827E19D72AA1D"
	fmt.Printf("Text number is %v\n", textNumber)
	var bigNumber *big.Int = new(big.Int)
	bigNumber.SetString(textNumber, 16)
	fmt.Printf("Decoded number should be %v\n", bigNumber)

	// Decoding key using base58
	decoded := base58.Decode(string(encodedKey))
	fmt.Printf("Base58 decoded []byte: %v\n", hex.EncodeToString(decoded))

	decKey, version, err := base58.CheckDecode(string(encodedKey))
	if err != nil {
		fmt.Errorf("Cannot decode key %v", err)
	}
	fmt.Printf("Decoded key %x, version %v\n", decKey, version)
	// var ecKey *ecdsa.PrivateKey = decodeKey(commonKey)
	// if ecKey == nil {
	// 	t.Error("The key is nil")
	// }
	// fmt.Println("Private KeyBig int", privKeyNum)
	// if ecKey.D != &privKeyNum {
	// 	t.Error("Key doesn't match")
	// }
	// fmt.Printf("ECSDA KEY: %v\n", ecKey)
	fmt.Println("THE END")
}
