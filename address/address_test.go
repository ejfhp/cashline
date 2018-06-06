package address

import (
	"crypto/ecdsa"
	"fmt"
	"math/big"
	"testing"
)

func TestDecodeKey(t *testing.T) {
	var key Key = "tanto va la gatta al lardo che ci lascia lo zampino"
	var ecKey ecdsa.PrivateKey = decodeKey(key)
	if ecKey == (ecdsa.PrivateKey{}) {
		t.Error("The key is nil")
	}
	commonKey := "5HueCGU8rMjxEXxiPuD5BDku4MkFqeZyd4dZ1jvhTVqvbTLvyTJ"
	bareKey := "0C28FCA386C7A227600B2FE50B7CAE11EC86D3BF1FBE471BE89827E19D72AA1D"
	var privKeyNum big.Int = big.Int{}
	privKeyNum.UnmarshalText([]byte(bareKey))
	fmt.Println("Private KeyBig int", privKeyNum)
	if ecKey.D != &privKeyNum {
		t.Error("Key doesn't match")
	}
	fmt.Printf("ECSDA KEY: %v\n", ecKey)
	fmt.Println("THE END")
}
