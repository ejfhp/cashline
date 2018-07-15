package keys

import (
	"encoding/hex"
	"strings"
	"testing"
)

func TestDecodeUncompressedWIF(t *testing.T) {
	//http://gobittest.appspot.com/PrivateKey
	encodedKey := "5HueCGU8rMjxEXxiPuD5BDku4MkFqeZyd4dZ1jvhTVqvbTLvyTJ"
	privateKey := strings.ToLower("0C28FCA386C7A227600B2FE50B7CAE11EC86D3BF1FBE471BE89827E19D72AA1D")
	decoded, compressed, err := PrivateFromWIF(encodedKey)
	if err != nil {
		t.Errorf("Failed because: %v", err)
	}
	decodedAsString := hex.EncodeToString(decoded)
	if decodedAsString != privateKey {
		t.Errorf("Failed because decoded key is not correct: %v %x", decodedAsString, decoded)
	}
	if compressed != false {
		t.Errorf("Failed because decoded key is not compressed")
	}
}
func TestDecodeCompressedWIF(t *testing.T) {
	//http://gobittest.appspot.com/PrivateKey
	encodedKey := "KwdMAjGmerYanjeui5SHS7JkmpZvVipYvB2LJGU1ZxJwYvP98617"
	privateKey := strings.ToLower("0C28FCA386C7A227600B2FE50B7CAE11EC86D3BF1FBE471BE89827E19D72AA1D")
	decoded, compressed, err := PrivateFromWIF(encodedKey)
	if err != nil {
		t.Errorf("Failed because: %v", err)
	}
	decodedAsString := hex.EncodeToString(decoded)
	if decodedAsString != privateKey {
		t.Errorf("Failed because decoded key is not correct: %v expected: %v", decodedAsString, privateKey)
	}
	if compressed != true {
		t.Errorf("Failed because decoded key is compressed")
	}
}
func TestDerivateCompressedPublicKey(t *testing.T) {
	//https://en.bitcoin.it/wiki/Technical_background_of_version_1_Bitcoin_addresses
	privKeyHexString := "0C28FCA386C7A227600B2FE50B7CAE11EC86D3BF1FBE471BE89827E19D72AA1D"
	privKeyByte, err := hex.DecodeString(privKeyHexString)
	if err != nil {
		t.Errorf("Cannot decode private key")
	}
	compressedPubKey := Public(privKeyByte, true)
	expectedPubKey := "02d0de0aaeaefad02b8bdc8a01a1b8b11c696bd3d66a2c5f10780d95b7df42645c"
	pubKeyAsString := hex.EncodeToString(compressedPubKey)
	if pubKeyAsString != expectedPubKey {
		t.Errorf("Unexpected compressed pubKey actual:%v  expected:%v", pubKeyAsString, expectedPubKey)
	}
}

func TestDerivateUncompressesPublicKey(t *testing.T) {
	//https://en.bitcoin.it/wiki/Technical_background_of_version_1_Bitcoin_addresses
	privKeyHexString := "0C28FCA386C7A227600B2FE50B7CAE11EC86D3BF1FBE471BE89827E19D72AA1D"
	privKeyByte, err := hex.DecodeString(privKeyHexString)
	if err != nil {
		t.Errorf("Cannot decode private key")
	}
	uncompressedPubKey := Public(privKeyByte, false)
	expectedPubKey := "04d0de0aaeaefad02b8bdc8a01a1b8b11c696bd3d66a2c5f10780d95b7df42645cd85228a6fb29940e858e7e55842ae2bd115d1ed7cc0e82d934e929c97648cb0a"
	pubKeyAsString := hex.EncodeToString(uncompressedPubKey)
	if pubKeyAsString != expectedPubKey {
		t.Errorf("Unexpected uncompressed pubKey actual:%v  expected:%v", pubKeyAsString, expectedPubKey)
	}
}
