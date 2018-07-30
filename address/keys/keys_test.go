package keys

import (
	"encoding/hex"
	"math/big"
	"strings"
	"testing"
)

/*
/ Useful for teesting:
/ https://www.bitaddress.org/bitaddress.org-v3.3.0-SHA256-dec17c07685e1870960903d8f58090475b25af946fe95a734f88408cef4aa194.html
*/
func TestDecodeUncompressedWIF_1(t *testing.T) {
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
func TestDecodeUncompressedWIF_2(t *testing.T) {
	//http://gobittest.appspot.com/PrivateKey
	encodedKey := "5JLM1u1wmYBzPaHxr2fEM5cczS9oqeiVfCSXzDZdEVxZraogexk"
	privateKey := strings.ToLower("4440CD90151432BC082C6925A4A8D4CCFF2065017E9224D16563182C9AD8A7AA")
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
func TestDecodeUncompressedWIF_3(t *testing.T) {
	//http://gobittest.appspot.com/PrivateKey
	encodedKey := "5JkH4Qek122o4Sz6y4HEXokPvrprfcpEo84BfZxKNZse5zMeAoA"
	privateKey := strings.ToLower("7A97DA2C6F4BC73D2B330F2634975D6485C7294AD95F33ACC007C5BC5CB1DC5C")
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
func TestDecodeCompressedWIF_1(t *testing.T) {
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
func TestDecodeCompressedWIF_2(t *testing.T) {
	//http://gobittest.appspot.com/PrivateKey
	encodedKey := "KyWPLxbAjafWJdwsVQKjudNDrW1sjjU9VbVhmYSzvapG1n8giy9c"
	privateKey := strings.ToLower("4440CD90151432BC082C6925A4A8D4CCFF2065017E9224D16563182C9AD8A7AA")
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
func TestDecodeCompressedWIF_3(t *testing.T) {
	//http://gobittest.appspot.com/PrivateKey
	encodedKey := "L1L1t3Pao5YvJDh3LRUeiyLYCivEDT5Vta945ETA6C6WgswTeobf"
	privateKey := strings.ToLower("7A97DA2C6F4BC73D2B330F2634975D6485C7294AD95F33ACC007C5BC5CB1DC5C")
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

func TestEncodeToUncompressedWIF(t *testing.T) {
	privateKey := "7A97DA2C6F4BC73D2B330F2634975D6485C7294AD95F33ACC007C5BC5CB1DC5C"
	wif, err := ToWIF(privateKey, false)
	if err != nil {
		t.Errorf("WIF encoding has failed due to %v", err)
	}
	expected := "5JkH4Qek122o4Sz6y4HEXokPvrprfcpEo84BfZxKNZse5zMeAoA"
	if wif != expected {
		t.Errorf("Failed because encoded WIF is not correct, actual: %v  expected: %v", wif, expected)
	}
}
func TestEncodeToCompressedWIF(t *testing.T) {
	privateKey := "7A97DA2C6F4BC73D2B330F2634975D6485C7294AD95F33ACC007C5BC5CB1DC5C"
	wif, err := ToWIF(privateKey, true)
	if err != nil {
		t.Errorf("WIF encoding has failed due to %v", err)
	}
	expected := "L1L1t3Pao5YvJDh3LRUeiyLYCivEDT5Vta945ETA6C6WgswTeobf"
	if wif != expected {
		t.Errorf("Failed because encoded WIF is not correct, actual: %v  expected: %v", wif, expected)
	}
}
func TestDerivateCompressedPublicKey_1(t *testing.T) {
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
func TestDerivateCompressedPublicKey_2(t *testing.T) {
	//https://en.bitcoin.it/wiki/Technical_background_of_version_1_Bitcoin_addresses
	privKeyHexString := "4440CD90151432BC082C6925A4A8D4CCFF2065017E9224D16563182C9AD8A7AA"
	privKeyByte, err := hex.DecodeString(privKeyHexString)
	if err != nil {
		t.Errorf("Cannot decode private key")
	}
	compressedPubKey := Public(privKeyByte, true)
	expectedPubKey := strings.ToLower("02435D2055E0BEE0FF632652DE7982432DB2CD1A7321E1116500DE0E86047CB5F9")
	pubKeyAsString := hex.EncodeToString(compressedPubKey)
	if pubKeyAsString != expectedPubKey {
		t.Errorf("Unexpected compressed pubKey actual:%v  expected:%v", pubKeyAsString, expectedPubKey)
	}
}
func TestDerivateCompressedPublicKey_3(t *testing.T) {
	//https://en.bitcoin.it/wiki/Technical_background_of_version_1_Bitcoin_addresses
	privKeyHexString := "7A97DA2C6F4BC73D2B330F2634975D6485C7294AD95F33ACC007C5BC5CB1DC5C"
	privKeyByte, err := hex.DecodeString(privKeyHexString)
	if err != nil {
		t.Errorf("Cannot decode private key")
	}
	compressedPubKey := Public(privKeyByte, true)
	expectedPubKey := strings.ToLower("037F6B04E1F6DC00C3E707AF18EC43FCD320D722E8E63B755ABC4673301801A262")
	pubKeyAsString := hex.EncodeToString(compressedPubKey)
	if pubKeyAsString != expectedPubKey {
		t.Errorf("Unexpected compressed pubKey actual:%v  expected:%v", pubKeyAsString, expectedPubKey)
	}
}
func TestDerivateCompressedPublicKey_4(t *testing.T) {
	//https://en.bitcoin.it/wiki/Technical_background_of_version_1_Bitcoin_addresses
	privKeyHexString := "1111111111111111111111111111111111111111111111111111111111111111"
	privKeyByte, err := hex.DecodeString(privKeyHexString)
	if err != nil {
		t.Errorf("Cannot decode private key")
	}
	compressedPubKey := Public(privKeyByte, true)
	expectedPubKey := strings.ToLower("034f355bdcb7cc0af728ef3cceb9615d90684bb5b2ca5f859ab0f0b704075871aa")
	pubKeyAsString := hex.EncodeToString(compressedPubKey)
	if pubKeyAsString != expectedPubKey {
		t.Errorf("Unexpected compressed pubKey actual:%v  expected:%v", pubKeyAsString, expectedPubKey)
	}
}

func TestDerivateUncompressesPublicKey_1(t *testing.T) {
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

func TestDerivateUncompressesPublicKey_2(t *testing.T) {
	//https://en.bitcoin.it/wiki/Technical_background_of_version_1_Bitcoin_addresses
	privKeyHexString := "4440CD90151432BC082C6925A4A8D4CCFF2065017E9224D16563182C9AD8A7AA"
	privKeyByte, err := hex.DecodeString(privKeyHexString)
	if err != nil {
		t.Errorf("Cannot decode private key")
	}
	uncompressedPubKey := Public(privKeyByte, false)
	expectedPubKey := strings.ToLower("04435D2055E0BEE0FF632652DE7982432DB2CD1A7321E1116500DE0E86047CB5F9D7C137D402E743055DB05BBFB3EC108BE554EEEBC44C0BFFA8BF0C161521AF34")
	pubKeyAsString := hex.EncodeToString(uncompressedPubKey)
	if pubKeyAsString != expectedPubKey {
		t.Errorf("Unexpected uncompressed pubKey actual:%v  expected:%v", pubKeyAsString, expectedPubKey)
	}
}

func TestDerivateUncompressesPublicKey_3(t *testing.T) {
	//https://en.bitcoin.it/wiki/Technical_background_of_version_1_Bitcoin_addresses
	privKeyHexString := "7A97DA2C6F4BC73D2B330F2634975D6485C7294AD95F33ACC007C5BC5CB1DC5C"
	privKeyByte, err := hex.DecodeString(privKeyHexString)
	if err != nil {
		t.Errorf("Cannot decode private key")
	}
	uncompressedPubKey := Public(privKeyByte, false)
	expectedPubKey := strings.ToLower("047F6B04E1F6DC00C3E707AF18EC43FCD320D722E8E63B755ABC4673301801A262C7D26F0F70DBF77EC3F038F2236D77243C91F40F017D4AC9EDD62470BBBD3D0D")
	pubKeyAsString := hex.EncodeToString(uncompressedPubKey)
	if pubKeyAsString != expectedPubKey {
		t.Errorf("Unexpected uncompressed pubKey actual:%v  expected:%v", pubKeyAsString, expectedPubKey)
	}
}

func TestEvens(t *testing.T) {
	odds := []int64{16, 52, 17288, 718283782, 8484910, 8399490084, 0}
	odd := new(big.Int)
	for _, num := range odds {
		odd.SetInt64(num)
		isEven := isEven(odd)
		if isEven != true {
			t.Errorf("Number wrongly defined as odd: %v\n", num)
		}
	}
}
func TestOdds(t *testing.T) {
	odds := []int64{15, 55, 17287, 718283781, 8484909, 8399490081, 1}
	odd := new(big.Int)
	for _, num := range odds {
		odd.SetInt64(num)
		isEven := isEven(odd)
		if isEven != false {
			t.Errorf("Number wrongly defined as even: %v\n", num)
		}
	}
}
