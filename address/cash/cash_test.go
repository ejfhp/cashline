package cash

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"math/rand"
	"strings"
	"testing"
)

func TestChecksum(t *testing.T) {
	// str := "prefix:x64nx6hz"
	str := "bitcoincash:qpzry9x8gf2tvdw0s3jn54khce6mua7lcw20ayyn"
	strSplit := strings.Split(str, ":")
	prefix := strSplit[0]
	payload := strSplit[1]
	data := FullPrefixTo5Bit(prefix)
	fmt.Println(data)
	idx := byte('g')
	n := DECODEMAP[idx]
	fmt.Printf("Decoded value of %c (%d) is: %v\n", idx, idx, n)

	d := ENCODEMAP[n]
	fmt.Printf("Encoded char of %v is: %c (%d)\n", n, d, d)

	decodedPrefix := FullPrefixTo5Bit(prefix)
	fmt.Printf("Decoded prefix: %x\n", decodedPrefix)
	decodedPayload, err := Base32Decode(payload)
	fmt.Printf("Decoded payload: %x\n", decodedPayload)
	if err != nil {
		t.Errorf("Failed to decode payload %v due to: %v\n", payload, err)
	}

	dataToVerify := decodedPrefix
	dataToVerify = append(dataToVerify, decodedPayload...)
	chksum := polyMod(dataToVerify)
	if chksum != 0 {
		t.Errorf("Checsum is not 0, chksum: %v", chksum)
	}

}

// uncompressed 044526CABB86DE7767718CA2FE13B2066BE44615DEF846A15E6F4441C114807373BAD033C052327C75B40B9D938645B59BDABBC30E9C9545B63D0F251A9A689490
// uncompressed bitcoincash:qp842l6pwrsudd7t70c2epvcyg2xc297qq5clqxfgm
func TestFromUncompressedPubKey(t *testing.T) {
	uncompressed := "044526CABB86DE7767718CA2FE13B2066BE44615DEF846A15E6F4441C114807373BAD033C052327C75B40B9D938645B59BDABBC30E9C9545B63D0F251A9A689490"
	uncompressedAdd := "bitcoincash:qp842l6pwrsudd7t70c2epvcyg2xc297qq5clqxfgm"

	pubKey, _ := hex.DecodeString(uncompressed)
	withPrefix, onlyAddr, err := FromPubKey(pubKey)
	if err != nil {
		t.Errorf("cannot generate address due to %v", err)
	}
	fmt.Printf("BCH ADDRESS %s %s\n", withPrefix, onlyAddr)
	if withPrefix != uncompressedAdd {
		t.Errorf("address should be %s but it is %s", uncompressedAdd, withPrefix)
	}
}

func TestFromHash(t *testing.T) {
	hash := []byte{118, 160, 64, 83, 189, 160, 168, 139, 218, 81, 119, 184, 106, 21, 195, 178, 159, 85, 152, 115}
	add := "bitcoincash:qpm2qsznhks23z7629mms6s4cwef74vcwvy22gdx6a"

	// pubKey, _ := hex.DecodeString(compressed)
	withPrefix, onlyAddr, err := fromHash("bitcoincash", 0, hash)
	if err != nil {
		t.Errorf("cannot generate address due to %v", err)
	}
	fmt.Printf("BCH ADDRESS %s %s\n", withPrefix, onlyAddr)
	if withPrefix != add {
		t.Errorf("address should be %s but it is %s", add, withPrefix)
	}
}

// compressed 024526CABB86DE7767718CA2FE13B2066BE44615DEF846A15E6F4441C114807373
// compress bitcoincash:qqd86hz9tnuu98sxgmk48822xaqgh6hwvvhttn6r8h
func TestFromCompressedPubKey(t *testing.T) {
	// compressed := "024526CABB86DE7767718CA2FE13B2066BE44615DEF846A15E6F4441C114807373"
	hash := []byte{118, 160, 64, 83, 189, 160, 168, 139, 218, 81, 119, 184, 106, 21, 195, 178, 159, 85, 152, 115}
	compressedAdd := "bitcoincash:qqd86hz9tnuu98sxgmk48822xaqgh6hwvvhttn6r8h"

	// pubKey, _ := hex.DecodeString(compressed)
	withPrefix, onlyAddr, err := fromHash("bitcoincash", 0, hash)
	if err != nil {
		t.Errorf("cannot generate address due to %v", err)
	}
	fmt.Printf("BCH ADDRESS %s %s\n", withPrefix, onlyAddr)
	if withPrefix != compressedAdd {
		t.Errorf("address should be %s but it is %s", compressedAdd, withPrefix)
	}
}
func randData(size int, max int) []byte {
	data := make([]byte, size, size)
	for i := 0; i < size; i++ {
		data[i] = uint8(rand.Int() % max)
	}
	return data
}

func TestConvertError(t *testing.T) {
	_, err := convert([]byte{100}, 5, 8, false)
	if err == nil {
		t.Errorf("Should fail when data contains invalid values.")
	} else {
		t.Logf("Error correctly returned: %v\n", err)
	}

	rd1 := randData(10, 31)
	_, err = convert(rd1, 5, 8, true)
	if err == nil {
		t.Errorf("Should fail when in strict mode padding is needed.")
	} else {
		t.Logf("Error correctly returned: %v\n", err)
	}
}

func TestConvertPaddRan1(t *testing.T) {
	rd := randData(80, 31)
	conv11, err := convert(rd, 5, 8, false)
	if err != nil {
		t.Errorf("Unexpected failure: %v\n", err)
	}
	conv12, err := convert(conv11, 8, 5, false)
	if err != nil {
		t.Errorf("Unexpected failure: %v\n", err)
	}
	if !bytes.Equal(rd, conv12) {
		t.Logf("Before %d\n", rd)
		t.Logf("After  %d\n", conv12)
		t.Errorf("Gone and return conversion should bring to the original array.\n")
	}
}
func TestConvertPaddRan1NoPad(t *testing.T) {
	rd := randData(80, 31)
	conv11, err := convert(rd, 5, 8, true)
	if err != nil {
		t.Errorf("Unexpected failure: %v\n", err)
	}
	conv12, err := convert(conv11, 8, 5, true)
	if err != nil {
		t.Errorf("Unexpected failure: %v\n", err)
	}
	if !bytes.Equal(rd, conv12) {
		t.Logf("Before %d\n", rd)
		t.Logf("After  %d\n", conv12)
		t.Errorf("Gone and return conversion should bring to the original array.\n")
	}
}
func TestConvertPaddRan2(t *testing.T) {
	rd := randData(32, 31)
	conv11, err := convert(rd, 5, 8, false)
	if err != nil {
		t.Errorf("Unexpected failure: %v\n", err)
	}
	conv12, err := convert(conv11, 8, 5, false)
	if err != nil {
		t.Errorf("Unexpected failure: %v\n", err)
	}
	if !bytes.Equal(rd, conv12) {
		t.Logf("Before %d\n", rd)
		t.Logf("After  %d\n", conv12)
		t.Errorf("Gone and return conversion should bring to the original array.\n")
	}
}

func TestConvertPaddRan3(t *testing.T) {
	rd := randData(54, 7)
	conv11, err := convert(rd, 3, 8, false)
	if err != nil {
		t.Errorf("Unexpected failure: %v\n", err)
	}
	conv12, err := convert(conv11, 8, 3, false)
	if err != nil {
		t.Errorf("Unexpected failure: %v\n", err)
	}
	if !bytes.Equal(append(rd, []byte{0, 0}...), conv12) {
		t.Logf("Before %d\n", rd)
		t.Logf("After  %d\n", conv12)
		t.Errorf("Gone and return conversion should bring to the original array.\n")
	}
}
