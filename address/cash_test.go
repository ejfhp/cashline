package address

import (
	"fmt"
	"strings"
	"testing"
)

func TestChecksum(t *testing.T) {
	// str := "prefix:x64nx6hz"
	str := "bitcoincash:qpzry9x8gf2tvdw0s3jn54khce6mua7lcw20ayyn"
	strSplit := strings.Split(str, ":")
	prefix := strSplit[0]
	payload := strSplit[1]
	data := PrefixLower5Bit(prefix)
	fmt.Println(data)
	idx := byte('g')
	n := DECODEMAP[idx]
	fmt.Printf("Decoded value of %c (%d) is: %v\n", idx, idx, n)

	d := ENCODEMAP[n]
	fmt.Printf("Encoded char of %v is: %c (%d)\n", n, d, d)

	decodedPrefix := PrefixLower5Bit(prefix)
	fmt.Printf("Decoded prefix: %x\n", decodedPrefix)
	decodedPayload, err := DecodePayload(payload)
	fmt.Printf("Decoded payload: %x\n", decodedPayload)
	if err != nil {
		t.Errorf("Failed to decode payload %v due to: %v\n", payload, err)
	}

	dataToVerify := decodedPrefix
	dataToVerify = append(dataToVerify, decodedPayload...)
	chksum := PolyMod(dataToVerify)
	if chksum != 0 {
		t.Errorf("Checsum is not 0, chksum: %v", chksum)
	}

}
