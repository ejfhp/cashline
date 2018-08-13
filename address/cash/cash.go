package cash

import (
	// "encoding/binary"
	"fmt"
	"golang.org/x/crypto/ripemd160"
	"math"
)

//FromPubKey returns a P2KH (ripemd160) mainnet (prefix:bitcoincash) bchaddress (withprefix, without prefix)
func FromPubKey(pubKey []byte) (string, string, error) {
	ripe160 := ripemd160.New()
	ripe160.Write(pubKey)
	ripemd160Hash := ripe160.Sum(nil)
	prefix := "bitcoincash"
	addrType := int8(0)                         //P2KH -> 0
	hashSize, err := getHashSize(ripemd160Hash) //ripemd160 is 160 bit -> 0
	if err != nil {
		return "", "", fmt.Errorf("cannot get hash size because %v", err)
	}
	versionByte := byte(addrType + hashSize)
	fmt.Printf("version byte %d\n", versionByte)
	prefixBytes := FullPrefixTo5Bit(prefix) //OK
	fmt.Printf("prefix byte 5 %d\n", prefixBytes)
	data := append([]byte{versionByte}, ripemd160Hash...)
	fmt.Printf("data  %d\n", data)
	data5bit, err := convert(data, 8, 5, false)
	fmt.Printf("data 5 bits %d\n", data5bit)
	if err != nil {
		return "", "", fmt.Errorf("cannot convert data to 5 bit due to %v", err)
	}
	checksumData := append(append(prefixBytes, data5bit...), []byte{0, 0, 0, 0, 0, 0, 0, 0}...)
	// checksum := PolyMod(checksumData)
	// checksumBytes := make([]byte, 8)
	// binary.BigEndian.PutUint64(checksumBytes, checksum)
	// checksum5bit, err := convert(checksumBytes, 8, 5, false)
	checksum5bit := getChecksum(checksumData)
	if err != nil {
		return "", "", fmt.Errorf("cannot convert checksum to 5 bit due to %v", err)
	}
	addressPayload := append(data5bit, checksum5bit...)
	fmt.Printf("payload %d\n", addressPayload)
	if err != nil {
		return "", "", fmt.Errorf("cannot encode to Base32 due to %v", err)
	}
	fmt.Printf("address %x  %v\n", addressPayload, string(addressPayload))
	encodedAddress, err := Base32Encode(addressPayload)
	return prefix + ":" + encodedAddress, encodedAddress, nil
}

// PolyMod calculates 40 bit checksum
// Reference: https://github.com/bitcoincashorg/bitcoincash.org/blob/master/spec/cashaddr.md
// Credits to https://github.com/bitcoincashjs/cashaddrjs/ and https://github.com/cpacia/bchutil/blob/master/cashaddr.go
func polyMod(v []byte) uint64 {
	var c uint64 = 1
	for _, d := range v {
		c0 := byte(c >> 35)
		c = ((c & 0x07ffffffff) << 5) ^ uint64(d)

		if c0&0x01 > 0 {
			c ^= 0x98f2bc8e61
		}
		if c0&0x02 > 0 {
			c ^= 0x79b76d99e2
		}
		if c0&0x04 > 0 {
			c ^= 0xf33e5fb3c4
		}
		if c0&0x08 > 0 {
			c ^= 0xae2eabe2a8
		}
		if c0&0x10 > 0 {
			c ^= 0x1e4f43e470
		}
	}
	return c ^ 1
}

func getChecksum(checksumData []byte) []byte {
	mod := polyMod(checksumData)
	check := make([]byte, 8)
	for i := 0; i < 8; i++ {
		// Convert the 5-bit groups in mod to checksum values.
		check[i] = byte((mod >> uint(5*(7-i))) & 0x1f)
	}
	return check
}

// FullPrefixTo5Bit returns an array of byte with with the lower 5 bit of every prefix char plus a 0 for the colon separator
func FullPrefixTo5Bit(prefix string) []byte {
	ret := make([]byte, len(prefix)+1) // one more for the separator
	for i := 0; i < len(prefix); i++ {
		ret[i] = byte(prefix[i]) & 0x1f
	}
	ret[len(prefix)] = 0 // separator
	return ret
}

func fromHash(prefix string, addrType int8, hash []byte) (string, string, error) {
	hashSize, err := getHashSize(hash) //ripemd160 is 160 bit -> 0
	if err != nil {
		return "", "", fmt.Errorf("cannot get hash size because %v", err)
	}
	versionByte := byte(addrType + hashSize)
	fmt.Printf("version byte  %d\n", versionByte)
	prefixBytes := FullPrefixTo5Bit(prefix) //OK
	fmt.Printf("prefix byte 5 %d\n", prefixBytes)
	data := append([]byte{versionByte}, hash...)
	fmt.Printf("data          %d\n", data)
	data5bit, err := convert(data, 8, 5, false)
	fmt.Printf("data 5 bits   %d\n", data5bit)
	if err != nil {
		return "", "", fmt.Errorf("cannot convert data to 5 bit due to %v", err)
	}
	checksumData := append(append(prefixBytes, data5bit...), []byte{0, 0, 0, 0, 0, 0, 0, 0}...)
	fmt.Printf("checksum data %d\n", checksumData)
	// checksum := polyMod(checksumData)
	// fmt.Printf("checksum      %d\n", checksum)
	// checksumBytes := make([]byte, 8)
	// binary.BigEndian.PutUint64(checksumBytes, checksum)
	// fmt.Printf("checksum byte %d\n", checksumBytes)
	// checksum5bit, err := convert(checksumBytes, 8, 5, false)
	checksum5bit := getChecksum(checksumData)
	fmt.Printf("checksum 5    %d\n", checksum5bit)
	if err != nil {
		return "", "", fmt.Errorf("cannot convert checksum to 5 bit due to %v", err)
	}
	addressPayload := append(data5bit, checksum5bit...)
	fmt.Printf("payload       %d\n", addressPayload)
	if err != nil {
		return "", "", fmt.Errorf("cannot encode to Base32 due to %v", err)
	}
	fmt.Printf("address       %x  %v\n", addressPayload, string(addressPayload))
	encodedAddress, err := Base32Encode(addressPayload)
	return prefix + ":" + encodedAddress, encodedAddress, nil
}

func convert(data []byte, inSize uint, toSize uint, strict bool) ([]byte, error) {
	var outLen int
	if strict {
		outLen = int(math.Floor((float64(len(data)) * float64(inSize)) / float64(toSize)))
	} else {
		outLen = int(math.Ceil((float64(len(data)) * float64(inSize)) / float64(toSize)))
	}
	mask := uint((1 << toSize) - 1)
	result := make([]byte, outLen, outLen)
	index := 0
	var accumulator uint
	var bits uint
	for i := 0; i < len(data); i++ {
		value := uint(data[i])
		if (value < 0) || ((value >> inSize) != 0) {
			return nil, fmt.Errorf("invalid value %x", value)
		}
		accumulator = (accumulator << inSize) | value
		bits += inSize
		for bits >= toSize {
			bits -= toSize
			result[index] = byte((accumulator >> bits) & mask)
			index++
		}
	}
	end := byte((accumulator << (toSize - bits)) & mask)
	if !strict {
		if bits > 0 {
			result[index] = end
			index++
		}
	} else {
		if (bits > inSize) || (end != 0) {
			return nil, fmt.Errorf("strict mode required but input connot be converted to %d bits without padding", toSize)
		}
	}
	return result, nil
}

func getHashSize(hash []byte) (int8, error) {
	switch len(hash) * 8 {
	case 160:
		return 0, nil
	case 192:
		return 1, nil
	case 224:
		return 2, nil
	case 256:
		return 3, nil
	case 320:
		return 4, nil
	case 384:
		return 5, nil
	case 448:
		return 6, nil
	case 512:
		return 7, nil
	default:
		return -1, fmt.Errorf("invalid hash size: %d ", len(hash))
	}
}
