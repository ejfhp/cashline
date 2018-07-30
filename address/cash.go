package address

import (
	"fmt"
)

var (
	// DECODEMAP is the deconding map for base32 BCH encoding
	DECODEMAP map[byte]int
	ENCODEMAP map[int]byte
)

func init() {
	DECODEMAP = make(map[byte]int)
	DECODEMAP[byte('q')] = 0
	DECODEMAP[byte('p')] = 1
	DECODEMAP[byte('z')] = 2
	DECODEMAP[byte('r')] = 3
	DECODEMAP[byte('y')] = 4
	DECODEMAP[byte('9')] = 5
	DECODEMAP[byte('x')] = 6
	DECODEMAP[byte('8')] = 7
	DECODEMAP[byte('g')] = 8
	DECODEMAP[byte('f')] = 9
	DECODEMAP[byte('2')] = 10
	DECODEMAP[byte('t')] = 11
	DECODEMAP[byte('v')] = 12
	DECODEMAP[byte('d')] = 13
	DECODEMAP[byte('w')] = 14
	DECODEMAP[byte('0')] = 15
	DECODEMAP[byte('s')] = 16
	DECODEMAP[byte('3')] = 17
	DECODEMAP[byte('j')] = 18
	DECODEMAP[byte('n')] = 19
	DECODEMAP[byte('5')] = 20
	DECODEMAP[byte('4')] = 21
	DECODEMAP[byte('k')] = 22
	DECODEMAP[byte('h')] = 23
	DECODEMAP[byte('c')] = 24
	DECODEMAP[byte('e')] = 25
	DECODEMAP[byte('6')] = 26
	DECODEMAP[byte('m')] = 27
	DECODEMAP[byte('u')] = 28
	DECODEMAP[byte('a')] = 29
	DECODEMAP[byte('7')] = 30
	DECODEMAP[byte('l')] = 31

	ENCODEMAP = make(map[int]byte)
	for k, v := range DECODEMAP {
		ENCODEMAP[v] = k
	}
}

// PolyMod calculates 40 bit checksum
// Reference: https://github.com/bitcoincashorg/bitcoincash.org/blob/master/spec/cashaddr.md
// Credits to https://github.com/cpacia/bchutil/blob/master/cashaddr.go
func PolyMod(v []byte) uint64 {
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

// PrefixLower5Bit returns an array of byte with with the lower 5 bit of ecery prefix char
func PrefixLower5Bit(prefix string) []byte {
	ret := make([]byte, len(prefix)+1) // one more for the separator
	for i := 0; i < len(prefix); i++ {
		ret[i] = byte(prefix[i]) & 0x1f
	}
	ret[len(prefix)] = 0 // separator
	return ret
}

// DecodePayload get the paylod of an address and return the decoded array of byte
func DecodePayload(bch32 string) ([]byte, error) {
	l := len(bch32)
	decoded := make([]byte, l, l)
	for i := 0; i < l; i++ {
		c := bch32[i]
		v, ok := DECODEMAP[c]
		if !ok {
			return nil, fmt.Errorf("char not allowed in the address payload %c", c)
		}
		decoded[i] = byte(v)
	}
	return decoded, nil
}
