package address

import (
	"encoding/hex"
	"strings"
	"testing"
)

func TestUncompressedV1FromPubKey(t *testing.T) {
	//https://en.bitcoin.it/wiki/Technical_background_of_version_1_Bitcoin_addresses
	uncompressed := "04d0de0aaeaefad02b8bdc8a01a1b8b11c696bd3d66a2c5f10780d95b7df42645cd85228a6fb29940e858e7e55842ae2bd115d1ed7cc0e82d934e929c97648cb0a"
	uncompressedPubKey, _ := hex.DecodeString(uncompressed)
	address := V1FromPubKey(uncompressedPubKey)
	expectedAddress := "1GAehh7TsJAHuUAeKZcXf5CnwuGuGgyX2S"
	if address != expectedAddress {
		t.Errorf("Decoded address was not the expected expected: %v, decoded: %v", expectedAddress, address)
	}
}
func TestV1FromCompressedPubKey(t *testing.T) {
	//https://en.bitcoin.it/wiki/Technical_background_of_version_1_Bitcoin_addresses
	compressed := "02d0de0aaeaefad02b8bdc8a01a1b8b11c696bd3d66a2c5f10780d95b7df42645c"
	compressedPubKey, _ := hex.DecodeString(compressed)
	address := V1FromPubKey(compressedPubKey)
	expectedAddress := "1LoVGDgRs9hTfTNJNuXKSpywcbdvwRXpmK"
	if address != expectedAddress {
		t.Errorf("Decoded address was not the expected expected: %v, decoded: %v", expectedAddress, address)
	}
}

func TestV1FromCompressedWIF(t *testing.T) {
	//https://en.bitcoin.it/wiki/Technical_background_of_version_1_Bitcoin_addresses
	WIF := "L4WSMjd6ve28Y8WHWoDxgGLw9r7Ri5eZKboqVbpZnqhAXq3gCQZf"
	address, err := CompressedV1FromWIF(WIF)
	if err != nil {
		t.Errorf("Cannot get address for key %v due to %v", WIF, err)
	}
	expectedAddress := "1KouakBQuaKQmBa9PtDhPttm4NmNABqFY4"
	if address != expectedAddress {
		t.Errorf("Decoded address was not the expected expected: %v, decoded: %v", expectedAddress, address)
	}
}
func TestCompressedV1FromPrivKey(t *testing.T) {
	//https://en.bitcoin.it/wiki/Technical_background_of_version_1_Bitcoin_addresses
	privKeyHexString := "18e14a7b6a307f426a94f8114701e7c8e774e7f9a47e2c2035db29a206321725"
	privKeyByte, err := hex.DecodeString(privKeyHexString)
	address, err := CompressedV1(privKeyByte)
	if err != nil {
		t.Errorf("Unexpected error while decoding address: %v", err)
	}
	expectedAddress := "1PMycacnJaSqwwJqjawXBErnLsZ7RkXUAs"
	if address != expectedAddress {
		t.Errorf("Decoded address was not the expected expected: %v, decoded: %v", expectedAddress, address)
	}
}
func TestBulkCompressedWIF(t *testing.T) {
	//https://en.bitcoin.it/wiki/Technical_background_of_version_1_Bitcoin_addresses
	keyAddress := [][]string{
		[]string{"14rK9eCMHnRUY4CP4Ek2uE5nREZ2uddAAR", "KwEbTtuEaCieuJ7T4qtfn4hV3jqdpQSoRjiuyYS9vMVwWqzencHA"},
		[]string{"1ASPfH9oUcdwFwpnC11wFqAQqJ2oo56P86", "L3WrDboiSWcZSV7oGzNp98doJZW1eWuJsgcrfSE4B99JEpneqo2r"},
		[]string{"18coMHq1YxoSqdiCKtzU1pFK4JBNDDnDFq", "L1L1t3Pao5YvJDh3LRUeiyLYCivEDT5Vta945ETA6C6WgswTeobf"},
		[]string{"1MZHcx9cBvErnoadrP3q6PGteKpmf8hiXS", "KyRpywmtM7LA6NSt76uTB4C7RUAwqHjnvu76PhUHHeN1ctf4H4r2"},
		[]string{"1CUV6Wx14rkgpagBZdaqu75DwvBoiMedJX", "L1Z8WYSRf4BiUH9SL9nygqDkYN1MkjWufckULNi9GA75yueoBhZD"},
		[]string{"1Espv7TwsZ4qKZc4JABXZiowoV6Z6KRmcf", "L168y9YQ2uFKcfpHWAgQoc3pGwsGQ5Y1oimH5v5FC3HQNdtBeap9"},
		[]string{"15M8kkBa3ArUx7VZG98Enwo6Ji8RTPYg2w", "L1ubgTeSbnPD2JxQSZBJgQrTjPnnJSxmeBKXxBqANMYr63Jmpagj"},
		[]string{"1K3GeJwSSjzcpVrMG2pBbH5UyzgAmNVEnW", "L5Th5hoGsSBMxFkEAPnJygr36wtAzWvGKQMyv2LmrYbm57CHsJex"},
		[]string{"1MRPV3x81GBaD4Yee76y9pnVk2wr8z6oZa", "KyWPLxbAjafWJdwsVQKjudNDrW1sjjU9VbVhmYSzvapG1n8giy9c"},
	}
	for _, pair := range keyAddress {
		address, err := CompressedV1FromWIF(pair[1])
		if err != nil {
			t.Errorf("Unexpected error while decoding address: %v", err)
		}
		if address != pair[0] {
			t.Errorf("Decoded address was not the expected expected: %v, decoded: %v", pair[0], address)
		}
	}
}
