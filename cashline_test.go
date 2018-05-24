package main

import (
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"testing"
)

func TestTestVectors(t *testing.T) {
	text := "tanto va la gatta al lardo che ci lascia lo zampino"
	end := "firma"
	full := text + end

	hasher := sha256.New()
	if hasher == nil {
		t.Errorf("Sha256 is nil")
	}
	// hasher.Write([]byte("cogito ergo sum"))
	fmt.Printf("Blocksize: %v\n", hasher.BlockSize())
	fmt.Printf("Size: %v\n", hasher.Size())
	hashfull := hasher.Sum([]byte(full))
	encoded := base64.StdEncoding.EncodeToString(hashfull)
	fmt.Printf("Encoded: %v\n", encoded)

	hasher.Reset()
	hasher.Write([]byte(text))
	hashend := hasher.Sum([]byte(end))
	encodedE := base64.StdEncoding.EncodeToString(hashend)
	fmt.Printf("Encoded: %v\n", encodedE)
	fmt.Println("THE END")
}
