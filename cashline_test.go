package main

import (
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"testing"
)

func TestTestVectors(t *testing.T) {
	hasher := sha256.New()
	if hasher == nil {
		t.Errorf("Sha256 is nil")
	}
	// hasher.Write([]byte("cogito ergo sum"))
	fmt.Printf("Blocksize: %v\n", hasher.BlockSize())
	fmt.Printf("Size: %v\n", hasher.Size())
	hashsum := hasher.Sum([]byte("cogito ergo sum"))

	encoded := base64.StdEncoding.EncodeToString(hashsum)
	fmt.Println(encoded)

	// if !ok {
	// 	t.Error("Marshaler dont instantiate")
	// }
	// state, err := marshaler.MarshalBinary()
	// if err != nil {
	// 	t.Error("Marshaler does not work")
	// }
	fmt.Printf("Sum: %x\n", hashsum)
	fmt.Println("THE END")
}
