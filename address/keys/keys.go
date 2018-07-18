package keys

import (
	"crypto/ecdsa"
	"crypto/sha256"
	"fmt"
	"github.com/btcsuite/btcd/btcec"
	"github.com/btcsuite/btcutil/base58"
	"math/big"
)

// PrivateFromWIF decodes a base58 encoded key (compressed or uncompressed) (WIF Wallet Import Format) to []byte
func PrivateFromWIF(keyString string) (key []byte, compressed bool, err error) {
	// Decoding key using base58
	decoded := base58.Decode(keyString)
	if decoded[0] != 0x80 {
		return nil, false, fmt.Errorf("input value is not a valid mainnet key")
	}
	checkSum := decoded[len(decoded)-4:]
	hashOne := sha256.Sum256(decoded[:len(decoded)-4])
	hashTwo := sha256.Sum256(hashOne[:])
	newCheckSum := hashTwo[:4]
	if string(newCheckSum) != string(checkSum) {
		return nil, false, fmt.Errorf("cannot decode private key %v because checksum is wrong", key)
	}
	decKey := decoded[1 : len(decoded)-4]
	key = decKey
	compressed = false
	if len(decKey) == 33 && decKey[len(decKey)-1] == 0x01 {
		compressed = true
		key = decKey[:32]
	}
	fmt.Printf("Decoded key: %x compressed: %t\n", key, compressed)
	return key, compressed, nil
}

// ToWIF encode a private key to WIF (Wallet IMport Format) compressed or uncompressed
func ToWIF(privateKey []byte, compressed bool) string {
	return ""
}

// Public derivates a public key in compressed or uncompressed format from a private key
func Public(privateKey []byte, compressed bool) (pubKey []byte) {
	publicKey := derivatePublicKey(privateKey)
	if compressed {
		pubKey = toCompressedBytes(publicKey)
	} else {
		pubKey = toUncompressedBytes(publicKey)
	}
	return pubKey
}

func derivatePublicKey(key []byte) ecdsa.PublicKey {
	bigNumberKey := new(big.Int)
	bigNumberKey.SetBytes(key)
	privKey := new(ecdsa.PrivateKey)
	privKey.D = bigNumberKey
	secp256k1Curve := btcec.S256()
	privKey.PublicKey.Curve = secp256k1Curve
	privKey.PublicKey.X, privKey.PublicKey.Y = secp256k1Curve.ScalarBaseMult(bigNumberKey.Bytes())
	publicKey := privKey.PublicKey
	return publicKey
}

func toCompressedBytes(pubK ecdsa.PublicKey) (compressedPubKey []byte) {
	byteX := pubK.X.Bytes()
	//byteY := pubK.Y.Bytes()
	yIsEven := isEven(pubK.Y) //O means X is even, 1 means X is odd
	compressedPubKey = []byte{}
	//Append 0x02 if Y even and 0x03 if X is odd
	if yIsEven {
		compressedPubKey = append(compressedPubKey, 0x02)
	} else {
		compressedPubKey = append(compressedPubKey, 0x03)
	}
	compressedPubKey = append(compressedPubKey, byteX...)
	return compressedPubKey
}

func toUncompressedBytes(pubK ecdsa.PublicKey) (uncompressedPubKey []byte) {
	byteX := pubK.X.Bytes()
	byteY := pubK.Y.Bytes()
	//Append 0x04 X and Y to build public key
	uncompressedPubKey = []byte{0x04}
	uncompressedPubKey = append(uncompressedPubKey, byteX...)
	uncompressedPubKey = append(uncompressedPubKey, byteY...)
	return uncompressedPubKey
}

func isEven(num *big.Int) (even bool) {
	evenOdd := num.Bit(0) //O means X is even, 1 means X is odd
	defer func() { fmt.Printf("Number %v is even: %v\n", num, even) }()
	even = true
	if evenOdd == 1 {
		even = false
	}
	return

}
