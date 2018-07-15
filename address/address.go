package address

import (
	"crypto/ecdsa"
	"crypto/sha256"
	"fmt"
	"github.com/btcsuite/btcd/btcec"
	"github.com/btcsuite/btcutil/base58"
	"golang.org/x/crypto/ripemd160"
	"math/big"
)

// DecodeBase58PrivKey decodes a base58 encoded key (WIF Wallet Import Format) to []byte
func DecodeBase58PrivKey(key string) ([]byte, bool, error) {
	// Decoding key using base58
	decoded := base58.Decode(key)
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
	defer fmt.Printf("Decoded key: %x length %d:\n", decKey, len(decKey))
	if len(decKey) == 33 && decKey[len(decKey)-1] == 0x01 {
		return decKey[:32], true, nil
	}
	return decKey[:], false, nil

}

// DerivatePublicKey derivates a public key from a private key (compressed or uncompressed)
func DerivatePublicKey(privateKey []byte, compressed bool) (compressedPubKey []byte) {
	publicKey := derivatePublicKey(privateKey)
	if compressed {
		return toCompressedBytes(publicKey)
	} else {
		return toUncompressedBytes(publicKey)
	}
}

// // CompressedV1FromPubKey derivates a version 1 (the oldest) version address from a compressed public key
// func CompressedV1FromPubKey(compressedPubKey []byte) (string, error) {
// 	if len(compressedPubKey) > 33 {
// 		return "", fmt.Errorf("Public Key is too long, should be 33bytes: %x", compressedPubKey)
// 	}
// 	sha256Hash := sha256.Sum256(compressedPubKey)
// 	ripe160 := ripemd160.New()
// 	ripe160.Write(sha256Hash[:])
// 	ripemd160Hash := ripe160.Sum(nil)
// 	withVersion := append([]byte{0x00}, ripemd160Hash...)
// 	withVersionSha256 := sha256.Sum256(withVersion)
// 	withVersionSha256 = sha256.Sum256(withVersionSha256[:])
// 	checkSum := withVersionSha256[:4]
// 	withVersionAndChecksum := append(withVersion, checkSum...)
// 	addressV1 := base58.Encode(withVersionAndChecksum)
// 	return addressV1, nil
// }

// V1FromPubKey derivates a version 1 (the oldest) version address from a compressed public key
func V1FromPubKey(compressedPubKey []byte) string {
	sha256Hash := sha256.Sum256(compressedPubKey)
	ripe160 := ripemd160.New()
	ripe160.Write(sha256Hash[:])
	ripemd160Hash := ripe160.Sum(nil)
	withVersion := append([]byte{0x00}, ripemd160Hash...)
	withVersionSha256 := sha256.Sum256(withVersion)
	withVersionSha256 = sha256.Sum256(withVersionSha256[:])
	checkSum := withVersionSha256[:4]
	withVersionAndChecksum := append(withVersion, checkSum...)
	addressV1 := base58.Encode(withVersionAndChecksum)
	return addressV1
}

// CompressedV1 derivates a version 1 (the oldest) compressed address from a private key
func CompressedV1(privKey []byte) (string, error) {
	publicKey := derivatePublicKey(privKey)
	compressedPubKey := toCompressedBytes(publicKey)
	addressV1 := V1FromPubKey(compressedPubKey)
	return addressV1, nil
}

// CompressedV1FromWIF derivates a version 1 (the oldest) compressed address from a base58 encoded WIF private key
func CompressedV1FromWIF(privKey string) (string, error) {
	if len(privKey) < 18 {
		return "", fmt.Errorf("Private Key is too short: %v", privKey)
	}
	decodedPrivKey, _, err := DecodeBase58PrivKey(privKey)
	if err != nil {
		fmt.Printf("Cannot decode private key from base58 string: %v", privKey)
		return "", fmt.Errorf("Cannot decode private key from base58 string: %v due to %v", privKey, err)
	}
	publicKey := derivatePublicKey(decodedPrivKey)
	compressedPubKey := toCompressedBytes(publicKey)
	addressV1 := V1FromPubKey(compressedPubKey)
	return addressV1, nil
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
	evenOdd := pubK.X.Bit(0) //O means X is even, 1 means X is odd
	compressedPubKey = []byte{}
	//Append 0x02 if X even and 0x03 if X is odd
	if evenOdd == 0 {
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
