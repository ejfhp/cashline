package address

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"github.com/btcsuite/btcd/btcec"
	"github.com/btcsuite/btcutil/base58"
	"golang.org/x/crypto/ripemd160"
	"math/big"
	"testing"
)

type Secp256k1 struct {
	*elliptic.CurveParams
}

func marshalToUncompressedBytes(pubK ecdsa.PublicKey) (uncompressedPubKey []byte) {
	byteX := pubK.X.Bytes()
	byteY := pubK.Y.Bytes()
	fmt.Printf("X: %x  Y:%x \n", byteX, byteY)

	//Append 0x04 X and Y to build public key
	uncompressedPubKey = []byte{0x04}
	uncompressedPubKey = append(uncompressedPubKey, byteX...)
	uncompressedPubKey = append(uncompressedPubKey, byteY...)
	fmt.Printf("Uncompressed: %x\n", uncompressedPubKey)
	return uncompressedPubKey
}

func marshalToCompressedBytes(pubK ecdsa.PublicKey) (compressedPubKey []byte) {
	byteX := pubK.X.Bytes()
	byteY := pubK.Y.Bytes()
	fmt.Printf("X: %x  Y:%x \n", byteX, byteY)
	fmt.Printf("X: %v  Y:%v \n", pubK.X, pubK.Y)
	evenOdd := pubK.X.Bit(0)
	fmt.Printf("O means X is even: %d\n", evenOdd)
	compressedPubKey = []byte{}
	//Append 0x02 if X even and 0x03 if X is odd
	if evenOdd == 0 {
		compressedPubKey = append(compressedPubKey, 0x02)
	} else {
		compressedPubKey = append(compressedPubKey, 0x03)
	}
	compressedPubKey = append(compressedPubKey, byteX...)
	fmt.Printf("Compressed: %x\n", compressedPubKey)
	return compressedPubKey
}

func derivatePublicKey(key []byte, curve elliptic.Curve) ecdsa.PublicKey {
	fmt.Printf("PrivateKey is %x of length=%d\n", key, len(key))
	bigNumberKey := new(big.Int)
	bigNumberKey.SetBytes(key)
	fmt.Printf("Big.Int HEX %x\n", bigNumberKey.Bytes())
	fmt.Printf("Big.Int num %v\n", bigNumberKey)

	privKey := new(ecdsa.PrivateKey)
	privKey.D = bigNumberKey
	privKey.PublicKey.Curve = curve
	privKey.PublicKey.X, privKey.PublicKey.Y = curve.ScalarBaseMult(bigNumberKey.Bytes())
	publicKey := privKey.PublicKey
	return publicKey
}

func makeSecp256k1Curve() elliptic.Curve {
	bchCurve := btcec.S256()
	return bchCurve
}

func decodeBase58Example() {
	// Example from http://gobittest.appspot.com/PrivateKey
	encodedKey := Key("5HueCGU8rMjxEXxiPuD5BDku4MkFqeZyd4dZ1jvhTVqvbTLvyTJ")
	fmt.Printf("BCH private key is %v\n", encodedKey)

	// Decoding key using base58
	decoded, version, err := base58.CheckDecode(string(encodedKey))
	if err != nil {
		fmt.Println("Cannot decode private key", err)
	}
	fmt.Printf("Key version is: %d\n", version)
	fmt.Printf("Base58 decoded []byte: %v\n", decoded)
	fmt.Printf("Base58 decoded []byte: %v\n", hex.EncodeToString(decoded))

}

// Key example from https://en.bitcoin.it/wiki/Technical_background_of_version_1_Bitcoin_addresses
// ECDSA KEY PAIR GENERATOR https://kjur.github.io/jsrsasign/sample/sample-ecdsa.html
func TestDecodeKey(t *testing.T) {
	fmt.Println("FROM KEY TO ADDRESS ---------------------------------------------------")
	fmt.Println("")

	// PRIV "9e6e0deb74e38262b1858279857c3f95ce7acde1ed01ec7838eb77d298efb3fb"
	// PUB "040fd18893777850957d713987160ac4922efbcf827596eb3d2eea3680053040fc9303b18c2d5068345a29b506dbfcb2a8c03394c3aed06297bd9d580dde4148b8"
	// works with "github.com/btcsuite/btcd/btcec"

	privKeyHexString := "18e14a7b6a307f426a94f8114701e7c8e774e7f9a47e2c2035db29a206321725"
	privKeyByte, err := hex.DecodeString(privKeyHexString)
	if err != nil {
		panic(err)
	}

	bchCurve := makeSecp256k1Curve()
	publicKey := derivatePublicKey(privKeyByte, bchCurve)

	comPubKey := marshalToCompressedBytes(publicKey)
	// uncomPubKey := marshalToUncompressedBytes(publicKey)

	fmt.Printf("Compressed pubkey is %x len: %v\n", comPubKey, len(comPubKey))

	fmt.Println("FROM KEY TO ADDRESS --------------------------------------------------- END")
	fmt.Println("")
	fmt.Println("")

	//Sha256 of public key
	publicKSha256 := sha256.Sum256(comPubKey)
	pkSha256 := []byte(publicKSha256[:])

	fmt.Printf("Sha256 of PubKey: %[1]T %[1]x %d\n", pkSha256, len(pkSha256))

	// Ripe160
	ripe160 := ripemd160.New()
	fmt.Printf("Ripemd160 return size is %d\n", ripe160.Size())
	ripe160.Write(pkSha256)
	pkRip160 := ripe160.Sum(nil)
	fmt.Printf("Ripemd160 of PubKey Sha256 is %x %d\n", pkRip160, len(pkRip160)) // giusto!

	withVersion := append([]byte{0x00}, pkRip160...)
	fmt.Printf("WithVersion is %x \n", withVersion) // giusto!

	shaWithVersion := sha256.Sum256(withVersion)
	fmt.Printf("Sha256 of WithVersion is %x \n", shaWithVersion) // giusto!

	shaWithVersion = sha256.Sum256(shaWithVersion[:])
	fmt.Printf("Double Sha256 of WithVersion is %x \n", shaWithVersion) // giusto!

	checkSum := shaWithVersion[:4]
	fmt.Printf("CheckSum is %x \n", checkSum) // giusto!

	ripeAndCheck := append(withVersion, checkSum...)
	fmt.Printf("Ripemd160 with Version and CheckSum is %x \n", ripeAndCheck) // giusto!

	addressV1 := base58.Encode(ripeAndCheck)
	fmt.Printf("Address V1 is %v \n", addressV1) // giusto!
}
