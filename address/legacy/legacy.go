package legacy

import (
	"crypto/sha256"
	"fmt"
	"github.com/btcsuite/btcutil/base58"
	"github.com/savardiego/cashline/address/keys"
	"golang.org/x/crypto/ripemd160"
)

// FromPubKey derivates a legacy address (version 1, the oldest) from a public key
func FromPubKey(pubKey []byte) string {
	sha256Hash := sha256.Sum256(pubKey)
	ripe160 := ripemd160.New()
	ripe160.Write(sha256Hash[:])
	ripemd160Hash := ripe160.Sum(nil)
	withVersion := append([]byte{0x00}, ripemd160Hash...)
	withVersionSha256 := sha256.Sum256(withVersion)
	withVersionSha256 = sha256.Sum256(withVersionSha256[:])
	checkSum := withVersionSha256[:4]
	withVersionAndChecksum := append(withVersion, checkSum...)
	address := base58.Encode(withVersionAndChecksum)
	return address
}

// FromPrivKey derivates a legacy address (version 1, the oldest) from a private key, in compressed or uncompressed format
func FromPrivKey(privKey []byte, compressed bool) string {
	publicKeyBytes := keys.Public(privKey, compressed)
	address := FromPubKey(publicKeyBytes)
	return address
}

// FromWIF derivates a legacy address (version 1, the oldest) from a base58 encoded WIF private key, compressed/uncompressed depending on the WIF format.
func FromWIF(privKey string) (string, error) {
	decodedPrivKey, compressed, err := keys.PrivateFromWIF(privKey)
	if err != nil {
		fmt.Printf("Cannot decode private key from base58 string: %v", privKey)
		return "", fmt.Errorf("Cannot decode private key from base58 string: %v due to %v", privKey, err)
	}
	publicKey := keys.Public(decodedPrivKey, compressed)
	address := FromPubKey(publicKey)
	return address, nil
}
