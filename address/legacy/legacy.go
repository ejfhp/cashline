package legacy

import (
	"crypto/sha256"
	"fmt"
	"github.com/btcsuite/btcutil/base58"
	"github.com/savardiego/cashline/address/keys"
)

// FromPubKey derivates a legacy address (version 1, the oldest) from a public key
func FromPubKey(pubKey []byte) (string, error) {
	hashed := keys.Hashed(pubKey)
	withVersion := append([]byte{0x00}, hashed...)
	withVersionSha256 := sha256.Sum256(withVersion)
	withVersionSha256 = sha256.Sum256(withVersionSha256[:])
	checkSum := withVersionSha256[:4]
	withVersionAndChecksum := append(withVersion, checkSum...)
	address := base58.Encode(withVersionAndChecksum)
	return address, nil
}

// FromPrivKey derivates a legacy address (version 1, the oldest) from a private key, in compressed or uncompressed format
func FromPrivKey(privKey []byte, compressed bool) (string, error) {
	publicKeyBytes := keys.Public(privKey, compressed)
	address, err := FromPubKey(publicKeyBytes)
	return address, err
}

// FromWIF derivates a legacy address (version 1, the oldest) from a base58 encoded WIF private key, compressed/uncompressed depending on the WIF format.
func FromWIF(privKey string) (string, error) {
	decodedPrivKey, compressed, err := keys.PrivateFromWIF(privKey)
	if err != nil {
		fmt.Printf("Cannot decode private key from base58 string: %v", privKey)
		return "", fmt.Errorf("Cannot decode private key from base58 string: %v due to %v", privKey, err)
	}
	publicKey := keys.Public(decodedPrivKey, compressed)
	address, err := FromPubKey(publicKey)
	return address, err
}
