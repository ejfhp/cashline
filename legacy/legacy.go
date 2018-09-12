package legacy

import (
	"crypto/sha256"
	"fmt"
	"github.com/btcsuite/btcutil/base58"
	"github.com/savardiego/cashline/keys"
	"reflect"
)

// FromPubKey derivates a legacy address (version 1, the oldest) from a public key
func FromPubKey(pubKey []byte) (string, error) {
	hashed := keys.Hashed(pubKey)
	withVersion := append([]byte{0x00}, hashed...)
	checkSum := checksum(withVersion)
	withVersionAndChecksum := append(withVersion, checkSum...)
	address := base58.Encode(withVersionAndChecksum)
	return address, nil
}

func checksum(hashWithVer []byte) []byte {
	withVersionSha256 := sha256.Sum256(hashWithVer)
	withVersionSha256 = sha256.Sum256(withVersionSha256[:])
	checkSum := withVersionSha256[:4]
	return checkSum
}

// FromPrivKey derivates a legacy address (version 1, the oldest) from a private key, in compressed or uncompressed format
func FromPrivKey(privKey []byte, compressed bool) (string, error) {
	publicKeyBytes := keys.Public(privKey, compressed)
	address, err := FromPubKey(publicKeyBytes)
	return address, err
}

// CheckAddress checks the checksum
func CheckAddress(address string) bool {
	addressBytes := base58.Decode(address)
	checksumPart := addressBytes[len(addressBytes)-4:]
	hashPart := addressBytes[:len(addressBytes)-4]
	check := checksum(hashPart)
	return reflect.DeepEqual(check, checksumPart)
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
