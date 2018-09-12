package cashaddr

import (
	"bytes"
	"encoding/hex"
	"math/rand"
	"strings"
	"testing"
)

func TestChecksum(t *testing.T) {
	str := "bitcoincash:qpzry9x8gf2tvdw0s3jn54khce6mua7lcw20ayyn"
	strSplit := strings.Split(str, ":")
	prefix := strSplit[0]
	payload := strSplit[1]
	decodedPrefix := fullPrefixTo5Bit(prefix)
	decodedPayload, err := Base32Decode(payload)
	if err != nil {
		t.Errorf("Failed to decode payload %v due to: %v\n", payload, err)
	}
	dataToVerify := decodedPrefix
	dataToVerify = append(dataToVerify, decodedPayload...)
	chksum := polyMod(dataToVerify)
	if chksum != 0 {
		t.Errorf("Checsum is not 0, chksum: %v", chksum)
	}

}

// uncompressed 044526CABB86DE7767718CA2FE13B2066BE44615DEF846A15E6F4441C114807373BAD033C052327C75B40B9D938645B59BDABBC30E9C9545B63D0F251A9A689490
// uncompressed bitcoincash:qp842l6pwrsudd7t70c2epvcyg2xc297qq5clqxfgm
func TestFromUncompressedPubKey(t *testing.T) {
	uncompressed := "044526CABB86DE7767718CA2FE13B2066BE44615DEF846A15E6F4441C114807373BAD033C052327C75B40B9D938645B59BDABBC30E9C9545B63D0F251A9A689490"
	uncompressedAdd := "bitcoincash:qp842l6pwrsudd7t70c2epvcyg2xc297qq5clqxfgm"
	pubKey, _ := hex.DecodeString(uncompressed)
	withPrefix, err := FromPubKey(pubKey)
	if err != nil {
		t.Errorf("cannot generate address due to %v", err)
	}
	if withPrefix != uncompressedAdd {
		t.Errorf("address should be %s but it is %s", uncompressedAdd, withPrefix)
	}
}

// compressed 024526CABB86DE7767718CA2FE13B2066BE44615DEF846A15E6F4441C114807373
// compress bitcoincash:qqd86hz9tnuu98sxgmk48822xaqgh6hwvvhttn6r8h
func TestFromCompressedPubKey(t *testing.T) {
	compressed := "024526CABB86DE7767718CA2FE13B2066BE44615DEF846A15E6F4441C114807373"
	compressedAdd := "bitcoincash:qqd86hz9tnuu98sxgmk48822xaqgh6hwvvhttn6r8h"
	pubKey, _ := hex.DecodeString(compressed)
	withPrefix, err := FromPubKey(pubKey)
	if err != nil {
		t.Errorf("cannot generate address due to %v", err)
	}
	if withPrefix != compressedAdd {
		t.Errorf("address should be %s but it is %s", compressedAdd, withPrefix)
	}
}

func TestFromPrivKeyBytes(t *testing.T) {
	privKey := "0D9693B7399372A42F871ACDC4ADDCEFA15C39E8B4E2B0035B18BBF75B1A7F61"
	expUncompr := "bitcoincash:qqpfam9ksmp6a783y8jet60h4hmr6plp7ccag0qanq"
	expCompres := "bitcoincash:qpz2x5tsyzf2ll7cph6ckzzpjkm96nn6qvkt5xk6l2"
	k, err := hex.DecodeString(privKey)
	if err != nil {
		t.Errorf("cannot decode private key due to %v\n", err)
	}
	compressed, err := FromPrivKey(k, true)
	if err != nil {
		t.Errorf("cannot get compressed address due to %v\n", err)
	}
	if expCompres != compressed {
		t.Errorf("compressed address should be %v but result is %v\n", expCompres, compressed)
	}
	uncompressed, err := FromPrivKey(k, false)
	if err != nil {
		t.Errorf("cannot get uncompressed address due to %v\n", err)
	}
	if expUncompr != uncompressed {
		t.Errorf("uncompressed address should be %v but result is %v\n", expUncompr, uncompressed)
	}
}
func TestFromPrivKeyHex(t *testing.T) {
	privKey := "0D9693B7399372A42F871ACDC4ADDCEFA15C39E8B4E2B0035B18BBF75B1A7F61"
	expUncompr := "bitcoincash:qqpfam9ksmp6a783y8jet60h4hmr6plp7ccag0qanq"
	expCompres := "bitcoincash:qpz2x5tsyzf2ll7cph6ckzzpjkm96nn6qvkt5xk6l2"
	compressed, err := FromPrivKeyHex(privKey, true)
	if err != nil {
		t.Errorf("cannot get compressed address due to %v\n", err)
	}
	if expCompres != compressed {
		t.Errorf("compressed address should be %v but result is %v\n", expCompres, compressed)
	}
	uncompressed, err := FromPrivKeyHex(privKey, false)
	if err != nil {
		t.Errorf("cannot get uncompressed address due to %v\n", err)
	}
	if expUncompr != uncompressed {
		t.Errorf("uncompressed address should be %v but result is %v\n", expUncompr, uncompressed)
	}
}

func TestFromBulkWIFCompressed(t *testing.T) {
	keys := make([][]string, 3)
	// PrivKey Compressed WIF, cashaddress
	keys[0] = []string{"KwdJzVEt9vVc8RuLcz9tEDAYsMUk3bBoswUGSH4yt1Juxyi7gU3G", "bitcoincash:qqd86hz9tnuu98sxgmk48822xaqgh6hwvvhttn6r8h"}
	keys[1] = []string{"Kwg8BEpwVFVGeMhW4tBhXq6rouvfqdNNzZaCm2bg7x7oxQEWqi1k", "bitcoincash:qpz2x5tsyzf2ll7cph6ckzzpjkm96nn6qvkt5xk6l2"}
	keys[2] = []string{"L3fGTEJneiVzgmNg6NCeCJeQWKNHFp8zwRi2Xk968KiH4zSrRjC7", "bitcoincash:qzlwryqkrdnewf5yft6rjrvmgr8w3xemr5p3xype64"}
	for _, v := range keys {
		address, err := FromWIF(v[0])
		if err != nil {
			t.Errorf("test failed due to %v \n", err)
		}
		if address != v[1] {
			t.Errorf("address from compressed pubkey should be %v but is %v\n", v[1], address)
		}
	}
}

func TestFromBulkWIFUncompressed(t *testing.T) {
	keys := make([][]string, 3)
	// PrivKey Compressed WIF, compressed address, uncompressed address
	keys[0] = []string{"5Hudhfa3yrGzoYUGKaLghbvpYoKyRbw76CSD7BSNVmvuL43PtPd", "bitcoincash:qp842l6pwrsudd7t70c2epvcyg2xc297qq5clqxfgm"}
	keys[1] = []string{"5Jqb9D6asTW3rkzWg61yWi8d4bnFrEtWKuWYKzgRsTL3hqNXCfZ", "bitcoincash:qpc5afcwdvqu0psg0usct5c6u3fnuyvfzqrt34z2zs"}
	keys[2] = []string{"5KWJ95ZSBbkA2Rc32DJ6Eg7iXx7uJvWUuUPQqh7cn3SHDqAGmH8", "bitcoincash:qr3yg0y8la3ap6rtxh8uw4lttvl2ypc2gv699xqxad"}
	for _, v := range keys {
		address, err := FromWIF(v[0])
		if err != nil {
			t.Errorf("test failed due to %v \n", err)
		}
		if address != v[1] {
			t.Errorf("address from uncompressed pubkey should be %v but is %v\n", v[1], address)
		}
	}
}
func TestFromBulkLegacy(t *testing.T) {
	legacyConverted := make([][]string, 6)
	// Legacy address, cashaddress
	legacyConverted[0] = []string{"15C4WVsvSyG2YoFTsqo4kGZ7aMAgYHQz6p", "qqklsq0dhqaksh3mchylnhsfv2kmutza6u38dqh8k4"}
	legacyConverted[1] = []string{"1Eo9je9UYUpgnJbqBnoDFb26SoP4LLc4zk", "qzt4gra228ptq5kmz529h0df5kafjtmgzv24vrlc9q"}
	legacyConverted[2] = []string{"13FRL2cc2Pu1Lw8vPimp7TSoSrVmzrY8UP", "qqv25cs3052kdru55qdu53n778fs3d0hzckqt8nxyc"}
	legacyConverted[3] = []string{"1KoeHg1ygc5NG2sKHRpaXnfTQwgYy4e5Ka", "qr8yfp3ur5hw3r4mjsgjlu29g6gwrjj6yuhd0mnzg9"}
	legacyConverted[4] = []string{"16DhH7baDeg3uX8hsyf4Q1k1fUWyqTMzFs", "qqun703p9sc6cdg6vhhmq4tafdspjdk4jscufk6wzs"}
	legacyConverted[5] = []string{"12xMdxaABaj6yahaLUDRVzKRBSMt6Pe4ci", "qq2hqwcju8plkp5047yjgqh8h9ayn4rwccljj6k694"}
	for _, v := range legacyConverted {
		withPref, err := FromLegacyP2PKH(v[0])
		if err != nil {
			t.Errorf("test failed due to %v \n", err)
		}
		if withPref != "bitcoincash:"+v[1] {
			t.Errorf("address converted from %v should be %v but is %v\n", v[0], "bitcoincash:"+v[1], withPref)
		}
	}
}

func TestFromHash(t *testing.T) {
	hashes := make([][]byte, 3)
	hashes[0] = []byte{118, 160, 64, 83, 189, 160, 168, 139, 218, 81, 119, 184, 106, 21, 195, 178, 159, 85, 152, 115}
	hashes[1] = []byte{203, 72, 18, 50, 41, 156, 213, 116, 49, 81, 172, 75, 45, 99, 174, 25, 142, 123, 176, 169}
	hashes[2] = []byte{1, 31, 40, 228, 115, 201, 95, 64, 19, 215, 213, 62, 197, 251, 195, 180, 45, 248, 237, 16}
	addresses := make([]string, 3)
	addresses[0] = "bitcoincash:qpm2qsznhks23z7629mms6s4cwef74vcwvy22gdx6a"
	addresses[1] = "bitcoincash:qr95sy3j9xwd2ap32xkykttr4cvcu7as4y0qverfuy"
	addresses[2] = "bitcoincash:qqq3728yw0y47sqn6l2na30mcw6zm78dzqre909m2r"
	for i, h := range hashes {
		withPrefix, onlyaddr, err := addressFromHash("bitcoincash", AddressTypeP2KH, h)
		if !strings.Contains(withPrefix, onlyaddr) {
			t.Errorf("withprefix and onlyaddr are not coherent %v %v", withPrefix, onlyaddr)
		}
		if err != nil {
			t.Errorf("cannot generate address due to %v", err)
		}
		if withPrefix != addresses[i] {
			t.Errorf("address should be %s but it is %s", addresses[i], withPrefix)
		}
	}
}

func randData(size int, max int) []byte {
	data := make([]byte, size, size)
	for i := 0; i < size; i++ {
		data[i] = uint8(rand.Int() % max)
	}
	return data
}

func TestConvertError(t *testing.T) {
	_, err := convert([]byte{100}, 5, 8, false)
	if err == nil {
		t.Errorf("Should fail when data contains invalid values.")
	} else {
		t.Logf("Error correctly returned: %v\n", err)
	}
	rd1 := randData(10, 31)
	_, err = convert(rd1, 5, 8, true)
	if err == nil {
		t.Errorf("Should fail when in strict mode padding is needed.")
	} else {
		t.Logf("Error correctly returned: %v\n", err)
	}
}

func TestConvertPaddRan1(t *testing.T) {
	rd := randData(80, 31)
	conv11, err := convert(rd, 5, 8, false)
	if err != nil {
		t.Errorf("Unexpected failure: %v\n", err)
	}
	conv12, err := convert(conv11, 8, 5, false)
	if err != nil {
		t.Errorf("Unexpected failure: %v\n", err)
	}
	if !bytes.Equal(rd, conv12) {
		t.Logf("Before %d\n", rd)
		t.Logf("After  %d\n", conv12)
		t.Errorf("Gone and return conversion should bring to the original array.\n")
	}
}
func TestConvertPaddRan1NoPad(t *testing.T) {
	rd := randData(80, 31)
	conv11, err := convert(rd, 5, 8, true)
	if err != nil {
		t.Errorf("Unexpected failure: %v\n", err)
	}
	conv12, err := convert(conv11, 8, 5, true)
	if err != nil {
		t.Errorf("Unexpected failure: %v\n", err)
	}
	if !bytes.Equal(rd, conv12) {
		t.Logf("Before %d\n", rd)
		t.Logf("After  %d\n", conv12)
		t.Errorf("Gone and return conversion should bring to the original array.\n")
	}
}
func TestConvertPaddRan2(t *testing.T) {
	rd := randData(32, 31)
	conv11, err := convert(rd, 5, 8, false)
	if err != nil {
		t.Errorf("Unexpected failure: %v\n", err)
	}
	conv12, err := convert(conv11, 8, 5, false)
	if err != nil {
		t.Errorf("Unexpected failure: %v\n", err)
	}
	if !bytes.Equal(rd, conv12) {
		t.Logf("Before %d\n", rd)
		t.Logf("After  %d\n", conv12)
		t.Errorf("Gone and return conversion should bring to the original array.\n")
	}
}

func TestConvertPaddRan3(t *testing.T) {
	rd := randData(54, 7)
	conv11, err := convert(rd, 3, 8, false)
	if err != nil {
		t.Errorf("Unexpected failure: %v\n", err)
	}
	conv12, err := convert(conv11, 8, 3, false)
	if err != nil {
		t.Errorf("Unexpected failure: %v\n", err)
	}
	if !bytes.Equal(append(rd, []byte{0, 0}...), conv12) {
		t.Logf("Before %d\n", rd)
		t.Logf("After  %d\n", conv12)
		t.Errorf("Gone and return conversion should bring to the original array.\n")
	}
}
