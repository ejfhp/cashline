package main

import (
	"flag"
	"fmt"
	"github.com/savardiego/cashline/cashaddr"
	"os"
)

//https://blog.rapid7.com/2016/08/04/build-a-simple-cli-tool-with-golang/
func main() {
	addressSet := flag.NewFlagSet("address", flag.ExitOnError)
	wif := addressSet.String("wif", "", "Private Key - WIF")
	legacyP2PKH := addressSet.String("legacyP2PKH", "", "Legacy P2PKH Address to convert to Cashaddr")
	privkey := addressSet.String("privkey", "", "Private Key (HEX)")
	pubkey := addressSet.String("pubkey", "", "Public Key (HEX)")

	if len(os.Args) == 0 {
		flag.PrintDefaults()
		os.Exit(0)
	}

	switch os.Args[1] {
	case "address":
		addressSet.Parse(os.Args[2:])
	default:
		fmt.Printf("Command unknown: %v\n", os.Args[1])
		flag.PrintDefaults()
		os.Exit(1)
	}

	if addressSet.Parsed() {
		fmt.Println()
		if addressSet.NFlag() < 1 {
			addressSet.PrintDefaults()
		}
		if len(*wif) != 0 {
			fmt.Printf("WIF: %v\n", *wif)
			address, err := cashaddr.FromWIF(*wif)
			if err != nil {
				fmt.Printf("Something bad has happened.. %v\n", err)
			} else {
				fmt.Printf("\t%v\n", address)
			}
			fmt.Println()
		}
		if len(*legacyP2PKH) != 0 {
			fmt.Printf("Legacy P2PKH: %v\n", *legacyP2PKH)
			address, err := cashaddr.FromLegacyP2PKH(*legacyP2PKH)
			if err != nil {
				fmt.Printf("Something bad has happened.. %v\n", err)
			} else {
				fmt.Printf("\t%v\n", address)
			}
			fmt.Println()
		}
		if len(*privkey) != 0 {
			fmt.Printf("Private Key: %v\n", *privkey)
			compressed, err := cashaddr.FromPrivKeyHex(*privkey, true)
			uncompress, err := cashaddr.FromPrivKeyHex(*privkey, false)
			if err != nil {
				fmt.Printf("Something bad has happened.. %v\n", err)
			} else {
				fmt.Printf("\t%v compressed\n", compressed)
				fmt.Printf("\t%v uncompressed\n", uncompress)
			}
			fmt.Println()
		}
		if len(*pubkey) != 0 {
			fmt.Printf("Public Key: %v\n", *pubkey)
			address, err := cashaddr.FromPubKeyHex(*pubkey)
			if err != nil {
				fmt.Printf("Something bad has happened.. %v\n", err)
			} else {
				fmt.Printf("\t%v\n", address)
			}
			fmt.Println()
		}
	}
}
