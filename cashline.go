package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/savardiego/cashline/cashaddr"
)

//https://blog.rapid7.com/2016/08/04/build-a-simple-cli-tool-with-golang/
func main() {
	addressSet := flag.NewFlagSet("address", flag.ExitOnError)
	wif := addressSet.String("wif", "", "Private Key - WIF")
	legacyP2PKH := addressSet.String("legacyP2PKH", "", "Legacy P2PKH Address to convert to Cashaddr")
	privkey := addressSet.String("privkey", "", "Private Key (HEX)")
	pubkey := addressSet.String("pubkey", "", "Public Key (HEX)")
	keysSet := flag.NewFlagSet("keys", flag.ExitOnError)
	diceSequence := keysSet.String("dices", "", "99 dice number (1-6)")
	coinflipSequence := keysSet.String("coinflips", "", "256 coinflip number (0-1)")
	flags := make([]*flag.FlagSet, 2, 2)
	flags[0] = addressSet
	flags[1] = keysSet

	if len(os.Args) < 2 {
		printDefaults(flags)
		os.Exit(0)
	}

	switch os.Args[1] {
	case "address":
		addressSet.Parse(os.Args[2:])
	case "keys":
		keysSet.Parse(os.Args[2:])
	default:
		fmt.Printf("Command unknown: %v\n", os.Args[1])
		flag.PrintDefaults()
		os.Exit(1)
	}

	switch {
	case addressSet.Parsed():
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
	case keysSet.Parsed():
		fmt.Println()
		if keysSet.NFlag() < 1 {
			keysSet.PrintDefaults()
		}
		if len(*diceSequence) != 0 {
			fmt.Printf("Dice sequence: %v\n", *diceSequence)
			fmt.Println()
		}
		if len(*coinflipSequence) != 0 {
			fmt.Printf("Coinflip sequence: %v\n", *legacyP2PKH)
			fmt.Println()
		}
	}
}

func printDefaults(flags []*flag.FlagSet) {
	fmt.Printf("Usage: cashline <command> [options]\n")
	fmt.Printf("Please specify a command: \n")
	for i, f := range flags {
		fmt.Printf(" %d- %v\n", i, f.Name())
	}
	for i, f := range flags {
		fmt.Printf("\n")
		fmt.Printf("%d) %v\n", i, f.Name())
		f.PrintDefaults()
	}
}
