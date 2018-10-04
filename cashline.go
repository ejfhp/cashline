package main

import (
	"encoding/hex"
	"flag"
	"fmt"
	"os"

	"github.com/savardiego/cashline/keys"

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
	diceSequence := keysSet.String("dice", "", "99 dice number (1-6)")
	coinflipSequence := keysSet.String("coinflip", "", "256 coinflip number (0-1)")
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
		if addressSet.NFlag() < 1 {
			addressSet.PrintDefaults()
		}
		if len(*wif) != 0 {
			fmt.Printf("\nWIF: %v\n", *wif)
			address, err := cashaddr.FromWIF(*wif)
			exitOnError(err)
			printResult(address, "cashaddress")
		}
		if len(*legacyP2PKH) != 0 {
			fmt.Printf("\nLegacy P2PKH: %v\n", *legacyP2PKH)
			address, err := cashaddr.FromLegacyP2PKH(*legacyP2PKH)
			exitOnError(err)
			printResult(address, "cashaddress")
		}
		if len(*privkey) != 0 {
			fmt.Printf("\nPrivate Key: %v\n", *privkey)
			compressed, err := cashaddr.FromPrivKeyHex(*privkey, true)
			uncompress, err := cashaddr.FromPrivKeyHex(*privkey, false)
			exitOnError(err)
			printResult(compressed, "compressed cashaddress")
			printResult(uncompress, "uncompressed cashaddress")
		}
		if len(*pubkey) != 0 {
			fmt.Printf("\nPublic Key: %v\n", *pubkey)
			address, err := cashaddr.FromPubKeyHex(*pubkey)
			exitOnError(err)
			printResult(address, "cashaddress")
		}
	case keysSet.Parsed():
		fmt.Println()
		if keysSet.NFlag() < 1 {
			keysSet.PrintDefaults()
		}
		if len(*diceSequence) != 0 {
			fmt.Printf("\nDice sequence: %v\n", *diceSequence)
			key, err := keys.FromDiceSequence(*diceSequence)
			exitOnError(err)
			describeKey(key)
		}
		if len(*coinflipSequence) != 0 {
			fmt.Printf("\nCoinflip sequence: %v\n", *coinflipSequence)
			key, err := keys.FromCoinflipSequence(*coinflipSequence)
			exitOnError(err)
			describeKey(key)
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

func describeKey(key []byte) {
	keyStr := hex.EncodeToString(key)
	compWIF, err := keys.ToWIF(keyStr, true)
	exitOnError(err)
	printResult(compWIF, "compressed WIF")
	address, err := cashaddr.FromWIF(compWIF)
	exitOnError(err)
	printResult(address, "compressed cashaddress")
	uncoWIF, err := keys.ToWIF(keyStr, false)
	exitOnError(err)
	printResult(uncoWIF, "uncompressed WIF")
	address, err = cashaddr.FromWIF(uncoWIF)
	exitOnError(err)
	printResult(address, "uncompressed cashaddress")
	printResult(keyStr, "key in HEX")
	printResult(hex.EncodeToString(keys.Public(key, true)), "compressed public key in HEX")
	printResult(hex.EncodeToString(keys.Public(key, false)), "uncompressed public key in HEX")
}

func printResult(value, description string) {
	fmt.Printf("\t%v %s\n", value, description)
}

func exitOnError(err error) {
	if err != nil {
		fmt.Printf("Something bad has happened: %v\n", err)
		os.Exit(1)
	}

}
