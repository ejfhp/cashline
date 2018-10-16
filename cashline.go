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
	diceKSequence := keysSet.String("dice", "", "99 dice number (1-6)")
	coinflipKSequence := keysSet.String("coinflips", "", "256 coinflip number (0-1)")
	mnemonicSet := flag.NewFlagSet("mnemonic", flag.ExitOnError)
	diceMSequence := mnemonicSet.String("dice", "", "99 dice number (1-6)")
	coinflipMSequence := mnemonicSet.String("coinflips", "", "256 coinflip number (0-1)")
	hexMSequence := mnemonicSet.String("hex", "", "64 chars hex string")
	flags := make([]*flag.FlagSet, 3, 3)
	flags[0] = addressSet
	flags[1] = keysSet
	flags[2] = mnemonicSet

	if len(os.Args) < 2 {
		printDefaults(flags)
		os.Exit(0)
	}

	switch os.Args[1] {
	case "address":
		addressSet.Parse(os.Args[2:])
	case "keys":
		keysSet.Parse(os.Args[2:])
	case "mnemonic":
		mnemonicSet.Parse(os.Args[2:])
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
		if len(*diceKSequence) != 0 {
			fmt.Printf("\nDice sequence (%d chars): %v\n", len(*diceKSequence), *diceKSequence)
			if len(*diceKSequence) != keys.DiceSeqRequiredLength {
				fmt.Printf("\nSequence must be of %d chars.\n\n", keys.DiceSeqRequiredLength)
				os.Exit(0)
			}
			key, err := keys.FromDiceSequence(*diceKSequence)
			exitOnError(err)
			describeKey(key)
		}
		if len(*coinflipKSequence) != 0 {
			fmt.Printf("\nCoinflip sequence (%d chars): %v\n", len(*coinflipKSequence), *coinflipKSequence)
			if len(*coinflipKSequence) != keys.CoinflipSeqRequiredLength {
				fmt.Printf("\nSequence must be of %d chars.\n\n", keys.CoinflipSeqRequiredLength)
				os.Exit(0)
			}
			key, err := keys.FromCoinflipSequence(*coinflipKSequence)
			exitOnError(err)
			describeKey(key)
		}
	case mnemonicSet.Parsed():
		fmt.Println()
		if mnemonicSet.NFlag() < 1 {
			mnemonicSet.PrintDefaults()
		}
		if len(*diceMSequence) != 0 {
			fmt.Printf("\nDice sequence (%d chars): %v\n", len(*diceMSequence), *diceMSequence)
			if len(*diceMSequence) != keys.DiceSeqRequiredLength {
				fmt.Printf("\nSequence must be of %d chars.\n\n", keys.DiceSeqRequiredLength)
				os.Exit(0)
			}
			key, err := keys.FromDiceSequence(*diceMSequence)
			exitOnError(err)
			mn, err := keys.Mnemonic(key)
			exitOnError(err)
			printResult(mn, "24 words mnemonic")
		}
		if len(*coinflipMSequence) != 0 {
			fmt.Printf("\nCoinflip sequence (%d chars): %v\n", len(*coinflipMSequence), *coinflipMSequence)
			if len(*coinflipMSequence) != keys.CoinflipSeqRequiredLength {
				fmt.Printf("\nSequence must be of %d chars.\n\n", keys.CoinflipSeqRequiredLength)
				os.Exit(0)
			}
			key, err := keys.FromCoinflipSequence(*coinflipMSequence)
			exitOnError(err)
			mn, err := keys.Mnemonic(key)
			exitOnError(err)
			printResult(mn, "24 words mnemonic")
		}
		if len(*hexMSequence) != 0 {
			fmt.Printf("\nHex sequence (%d chars): %v\n", len(*hexMSequence), *hexMSequence)
			if len(*hexMSequence) != keys.HexSeqRequiredLength {
				fmt.Printf("\nSequence must be of %d chars.\n\n", keys.HexSeqRequiredLength)
				os.Exit(0)
			}
			key, err := hex.DecodeString(*hexMSequence)
			exitOnError(err)
			mn, err := keys.Mnemonic(key)
			exitOnError(err)
			printResult(mn, "24 words mnemonic")
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
	compWIF, err := keys.ToWIF(key, true)
	exitOnError(err)
	printResult(compWIF, "compressed WIF")
	address, err := cashaddr.FromWIF(compWIF)
	exitOnError(err)
	printResult(address, "compressed cashaddress")
	uncoWIF, err := keys.ToWIF(key, false)
	exitOnError(err)
	printResult(uncoWIF, "uncompressed WIF")
	address, err = cashaddr.FromWIF(uncoWIF)
	exitOnError(err)
	printResult(address, "uncompressed cashaddress")
	printResult(hex.EncodeToString(key), "key in HEX")
	printResult(hex.EncodeToString(keys.Public(key, true)), "compressed public key in HEX")
	printResult(hex.EncodeToString(keys.Public(key, false)), "uncompressed public key in HEX")
}

func printResult(value, description string) {
	fmt.Printf("\t%v [%s]\n", value, description)
}

func exitOnError(err error) {
	if err != nil {
		fmt.Printf("Something bad has happened: %v\n", err)
		os.Exit(1)
	}

}
