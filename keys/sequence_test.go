package keys

import (
	"math"
	"math/rand"
	"strconv"
	"testing"
	"time"
)

func TestFromDiceSequenceRandom(t *testing.T) {
	source := rand.NewSource(time.Now().UnixNano())
	random := rand.New(source)
	for i := 0; i < 10; i++ {
		sequence := ""
		for j := 0; j < diceSeqRequiredLength; j++ {
			c := int(math.Round(random.Float64() * 5.0))
			sequence += strconv.Itoa(c)
		}
		pk, err := FromDiceSequence(sequence)
		if err != nil {
			t.Errorf("wrong conversion, got error %v", err)
		} else {
			t.Logf("PrivateKey %X for sequence of len %d %s\n", pk, len(sequence), sequence)
		}

	}
}

func TestFromCoinflipSequenceRandom(t *testing.T) {
	source := rand.NewSource(time.Now().UnixNano())
	random := rand.New(source)
	for i := 0; i < 10; i++ {
		sequence := ""
		for j := 0; j < coinflipSeqRequiredLength; j++ {
			c := int(math.Round(random.Float64()))
			sequence += strconv.Itoa(c)
		}
		pk, err := FromCoinflipSequence(sequence)
		if err != nil {
			t.Errorf("wrong conversion, got error %v", err)
		} else {
			t.Logf("PrivateKey %X for sequence of len %d %s\n", pk, len(sequence), sequence)
		}

	}
}
