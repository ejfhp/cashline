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
		pk, err := FromDiceSequence(string(sequence))
		if err != nil {
			t.Errorf("wrong conversion, decodeBase6 retrurned an error %v", err)
		} else {
			t.Logf("PrivateKey %X for sequence of len %d %s\n", pk, len(sequence), sequence)
		}

	}
}

func TestRandom256Base2ToBase10(t *testing.T) {
	source := rand.NewSource(time.Now().UnixNano())
	random := rand.New(source)
	for i := 0; i < 10; i++ {
		sequence := ""
		for j := 0; j < binarySeqRequiredLength; j++ {
			//c := int(math.Round(random.Float64()))
			c := int(math.Round(random.Float64()))
			sequence += strconv.Itoa(c)
		}
		t.Log(sequence)
		n, err := decodeBase2(string(sequence))
		if err != nil {
			t.Errorf("wrong conversion, decodeBase2 retrurned an error %v", err)
		} else {
			t.Logf("random base2 to base10: %d for sequence of len %d %s\n", n, len(sequence), sequence)
			t.Logf("random base2 to base10 number is: %d\n", n)
		}

	}
}
