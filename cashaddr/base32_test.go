package cashaddr

import (
	"testing"
)

func TestBase32EncodeDecode(t *testing.T) {
	in := "qpm2qsznhks23z7629mms6s4cwef74vcwvy22gdx6a"
	out, err := Base32Decode(in)
	if err != nil {
		t.Errorf("failed during decoding due to %v", err)
	}
	newIn, err := Base32Encode(out)
	if err != nil {
		t.Errorf("failed during encoding due to %v", err)
	}

	if in != newIn {
		t.Errorf("decoding and encoding led to a different value: %s instead of %s", newIn, in)
	}

}
