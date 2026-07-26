package ctlrec

import "fmt"

// Codec is one frozen control-payload encoding. A journal epoch declares
// exactly one control codec; every control record in that epoch is encoded
// and decoded with it. Mixing codecs within an epoch is prohibited, so the
// decoder for the WRONG codec must reject the other codec's bytes (gob
// payloads start with a version byte 1/2; PFC1 payloads start with "PFC1",
// which the gob path rejects as an unsupported version, and the PFC1 path
// rejects anything without its magic).
type Codec struct {
	Name   string
	Encode func(Payload) ([]byte, error)
	Decode func([]byte) (Payload, error)
	// MaxEncodedBytes is the codec's hard payload ceiling (admission bound).
	MaxEncodedBytes int
}

// GobCodec is the legacy local-mode codec (version byte + gob). It remains
// the file WAL's codec; the managed remote journal never accepts it for a new
// epoch, and outside explicit local/migration modes it is DECODE-ONLY.
var GobCodec = Codec{
	Name:            GobControlCodec,
	Encode:          Encode,
	Decode:          Decode,
	MaxEncodedBytes: MaxEncodedControlBytes,
}

// PFC1 is the production canonical codec for legacy pfr1 generations.
var PFC1 = Codec{
	Name:            PFC1Codec,
	Encode:          EncodePFC1,
	Decode:          DecodePFC1,
	MaxEncodedBytes: MaxPFC1Bytes,
}

// CodecByName resolves a generation's declared control codec.
func CodecByName(name string) (Codec, error) {
	switch name {
	case GobControlCodec:
		return GobCodec, nil
	case PFC1Codec:
		return PFC1, nil
	default:
		return Codec{}, fmt.Errorf("ctlrec: unknown control codec %q", name)
	}
}
