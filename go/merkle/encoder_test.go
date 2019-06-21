package merkle

import (
	"bytes"
	"testing"

	"github.com/stretchr/testify/require"
)

func dummy(i int) []byte {
	return bytes.Repeat([]byte{byte(i)}, 32)
}
func dummy16(i int) (ret [16]byte) {
	x := dummy(i)
	copy(ret[:], x)
	return ret
}
func dummy32(i int) (ret [32]byte) {
	x := dummy(i)
	copy(ret[:], x)
	return ret
}

func TestEncode(t *testing.T) {
	var tests = []struct {
		desc            string
		encodingType    EncodingType
		leaf            Leaf
		key             []byte
		secret          []byte
		expectedBlinder []byte
	}{
		{
			desc:         "basic",
			encodingType: EncodingTypeBlindedSHA512_256v1,
			leaf: Chain17v1Leaf{
				TeamID: dummy16(0),
				SigID:  dummy(1),
				LinkID: dummy32(2),
				Seqno:  123,
			},
			key:    dummy(3),
			secret: dummy(4),
			expectedBlinder: []byte{0x5a, 0xad, 0x4f, 0x40, 0xe4, 0x61, 0x16,
				0xaf, 0x4a, 0xf7, 0xad, 0xaf, 0x71, 0xe1, 0x73, 0xb4, 0x8e, 0x8,
				0xed, 0xd4, 0xc7, 0xce, 0x9f, 0x0, 0x30, 0xbf, 0x88, 0x19, 0x7f,
				0xd5, 0xa2, 0x25},
		},
		{
			desc:         "ensure different secret produces different blinder with same leaf",
			encodingType: EncodingTypeBlindedSHA512_256v1,
			leaf: Chain17v1Leaf{
				TeamID: dummy16(0),
				SigID:  dummy(1),
				LinkID: dummy32(2),
				Seqno:  123,
			},
			key:    dummy(3),
			secret: dummy(5),
			expectedBlinder: []byte{0x10, 0x52, 0x66, 0xf9, 0xd3, 0xdc, 0x28,
				0x42, 0xee, 0x1e, 0x4f, 0xfa, 0xa6, 0x4, 0xae, 0x57, 0x41, 0x34,
				0xa1, 0xdb, 0xf2, 0xd0, 0x28, 0xdd, 0x35, 0xc2, 0xd5, 0xfa, 0x7f,
				0x13, 0xc9, 0x67},
		},
		{
			desc:         "ensure different leaf produces different blinder with same secret",
			encodingType: EncodingTypeBlindedSHA512_256v1,
			leaf: Chain17v1Leaf{
				TeamID: dummy16(0),
				SigID:  dummy(1),
				LinkID: dummy32(3),
				Seqno:  123,
			},
			key:    dummy(3),
			secret: dummy(4),
			expectedBlinder: []byte{0x7, 0x8a, 0x8b, 0xee, 0xe5, 0x9d, 0x42,
				0x6e, 0x2c, 0x19, 0x20, 0xf, 0xde, 0xa6, 0x6d, 0xf5, 0x16, 0xdf,
				0x4f, 0x66, 0x22, 0x3f, 0xab, 0xc0, 0x4d, 0xe8, 0x9b, 0x16, 0xa4,
				0x2, 0xd9, 0x6a},
		},
	}
	for _, tt := range tests {
		e := NewEncoder(tt.encodingType)
		t.Run(tt.desc, func(t *testing.T) {
			blinder, err := e.Encode(tt.leaf, NewKey(tt.key), NewSecret(tt.secret))
			require.NoError(t, err)
			require.Equal(t, blinder, tt.expectedBlinder)

			preimage, err := e.BlindedPreimage(tt.leaf, NewKey(tt.key), NewSecret(tt.secret))
			require.NoError(t, err)
			blinder2, err := e.Hash(preimage)
			require.NoError(t, err)
			require.Equal(t, blinder, blinder2, "got same blinder via validation route")
		})
	}

}

func TestGenerateSecret(t *testing.T) {
	e := NewEncoder(EncodingTypeBlindedSHA512_256v1)
	x, err := e.GenerateSecret()
	require.NoError(t, err)
	y, err := e.GenerateSecret()
	require.NoError(t, err)

	require.NotEqual(t, x, y)
}
