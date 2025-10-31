package poly1305

import (
	"bytes"
	"encoding/hex"
	"testing"
)

func TestPoly1305_RFC8439(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name        string
		keyMaterial string
		message     []byte
		expectedTag string
	}{
		{
			name:        "RFC 8439 Section 2.5.2",
			keyMaterial: "85d6be7857556d337f4452fe42d506a80103808afb0db2fd4abff6af4149f51b",
			message:     []byte("Cryptographic Forum Research Group"),
			expectedTag: "a8061dc1305136c6c22b8baf0c0127a9",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			keyMaterial, err := hex.DecodeString(tt.keyMaterial)
			if err != nil {
				t.Fatalf("failed to decode key material: %v", err)
			}

			var r [16]byte
			copy(r[:], keyMaterial[:16])

			var s [16]byte
			copy(s[:], keyMaterial[16:])

			expectedTag, err := hex.DecodeString(tt.expectedTag)
			if err != nil {
				t.Fatalf("failed to decode expected tag: %v", err)
			}

			mac := New(r, s)
			tag := mac.Sum(tt.message)

			if !bytes.Equal(tag, expectedTag) {
				t.Errorf("tag mismatch:\ngot:  %x\nwant: %x", tag, expectedTag)
			}
		})
	}
}
