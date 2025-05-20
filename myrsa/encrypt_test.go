package myrsa

import (
	"math/big"
	"reflect"
	"testing"
)

func TestEncryptNaive(t *testing.T) {
	// Create a simple test public key
	// Using small numbers for easier testing
	pub := &PublicKey{
		N: big.NewInt(143), // 11 * 13
		E: 7,
	}

	tests := []struct {
		name        string
		message     []byte
		wantErr     bool
		expectedHex string
	}{
		{
			name:        "Encrypt small message",
			message:     []byte{0x05}, // 5 in decimal
			wantErr:     false,
			expectedHex: "2f", // 5^7 % 143 = 75 (0x4b in hex)
		},
		{
			name:        "Encrypt larger message",
			message:     []byte{0x23}, // 35 in decimal
			wantErr:     false,
			expectedHex: "8b", // 35^7 % 143 = 47 (0x2f in hex)
		},
		{
			name:        "Message too large",
			message:     []byte{0x90, 0x00}, // 36864 in decimal, larger than N (143)
			wantErr:     true,
			expectedHex: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := EncryptNaive(pub, tt.message)

			// Check error expectations
			if (err != nil) != tt.wantErr {
				t.Errorf("EncryptNaive() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			// If we expected an error, don't check the output
			if tt.wantErr {
				return
			}

			// Convert the expected hex string to bytes for comparison
			var expectedBytes []byte
			if tt.expectedHex != "" {
				// Handle the leading zero if needed
				if len(tt.expectedHex)%2 == 1 {
					tt.expectedHex = "0" + tt.expectedHex
				}

				// Convert big-endian hex to bytes
				expected := new(big.Int)
				expected.SetString(tt.expectedHex, 16)
				expectedBytes = expected.Bytes()
			}

			if !reflect.DeepEqual(got, expectedBytes) {
				t.Errorf("EncryptNaive() = %x, want %x", got, expectedBytes)
			}
		})
	}
}
