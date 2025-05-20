package myrsa_tests

import (
	"log"
	"math/big"
	"testing"

	"github.com/cvcore/rsa-by-hand/data"
	"github.com/cvcore/rsa-by-hand/myrsa"
)

func TestEncryptNaiveRoundTripSimpleKeys(t *testing.T) {
	// Create a key pair with small numbers for testing
	pub := &myrsa.PublicKey{
		N: big.NewInt(143), // 11 * 13
		E: 7,
	}

	priv := &myrsa.PrivateKey{
		P:    big.NewInt(11),
		Q:    big.NewInt(13),
		D:    big.NewInt(103), // Modular multiplicative inverse of E (7) modulo φ(N) (120)
		Dp:   big.NewInt(7),   // D mod (P-1) = 103 mod 10 = 3
		Dq:   big.NewInt(7),   // D mod (Q-1) = 103 mod 12 = 7
		Qinv: big.NewInt(12),  // Modular multiplicative inverse of Q modulo P
	}

	naiveRoundTripTest(t, pub, priv)

}

func TestEncryptNaiveRoundTripLargeKeys(t *testing.T) {
	pub := new(myrsa.PublicKey)

	if err := pub.LoadFromFile(data.Path("public_key.pem")); err != nil {
		t.Fatalf("Failed to load public key: %v", err)
	}

	priv := new(myrsa.PrivateKey)
	if err := priv.LoadFromFile(data.Path("private_key.pem")); err != nil {
		t.Fatalf("Failed to load private key: %v", err)
	}

	naiveRoundTripTest(t, pub, priv)
}

func naiveRoundTripTest(t *testing.T, pub *myrsa.PublicKey, priv *myrsa.PrivateKey) {

	testCases := []struct {
		name    string
		message []byte
	}{
		{
			name:    "Single byte message",
			message: []byte{0x05}, // 5 in decimal
		},
		{
			name:    "Multi-byte message (but still smaller than N)",
			message: []byte{0x23}, // 35 in decimal
		},
		{
			name:    "Zero message",
			message: []byte{0x00},
		},
		{
			name:    "Message close to N",
			message: []byte{0x8E}, // 142 in decimal (N-1)
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Encrypt
			encrypted, err := myrsa.EncryptNaive(pub, tc.message)
			if err != nil {
				t.Fatalf("Failed to encrypt: %v", err)
			}

			log.Printf("Encrypted message: %x", encrypted)

			// Decrypt
			decrypted, err := myrsa.DecryptNaive(priv, encrypted)
			if err != nil {
				t.Fatalf("Failed to decrypt: %v", err)
			}

			// Compare original and decrypted messages
			// Need to handle leading zeros in the original message
			originalBigInt := new(big.Int).SetBytes(tc.message)
			decryptedBigInt := new(big.Int).SetBytes(decrypted)

			if originalBigInt.Cmp(decryptedBigInt) != 0 {
				t.Errorf("Round trip failed: got %x (%v), want %x (%v)",
					decrypted, decryptedBigInt,
					tc.message, originalBigInt)
			}
		})
	}

	// Test with a slightly larger message
	t.Run("Medium-sized message", func(t *testing.T) {
		// Create larger keys for this test
		largePub := &myrsa.PublicKey{
			N: big.NewInt(0).SetInt64(3233), // 61 * 53
			E: 17,
		}

		largePriv := &myrsa.PrivateKey{
			P:    big.NewInt(61),
			Q:    big.NewInt(53),
			D:    big.NewInt(413), // Modular multiplicative inverse of 17 modulo φ(N) (60*52)
			Dp:   big.NewInt(53),  // D mod (P-1)
			Dq:   big.NewInt(5),   // D mod (Q-1)
			Qinv: big.NewInt(38),  // Modular multiplicative inverse of Q modulo P
		}

		// Message smaller than N but requires multiple bytes
		msg := big.NewInt(1234).Bytes()

		// Encrypt
		encrypted, err := myrsa.EncryptNaive(largePub, msg)
		if err != nil {
			t.Fatalf("Failed to encrypt larger message: %v", err)
		}

		// Decrypt
		decrypted, err := myrsa.DecryptNaive(largePriv, encrypted)
		if err != nil {
			t.Fatalf("Failed to decrypt larger message: %v", err)
		}

		// Compare as big integers to handle potential leading zeros
		msgBigInt := new(big.Int).SetBytes(msg)
		decryptedBigInt := new(big.Int).SetBytes(decrypted)

		if msgBigInt.Cmp(decryptedBigInt) != 0 {
			t.Errorf("Round trip failed for medium message: got %v, want %v",
				decryptedBigInt, msgBigInt)
		}
	})
}
