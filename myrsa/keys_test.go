package myrsa

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"io/ioutil"
	"os"
	"testing"
)

func TestPublicKey_LoadFromFile(t *testing.T) {
	// Create temporary files for testing
	createTestKeyFiles(t)
	defer cleanupTestKeyFiles(t)

	tests := []struct {
		name     string
		filename string
		wantErr  bool
		errMsg   string
	}{
		{
			name:     "Valid PKIX Public Key",
			filename: "testdata/public_key_pkix.pem",
			wantErr:  false,
		},
		{
			name:     "Valid PKCS1 Public Key",
			filename: "testdata/public_key_pkcs1.pem",
			wantErr:  false,
		},
		{
			name:     "Empty Filename",
			filename: "",
			wantErr:  true,
			errMsg:   "invalid argument",
		},
		{
			name:     "Non-existent File",
			filename: "testdata/non_existent.pem",
			wantErr:  true,
			errMsg:   "error loading public key",
		},
		{
			name:     "Invalid PEM Type",
			filename: "testdata/private_key_pkcs1.pem",
			wantErr:  true,
			errMsg:   "invalid public key type",
		},
		{
			name:     "Invalid PEM Content",
			filename: "testdata/invalid.pem",
			wantErr:  true,
			errMsg:   "failed to decode PEM block",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pk := &PublicKey{}

			// Use defer-recover to catch fatal errors from log.Fatalf
			defer func() {
				if r := recover(); r != nil {
					if !tt.wantErr {
						t.Errorf("PublicKey.LoadFromFile() panicked: %v", r)
					}
				}
			}()

			err := pk.LoadFromFile(tt.filename)

			if (err != nil) != tt.wantErr {
				t.Errorf("PublicKey.LoadFromFile() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if err != nil && tt.errMsg != "" && err.Error() != tt.errMsg {
				if !tt.wantErr {
					t.Errorf("PublicKey.LoadFromFile() error message = %v, expected %v", err.Error(), tt.errMsg)
				}
			}

			if !tt.wantErr {
				if pk.N == nil {
					t.Errorf("PublicKey.LoadFromFile() N is nil, expected a value")
				}
				if pk.E == 0 {
					t.Errorf("PublicKey.LoadFromFile() E is 0, expected a value")
				}
			}
		})
	}
}

func TestPrivateKey_LoadFromFile(t *testing.T) {
	// Create temporary files for testing
	createTestKeyFiles(t)
	defer cleanupTestKeyFiles(t)

	tests := []struct {
		name     string
		filename string
		wantErr  bool
		errMsg   string
	}{
		{
			name:     "Valid PKCS1 Private Key",
			filename: "testdata/private_key_pkcs1.pem",
			wantErr:  false,
		},
		{
			name:     "Valid PKCS8 Private Key",
			filename: "testdata/private_key_pkcs8.pem",
			wantErr:  false,
		},
		{
			name:     "Empty Filename",
			filename: "",
			wantErr:  true,
			errMsg:   "invalid argument",
		},
		{
			name:     "Non-existent File",
			filename: "testdata/non_existent.pem",
			wantErr:  true,
			errMsg:   "error loading private key",
		},
		{
			name:     "Invalid PEM Type",
			filename: "testdata/public_key_pkix.pem",
			wantErr:  true,
			errMsg:   "invalid private key type",
		},
		{
			name:     "Invalid PEM Content",
			filename: "testdata/invalid.pem",
			wantErr:  true,
			errMsg:   "failed to decode PEM block",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pk := &PrivateKey{}

			// Use defer-recover to catch fatal errors from log.Fatalf
			defer func() {
				if r := recover(); r != nil {
					if !tt.wantErr {
						t.Errorf("PrivateKey.LoadFromFile() panicked: %v", r)
					}
				}
			}()

			err := pk.LoadFromFile(tt.filename)

			if (err != nil) != tt.wantErr {
				t.Errorf("PrivateKey.LoadFromFile() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if err != nil && tt.errMsg != "" && err.Error() != tt.errMsg {
				if !tt.wantErr {
					t.Errorf("PrivateKey.LoadFromFile() error message = %v, expected %v", err.Error(), tt.errMsg)
				}
			}

			if !tt.wantErr {
				if pk.P == nil || pk.Q == nil || pk.D == nil || pk.Dp == nil || pk.Dq == nil || pk.Qinv == nil {
					t.Errorf("PrivateKey.LoadFromFile() incomplete key data")
				}
			}
		})
	}
}

// Helper functions to create and cleanup test key files
func createTestKeyFiles(t *testing.T) {
	// Create testdata directory if it doesn't exist
	err := os.MkdirAll("testdata", 0755)
	if err != nil {
		t.Fatalf("Failed to create testdata directory: %v", err)
	}

	// Generate a test RSA key
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("Failed to generate RSA key: %v", err)
	}

	// Create PKCS1 private key file
	privateKeyPKCS1 := x509.MarshalPKCS1PrivateKey(privateKey)
	privateKeyPKCS1Block := &pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: privateKeyPKCS1,
	}
	privateKeyPKCS1PEM := pem.EncodeToMemory(privateKeyPKCS1Block)
	err = ioutil.WriteFile("testdata/private_key_pkcs1.pem", privateKeyPKCS1PEM, 0644)
	if err != nil {
		t.Fatalf("Failed to write PKCS1 private key: %v", err)
	}

	// Create PKCS8 private key file
	privateKeyPKCS8, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		t.Fatalf("Failed to marshal PKCS8 private key: %v", err)
	}
	privateKeyPKCS8Block := &pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: privateKeyPKCS8,
	}
	privateKeyPKCS8PEM := pem.EncodeToMemory(privateKeyPKCS8Block)
	err = ioutil.WriteFile("testdata/private_key_pkcs8.pem", privateKeyPKCS8PEM, 0644)
	if err != nil {
		t.Fatalf("Failed to write PKCS8 private key: %v", err)
	}

	// Create PKIX public key file
	publicKeyPKIX, err := x509.MarshalPKIXPublicKey(&privateKey.PublicKey)
	if err != nil {
		t.Fatalf("Failed to marshal PKIX public key: %v", err)
	}
	publicKeyPKIXBlock := &pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: publicKeyPKIX,
	}
	publicKeyPKIXPEM := pem.EncodeToMemory(publicKeyPKIXBlock)
	err = ioutil.WriteFile("testdata/public_key_pkix.pem", publicKeyPKIXPEM, 0644)
	if err != nil {
		t.Fatalf("Failed to write PKIX public key: %v", err)
	}

	// Create PKCS1 public key file
	publicKeyPKCS1 := x509.MarshalPKCS1PublicKey(&privateKey.PublicKey)
	publicKeyPKCS1Block := &pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: publicKeyPKCS1,
	}
	publicKeyPKCS1PEM := pem.EncodeToMemory(publicKeyPKCS1Block)
	err = ioutil.WriteFile("testdata/public_key_pkcs1.pem", publicKeyPKCS1PEM, 0644)
	if err != nil {
		t.Fatalf("Failed to write PKCS1 public key: %v", err)
	}

	// Create invalid PEM file
	err = ioutil.WriteFile("testdata/invalid.pem", []byte("This is not a valid PEM file"), 0644)
	if err != nil {
		t.Fatalf("Failed to write invalid PEM file: %v", err)
	}
}

func cleanupTestKeyFiles(t *testing.T) {
	err := os.RemoveAll("testdata")
	if err != nil {
		t.Fatalf("Failed to clean up test files: %v", err)
	}
}
