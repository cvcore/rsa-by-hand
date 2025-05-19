package myrsa

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"log"
	"math/big"
	"os"
)

type PublicKey struct {
	N *big.Int
	E int
}

type PrivateKey struct {
	P, Q, D, Dp, Dq, Qinv *big.Int
}

func loadPemFile(filename string) (*pem.Block, error) {
	if filename == "" {
		return nil, fmt.Errorf("filename cannot be empty")
	}
	data, err := os.ReadFile(filename)
	if err != nil {
		return nil, fmt.Errorf("error loading file %s: %w", filename, err)
	}
	pem, _ := pem.Decode(data)
	if pem == nil {
		return nil, fmt.Errorf("failed to decode PEM block")
	}
	return pem, nil
}

func (pk *PublicKey) LoadFromFile(filename string) error {
	// Load public key from file
	pem, err := loadPemFile(filename)
	if err != nil {
		return fmt.Errorf("error loading public key: %v", err)
	}
	if pem.Type != "PUBLIC KEY" {
		return fmt.Errorf("invalid public key type. Got %s, expected PUBLIC KEY", pem.Type)
	}

	if key, err := x509.ParsePKIXPublicKey(pem.Bytes); err == nil {
		log.Println("parsed PKIX public key")
		switch k := key.(type) {
		case *rsa.PublicKey:
			pk.N = k.N
			pk.E = k.E
			return nil
		default:
			return fmt.Errorf("unsupported public key type")
		}
	}

	if key, err := x509.ParsePKCS1PublicKey(pem.Bytes); err == nil {
		if key == nil {
			return fmt.Errorf("failed to parse PKCS1 public key")
		}
		log.Println("parsed PKCS1 public key")
		pk.N = key.N
		pk.E = key.E
		return nil
	}

	return fmt.Errorf("failed to parse: unknown public key type.")
}

func (pk *PrivateKey) LoadFromFile(filename string) error {
	// Load private key from file
	pem, err := loadPemFile(filename)
	if err != nil {
		return fmt.Errorf("error loading private key: %v", err)
	}
	if pem.Type != "PRIVATE KEY" {
		return fmt.Errorf("invalid private key type. Got %s, expected PRIVATE KEY", pem.Type)
	}

	if key, err := x509.ParsePKCS8PrivateKey(pem.Bytes); err == nil {
		log.Println("parsed PKCS8 private key")
		switch k := key.(type) {
		case *rsa.PrivateKey:
			if len(k.Primes) != 2 {
				return fmt.Errorf("invalid number of primes in RSA private key, got %d, expected 2", len(k.Primes))
			}
			pk.P = k.Primes[0]
			pk.Q = k.Primes[1]
			pk.D = k.D
			pk.Dp = k.Precomputed.Dp
			pk.Dq = k.Precomputed.Dq
			pk.Qinv = k.Precomputed.Qinv
			return nil
		default:
			return fmt.Errorf("unsupported private key type")
		}
	}

	if key, err := x509.ParsePKCS1PrivateKey(pem.Bytes); err == nil {
		log.Println("parsed PKCS1 private key")
		if key == nil {
			return fmt.Errorf("failed to parse PKCS1 private key")
		}
		if len(key.Primes) != 2 {
			return fmt.Errorf("invalid number of primes in RSA private key, got %d, expected 2", len(key.Primes))
		}
		pk.P = key.Primes[0]
		pk.Q = key.Primes[1]
		pk.D = key.D
		pk.Dp = key.Precomputed.Dp
		pk.Dq = key.Precomputed.Dq
		pk.Qinv = key.Precomputed.Qinv
		return nil
	}

	return fmt.Errorf("failed to parse: unknown private key type.")
}

func (pk *PublicKey) String() string {
	return fmt.Sprintf("Public Key:\n  N: %s\n  E: %d", pk.N.String(), pk.E)
}

func (pk *PrivateKey) String() string {
	return fmt.Sprintf(
		"Private Key:\n  P:    %s\n  Q:    %s\n  D:    %s\n  Dp:   %s\n  Dq:   %s\n  Qinv: %s",
		pk.P.String(),
		pk.Q.String(),
		pk.D.String(),
		pk.Dp.String(),
		pk.Dq.String(),
		pk.Qinv.String(),
	)
}
