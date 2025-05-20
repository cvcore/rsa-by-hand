package myrsa

import (
	"errors"
	"math/big"
)

var ErrMessageTooLong = errors.New("myrsa/encrypt: message too long")

func EncryptNaive(pub *PublicKey, message []byte) ([]byte, error) {
	// Encrypt the message using the public key
	mBig := big.NewInt(0).SetBytes(message)
	if mBig.Cmp(pub.N) >= 0 {
		return nil, ErrMessageTooLong
	}
	cipher := expMod(mBig, big.NewInt(int64(pub.E)), pub.N)
	return cipher.Bytes(), nil
}
