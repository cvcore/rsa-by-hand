package myrsa

import "math/big"

func DecryptNaive(priv *PrivateKey, cipher []byte) ([]byte, error) {
	// Decrypt the cipher using the private key
	cBig := big.NewInt(0).SetBytes(cipher)
	nBig := big.NewInt(0).Mul(priv.P, priv.Q)
	mBig := expMod(cBig, priv.D, nBig)
	return mBig.Bytes(), nil
}
