package myrsa

import "math/big"

func expMod(base *big.Int, exp *big.Int, mod *big.Int) *big.Int {
	// Modular exponentiation using the square-and-multiply method
	result := big.NewInt(1)
	exp = new(big.Int).Set(exp)   // Make a copy of exp to avoid modifying the original
	base = new(big.Int).Set(base) // Make a copy of base to avoid modifying the original
	base.Mod(base, mod)
	for exp.Cmp(big.NewInt(0)) > 0 {
		if exp.Bit(0) == 1 {
			result.Mul(result, base).Mod(result, mod)
		}
		exp.Rsh(exp, 1)
		base.Mul(base, base).Mod(base, mod)
	}
	return result
}
