package myrsa

import (
	"math/big"
	"testing"
)

func TestExpMod(t *testing.T) {
	tests := []struct {
		name     string
		base     *big.Int
		exp      *big.Int
		mod      *big.Int
		expected *big.Int
	}{
		{
			name:     "Basic exponentiation",
			base:     big.NewInt(2),
			exp:      big.NewInt(3),
			mod:      big.NewInt(10),
			expected: big.NewInt(8), // 2^3 % 10 = 8
		},
		{
			name:     "Zero base",
			base:     big.NewInt(0),
			exp:      big.NewInt(5),
			mod:      big.NewInt(7),
			expected: big.NewInt(0), // 0^5 % 7 = 0
		},
		{
			name:     "One base",
			base:     big.NewInt(1),
			exp:      big.NewInt(100),
			mod:      big.NewInt(13),
			expected: big.NewInt(1), // 1^100 % 13 = 1
		},
		{
			name:     "Large numbers",
			base:     big.NewInt(123456789),
			exp:      big.NewInt(54321),
			mod:      big.NewInt(999983), // A prime number
			expected: big.NewInt(179456), // 123456789^54321 % 999983 = 179456
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// We need to make copies because expMod modifies the inputs
			baseCopy := new(big.Int).Set(tt.base)
			expCopy := new(big.Int).Set(tt.exp)

			got := expMod(baseCopy, expCopy, tt.mod)
			if got.Cmp(tt.expected) != 0 {
				t.Errorf("expMod() = %v, want %v", got, tt.expected)
			}
		})
	}
}
