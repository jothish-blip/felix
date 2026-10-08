package secrets

import (
	"math"
)

// ShannonEntropy calculates the information entropy of a string in bits per character.
// Formula: H(X) = -Σ p(x) log2 p(x)
//
// Properties:
// - Empty string returns 0.0
// - Uniform repeated characters (e.g. "aaaa") return 0.0
// - Natural language English text typically measures 3.0 to 4.2 bits
// - Random cryptographic keys/hashes typically measure > 4.5 bits
func ShannonEntropy(s string) float64 {
	if len(s) == 0 {
		return 0.0
	}

	freq := make(map[rune]float64)
	total := float64(0)

	for _, r := range s {
		freq[r]++
		total++
	}

	var entropy float64
	for _, count := range freq {
		p := count / total
		entropy -= p * math.Log2(p)
	}

	return entropy
}
