package correlate

import (
	"hash/fnv"
	"strings"
)

// Perms is the MinHash signature length (07 §1: 64 permutations).
const Perms = 64

// MinHash returns a 64-value MinHash signature of the 3-gram shingles of the normalised commands.
// Two signatures estimate the Jaccard similarity of the two shingle sets.
func MinHash(commands []string) []uint64 {
	shingles := map[uint64]struct{}{}
	words := []string{}
	for _, c := range commands {
		words = append(words, strings.Fields(strings.ToLower(c))...)
	}
	if len(words) == 0 {
		return nil
	}
	for i := 0; i+3 <= len(words) || (i == 0 && len(words) < 3); i++ {
		end := min(i+3, len(words))
		h := fnv.New64a()
		h.Write([]byte(strings.Join(words[i:end], " ")))
		shingles[h.Sum64()] = struct{}{}
		if end == len(words) {
			break
		}
	}
	sig := make([]uint64, Perms)
	for p := range sig {
		sig[p] = ^uint64(0)
	}
	for s := range shingles {
		for p := uint64(0); p < Perms; p++ {
			v := mix(s ^ (p*0x9E3779B97F4A7C15 + 0x632BE59BD9B4E019))
			if v < sig[p] {
				sig[p] = v
			}
		}
	}
	return sig
}

// Jaccard estimates similarity from two signatures (0 when either is empty).
func Jaccard(a, b []uint64) float64 {
	if len(a) != Perms || len(b) != Perms {
		return 0
	}
	same := 0
	for i := range a {
		if a[i] == b[i] {
			same++
		}
	}
	return float64(same) / Perms
}

// mix is the splitmix64 finaliser.
func mix(x uint64) uint64 {
	x ^= x >> 30
	x *= 0xBF58476D1CE4E5B9
	x ^= x >> 27
	x *= 0x94D049BB133111EB
	return x ^ (x >> 31)
}
