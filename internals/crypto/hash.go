package crypto

import "crypto/sha256"

// SHA256 creates a SHA256 hash of the given bytes.
func SHA256(in []byte) []byte {
	hash := sha256.Sum256(in)
	return hash[:]
}
