package hashing

import (
	"crypto"
	"crypto/sha256"
	"database/sql/driver"
	"encoding/base64"
	"encoding/hex"
	"hash"

	"github.com/keylockerbv/secrethub/core/errio"
)

// Size is the hash bit length, set to 256 bits.
const Size = 32

// HashingAlgorithm is the hashing algorithm used and can be passed to other functions that needs this.
const HashingAlgorithm = crypto.SHA256

var (
	// EmptyHash is a shorthand for the hash of an empty slice.
	EmptyHash = Sum([]byte{})

	errHasher = errio.Namespace("hasher")
)

// Hash is a checksum
type Hash [Size]byte

// Base64 returns a string representation of the hash.
func (h Hash) Base64() string {
	return base64.StdEncoding.EncodeToString(h[:])
}

// URLSafeBase64 returns a string representation of the hash that is safe to use in URLs.
func (h Hash) URLSafeBase64() string {
	return base64.URLEncoding.EncodeToString(h.Bytes())
}

// Bytes returns a []byte representation of the hash.
func (h Hash) Bytes() []byte {
	return h[:]
}

// Hex returns the hexadecimal encoding of the hash.
func (h Hash) Hex() string {
	return hex.EncodeToString(h.Bytes())
}

// Value will write out a driver.Value or an error.
// This is used to be able to store the Hash in the database.
func (h Hash) Value() (driver.Value, error) {
	// Allows to save Hash in a Database
	return h[:], nil
}

// Scan will read a value to a Hash.
// This is used to read a Hash from the database.
func (h *Hash) Scan(value interface{}) error {
	switch v := value.(type) {
	case []uint8:
		copy(h[:], v[0:Size])
	default:
		return errHasher.Code("scan_failed").Error("cannot scan hash value")
	}

	return nil
}

// New returns a new hash.Hash that can be passed to functions that require a hasher.
func New() hash.Hash {
	return sha256.New()
}

// Sum calculates the hash of the data
func Sum(data []byte) Hash {
	return sha256.Sum256(data)
}

// Equal this function compares the hash with another hash.
func (h Hash) Equal(other Hash) bool {
	return Equal(h, other)
}

// Equal compares two hashes
func Equal(a, b Hash) bool {
	for i := 0; i < Size; i++ {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
