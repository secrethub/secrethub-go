package crypto

import (
	"crypto/rand"

	"github.com/keylockerbv/secrethub-go/pkg/errio"
)

// GenerateNonce generates a Nonce of a particular size.
func GenerateNonce(size int) (*[]byte, error) {
	nonce := make([]byte, size)
	if _, err := rand.Read(nonce); err != nil {
		return nil, errio.Error(err)
	}
	return &nonce, nil
}
