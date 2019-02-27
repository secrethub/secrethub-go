package api_test

import "github.com/keylockerbv/secrethub-go/pkg/crypto"

var (
	testCiphertextRSA = crypto.CiphertextRSA{
		Data: []byte("VGh/cyBpcyBhIHRlc3Qgc3RyaW5n"),
	}
	testCiphertextAES = crypto.CiphertextAES{
		Data:  []byte("Lwi6p9ofYSs+FeCHkmt/aacN3A8="),
		Nonce: []byte("DeLt3C9ZWZ1I4P+H"),
	}
)
