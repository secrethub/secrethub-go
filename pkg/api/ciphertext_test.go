package api_test

import "github.com/keylockerbv/secrethub-go/pkg/crypto"

// getValidEncodedCipherTextRSA returns a valid EncodedCipherTextRSA to use in tests.
func getValidEncodedCipherTextRSA() crypto.CiphertextRSA {
	return crypto.CiphertextRSA{
		Data: []byte("VGh/cyBpcyBhIHRlc3Qgc3RyaW5n"),
	}
}

// getValidEncodedCipherTextAES returns a valid EncodedCipherTextAES to use in tests.
func getValidEncodedCipherTextAES() crypto.CiphertextAES {
	return crypto.CiphertextAES{
		Data:  []byte("Lwi6p9ofYSs+FeCHkmt/aacN3A8="),
		Nonce: []byte("DeLt3C9ZWZ1I4P+H"),
	}
}
