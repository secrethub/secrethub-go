package api_test

import "github.com/keylockerbv/secrethub-go/pkg/crypto"

// getValidEncodedCipherTextRSA returns a valid EncodedCipherTextRSA to use in tests.
func getValidEncodedCipherTextRSA() crypto.EncodedCiphertextRSA {
	return "RSA-OAEP$VGh/cyBpcyBhIHRlc3Qgc3RyaW5n$"
}

// getValidEncodedCipherTextAES returns a valid EncodedCipherTextAES to use in tests.
func getValidEncodedCipherTextAES() crypto.EncodedCiphertextAES {
	return "AES-GCM$Lwi6p9ofYSs+FeCHkmt/aacN3A8=$nonce=DeLt3C9ZWZ1I4P+H"
}
