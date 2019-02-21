package api_test

import "github.com/keylockerbv/secrethub-go/pkg/crypto"

// getValidEncodedCipherText returns a valid EncodedCipherText to use in tests.
func getValidEncodedCipherText() crypto.EncodedCiphertext {
	return "RSA-OAEP$VGh/cyBpcyBhIHRlc3Qgc3RyaW5n$"
}

// getValidEncodedCipherTextRSA returns a valid EncodedCipherTextRSA to use in tests.
func getValidEncodedCipherTextRSA() crypto.EncodedCiphertextRSA {
	return "RSA-OAEP$VGh/cyBpcyBhIHRlc3Qgc3RyaW5n$"
}

// getValidEncodedCipherTextRSA returns a valid EncodedCipherTextRSA to use in tests.
func getValidEncodedCipherTextAES() crypto.EncodedCiphertextAES {
	return "AES-GCM$VGh/cyBpcyBhIHRlc3Qgc3RyaW5n$"
}
