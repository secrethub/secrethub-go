package api_test

import (
	"bytes"
	"testing"

	"github.com/keylockerbv/secrethub-go/pkg/api"
	"github.com/keylockerbv/secrethub-go/pkg/crypto"
)

func TestEncodedCiphertext_Validate(t *testing.T) {

	tests := []struct {
		input         string
		expectSuccess bool
	}{
		{"RSA-OAEP$VGh/cyBpcyBhIHRlc3Qgc3RyaW5n$", true},
		{"RSA-OAEP$dGVzdA==$", true},                                       // Allow ending of base64-encoded data with ==
		{"AES$VGhpcyBpcyBhIHRlc3Qgc3RyaW5n$l=5", true},                     // Allow parameter
		{"AES$VGhpcyBpcyBhIHRlc3Qgc3RyaW5n$param=foo,next=bar", true},      // Allow multiple parameters
		{"AES$VGhpcyBpcyBhIHRlc3Qgc3RyaW5n$param=ab/+s7==,next=bar", true}, // Allow base64-encoded metadata
		{"AES$VGhpcyBpcyBhIHRlc3Qgc3RyaW5n$param=foo,next=bar,", true},     // Allow ending with ,
		{"RSA-OAEP$VGh/cyBpcyBhIHRlc3Qgc3RyaW5n", false},                   // No trailing $
		{"RSA-OAEP$__$", false},                                            // Invalid base64
		{"$VGhpcyBpcyBhIHRlc3Qgc3RyaW5n==$", false},                        // No algorithm
		{"RSA-OAEP$VGhpcyBpcyBhIHRlc3Qgc3RyaW5n===$", false},               // Do not allow ending of base64-encoded data with ===
		{"AES$VGhpcyBpcyBhIHRlc3Qgc3RyaW5n$$", false},                      // An extra trailing $
		{"A_ES$VGhpcyBpcyBhIHRlc3Qgc3RyaW5n$$", false},                     // Invalid character in algorithm
		{"AES$VGhpcyBpcyBhIHRlc3Qgc3RyaW5n$,param=foo,next=bar", false},    // Comma before metadata
		{"AES$VGhpcyBpcyBhIHRlc3Qgc3RyaW5n$param=foonext=bar", false},      // No comma between parameters
		{"AES$VGhpcyBpcyBhIHRlc3Qgc3RyaW5n$param=", false},                 // Empty parameter
		{"AES$VGhpcyBpcyBhIHRlc3Qgc3RyaW5n$=val", false},                   // Unnamed parameter
		{"AES $VGhpcyBpcyBhIHRlc3Qgc3RyaW5n$=val", false},                  // Spaces are not allowed
	}

	for _, test := range tests {
		ek := api.EncodedCiphertext(test.input)

		err := ek.Validate()

		success := err == nil

		if success != test.expectSuccess {
			t.Errorf("expected success=%v but got success=%v for string %s", test.expectSuccess, success, test.input)
		}
	}

}

func TestEncodedCiphertext_GetAlgorithm(t *testing.T) {
	tests := []struct {
		input         string
		output        api.EncryptionAlgorithm
		expectSuccess bool
	}{
		{"RSA-OAEP$dGVzdA==$", "RSA-OAEP", true},
		{"AES$dGVzdA==$", "AES", true},
		{"$dGVzdA==", "", false},
	}

	for _, test := range tests {
		ek := api.EncodedCiphertext(test.input)

		alg, err := ek.GetAlgorithm()

		success := err == nil

		if success != test.expectSuccess {
			t.Errorf("expected success=%v but got success=%v for string %s", test.expectSuccess, success, test.input)
		}

		if alg != test.output {
			t.Errorf("expected output=%v but got output=%v for string %s", test.output, alg, test.input)
		}
	}
}

func TestEncodedCiphertext_GetKey(t *testing.T) {
	tests := []struct {
		input         string
		output        []byte
		expectSuccess bool
	}{
		{"AES$dGVzdGtleQ==$", []byte("testkey"), true},
		{"AES$AQIDBA==$", []byte{1, 2, 3, 4}, true},
		{"AES$$", []byte(""), false},
	}

	for _, test := range tests {
		ek := api.EncodedCiphertext(test.input)

		key, err := ek.GetData()

		success := err == nil

		if success != test.expectSuccess {
			t.Errorf("expected success=%v but got success=%v for string %s", test.expectSuccess, success, ek)
		}

		if !bytes.Equal(key, test.output) {
			t.Errorf("expected output=%s but got output=%s for string %s", test.output, key, test.input)
		}
	}
}

func TestEncodedCiphertext_GetMetadata(t *testing.T) {
	tests := []struct {
		input         string
		output        string
		expectSuccess bool
	}{
		{"AES$dGVzdA==$param=foo,", "param=foo,", true},
		{"AES$dGVzdA==$param=foo,second=bar", "param=foo,second=bar", true},
		{"AES$dGVzdA==$", "", true},
		{"AES$dGVzdA==$a", "", false},
	}

	for _, test := range tests {
		ek := api.EncodedCiphertext(test.input)

		metadata, err := ek.GetMetadata()

		success := err == nil

		if success != test.expectSuccess {
			t.Errorf("expected success=%v but got success=%v for string %s", test.expectSuccess, success, test.input)
		}

		if string(metadata) != test.output {
			t.Errorf("expected output=%s but got output=%s for string %s", test.output, metadata, test.input)
		}
	}
}

type UnknownCiphertext struct{}

func (d *UnknownCiphertext) Decrypt(k crypto.Key) ([]byte, error) {
	return nil, nil
}

func (d *UnknownCiphertext) ReEncrypt(k1, k2 crypto.Key) (crypto.Ciphertext, error) {
	return nil, nil
}

func TestEncodeCiphertext(t *testing.T) {

	tests := []struct {
		input         crypto.Ciphertext
		output        api.EncodedCiphertext
		expectSuccess bool
	}{
		{
			input: &crypto.CiphertextRSAAES{
				CiphertextAES: &crypto.CiphertextAES{
					Data:  []byte("aes_data"),
					Nonce: []byte("nonce_data"),
				},
				CiphertextRSA: &crypto.CiphertextRSA{
					Data: []byte("rsa_data"),
				},
			},
			output:        api.EncodedCiphertext("RSA-OAEP+AES-GCM$YWVzX2RhdGE=$key=cnNhX2RhdGE=,nonce=bm9uY2VfZGF0YQ=="),
			expectSuccess: true,
		},
		{
			input: &crypto.CiphertextAES{
				Data:  []byte("aes_data"),
				Nonce: []byte("nonce_data"),
			},
			output:        api.EncodedCiphertext("AES-GCM$YWVzX2RhdGE=$nonce=bm9uY2VfZGF0YQ=="),
			expectSuccess: true,
		},
		{
			input: &crypto.CiphertextRSA{
				Data: []byte("rsa_data"),
			},
			output:        api.EncodedCiphertext("RSA-OAEP$cnNhX2RhdGE=$"),
			expectSuccess: true,
		},
		{
			input:         &crypto.CiphertextRSA{},
			output:        api.EncodedCiphertext(""),
			expectSuccess: false, // No data provided
		},
		{
			input:         &crypto.CiphertextAES{},
			output:        api.EncodedCiphertext(""),
			expectSuccess: false, // No data provided
		},
		{
			input: &crypto.CiphertextRSAAES{
				CiphertextAES: &crypto.CiphertextAES{
					Data:  []byte("aes_data"),
					Nonce: []byte("nonce_data"),
				},
			},
			output:        api.EncodedCiphertext(""),
			expectSuccess: false, // Incomplete data provided
		},
		{
			input: &crypto.CiphertextRSAAES{
				CiphertextRSA: &crypto.CiphertextRSA{
					Data: []byte("rsa_data"),
				},
			},
			output:        api.EncodedCiphertext(""),
			expectSuccess: false, // Incomplete data provided
		},
		{
			input:         &UnknownCiphertext{},
			output:        api.EncodedCiphertext(""),
			expectSuccess: false, // Algorithm unknown
		},
	}

	for _, test := range tests {
		b, err := api.EncodeCiphertext(test.input)

		success := err == nil

		if success != test.expectSuccess {
			t.Errorf("expected success=%v but got success=%v for string %s", test.expectSuccess, success, test.input)
		}

		if b != test.output {
			t.Errorf("expected output=%s but got output=%s for string %s", test.output, b, test.input)
		}
	}

}

func TestNewEncodedCiphertextMetadata(t *testing.T) {

	tests := []struct {
		input  map[string]string
		output api.EncodedCiphertextMetadata
	}{
		{
			input:  map[string]string{},
			output: "",
		},
		{
			input: map[string]string{
				"param": "foo",
				"next":  "bar",
			},
			output: api.EncodedCiphertextMetadata("next=bar,param=foo"),
		},
		{
			input: map[string]string{
				"param":  "foo",
				"base64": "YWVzX2RhdGE=",
			},
			output: api.EncodedCiphertextMetadata("base64=YWVzX2RhdGE=,param=foo"),
		},
	}

	for _, test := range tests {

		output := api.NewEncodedCiphertextMetadata(test.input)

		if output != test.output {
			t.Errorf("expected output=%s but got output=%s", test.output, output)
		}

	}

}

func TestEncodedCiphertextMetadata_GetValue(t *testing.T) {
	tests := []struct {
		input         string
		name          string
		output        string
		expectSuccess bool
	}{
		{"AES$abc$param=foo,", "param", "foo", true},
		{"AES$abc$param=foo,second=bar", "second", "bar", true},
		{"AES$abc$param=foo,second=bar", "third", "", false},
		{"AES$abc$param=", "param", "", false},
	}

	for _, test := range tests {
		ek := api.EncodedCiphertext(test.input)

		metadata, err := ek.GetMetadata()
		success := err == nil

		value, err := metadata.GetValue(test.name)
		success = (err == nil) && success

		if success != test.expectSuccess {
			t.Errorf("expected success=%v but got success=%v for string %s", test.expectSuccess, success, test.input)
		}

		if value != test.output {
			t.Errorf("expected output=%s but got output=%s for string %s", test.output, value, test.input)
		}
	}
}

func TestEncodedCiphertextMetadata_GetDecodedValue(t *testing.T) {
	tests := []struct {
		input         string
		name          string
		output        []byte
		expectSuccess bool
	}{
		{"AES$abc$param=dGVzdA==", "param", []byte("test"), true},
		{"AES$aa$param=abc", "param", []byte{}, false}, //invalid base64
	}

	for _, test := range tests {
		ek := api.EncodedCiphertext(test.input)

		metadata, err := ek.GetMetadata()
		success := err == nil

		value, err := metadata.GetDecodedValue(test.name)
		success = (err == nil) && success

		if success != test.expectSuccess {
			t.Errorf("expected success=%v but got success=%v for string %s", test.expectSuccess, success, test.input)
		}

		if !bytes.Equal(value, test.output) {
			t.Errorf("expected output=%v but got output=%v for string %s", test.output, value, test.input)
		}
	}
}

// getValidEncodedCipherText returns a valid EncodedCipherText to use in tests.
func getValidEncodedCipherText() api.EncodedCiphertext {
	return "RSA-OAEP$VGh/cyBpcyBhIHRlc3Qgc3RyaW5n$"
}
