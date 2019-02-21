package crypto

import (
	"bytes"
	"testing"
)

var (
	testCiphertextAES = ciphertextAES{
		Data:  []byte("testdata"),
		Nonce: []byte("testnonce"),
	}

	testCiphertextRSA = ciphertextRSA{
		Data: []byte("testdata"),
	}

	testCiphertextRSAAES = ciphertextRSAAES{
		ciphertextAES: &testCiphertextAES,
		ciphertextRSA: &testCiphertextRSA,
	}
)

func generateRSAKey(t *testing.T) *RSAKey {
	key, err := GenerateRSAKey(1024)
	if err != nil {
		t.Fatal(err)
	}

	return key
}

func generateAESKey(t *testing.T) *AESKey {
	key, err := GenerateAESKey()
	if err != nil {
		t.Fatal(err)
	}

	return key
}

func TestRSAAES_Success(t *testing.T) {
	rsaKey1 := generateRSAKey(t)
	rsaKey2 := generateRSAKey(t)

	input := []byte("secret message")

	encoded, err := EncryptRSAAES(input, rsaKey1.RSAPublicKey)
	if err != nil {
		t.Fatal(err)
	}

	ciphertext, err := encoded.decode()
	if err != nil {
		t.Fatal(err)
	}

	if bytes.Equal(ciphertext.ciphertextAES.Data, input) {
		t.Error("encrypted data equals the original data")
	}

	decData, err := ciphertext.Decrypt(rsaKey1)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(decData, input) {
		t.Error("decrypted data does not equal the original data")
	}

	decDataWrongKey, err := ciphertext.Decrypt(rsaKey2)
	if err == nil {
		t.Error("did not return an error for decrypting with different key")
	}
	if decDataWrongKey != nil {
		t.Error("decrypted data with wrong key is set")
	}
}

func TestRSAAES_DecryptWrongKeyType(t *testing.T) {
	aesKey := generateAESKey(t)

	_, err := testCiphertextRSAAES.Decrypt(aesKey)

	if err != ErrWrongKeyType {
		t.Error("did not return an error for decrypting with wrong key type")
	}
}

func TestRSAAES_DecryptNilData(t *testing.T) {
	rsaKey := generateRSAKey(t)

	ciphertext := ciphertextRSAAES{}

	_, err := ciphertext.Decrypt(rsaKey)

	if err != ErrInvalidCiphertext {
		t.Error("did not return an error for decrypting with nil ciphertext")
	}
}

func TestAES_Success(t *testing.T) {
	aesKey1 := generateAESKey(t)
	aesKey2 := generateAESKey(t)

	input := []byte("secret message")

	ciphertext, err := aesKey1.encrypt(input)
	if err != nil {
		t.Fatal(err)
	}

	if bytes.Equal(ciphertext.Data, input) {
		t.Error("encrypted data equals the original data")
	}

	decData, err := ciphertext.Decrypt(aesKey1)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(decData, input) {
		t.Error("decrypted data does not equal the original data")
	}

	decDataWrongKey, err := ciphertext.Decrypt(aesKey2)
	if err == nil {
		t.Error("did not return an error for decrypting with different key")
	}
	if decDataWrongKey != nil {
		t.Error("decrypted data with wrong key is set")
	}
}

func TestAES_DecryptWrongKeyType(t *testing.T) {
	rsaKey := generateRSAKey(t)

	_, err := testCiphertextAES.Decrypt(rsaKey)

	if err != ErrWrongKeyType {
		t.Error("did not return an error for decrypting with wrong key type")
	}
}

func TestAES_DecryptNilData(t *testing.T) {
	aesKey := generateAESKey(t)

	ciphertext := ciphertextAES{
		Nonce: []byte("aa"),
	}

	_, err := ciphertext.Decrypt(aesKey)

	if err != ErrInvalidCiphertext {
		t.Error("did not return an error for decrypting with wrong key type")
	}
}

func TestRSA_Success(t *testing.T) {
	rsaKey1 := generateRSAKey(t)
	rsaKey2 := generateRSAKey(t)

	input := []byte("secret message")

	ciphertext, err := rsaKey1.RSAPublicKey.encrypt(input)
	if err != nil {
		t.Fatal(err)
	}

	if bytes.Equal(ciphertext.Data, input) {
		t.Error("encrypted data equals the original data")
	}

	decData, err := ciphertext.Decrypt(rsaKey1)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(decData, input) {
		t.Error("decrypted data does not equal the original data")
	}

	decDataWrongKey, err := ciphertext.Decrypt(rsaKey2)
	if err == nil {
		t.Error("did not return an error for decrypting with different key")
	}
	if decDataWrongKey != nil {
		t.Error("decrypted data with wrong key is set")
	}
}

func TestRSA_DecryptWrongKeyType(t *testing.T) {
	aesKey := generateAESKey(t)

	_, err := testCiphertextRSA.Decrypt(aesKey)

	if err != ErrWrongKeyType {
		t.Error("did not return an error for decrypting with wrong key type")
	}
}

func TestRSA_DecryptNilData(t *testing.T) {
	rsaKey := generateRSAKey(t)

	ciphertext := ciphertextRSA{}

	_, err := ciphertext.Decrypt(rsaKey)

	if err != ErrInvalidCiphertext {
		t.Error("did not return an error for decrypting nil ciphertext")
	}
}

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
		ek := EncodedCiphertext(test.input)

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
		output        EncryptionAlgorithm
		expectSuccess bool
	}{
		{"RSA-OAEP$dGVzdA==$", "RSA-OAEP", true},
		{"AES$dGVzdA==$", "AES", true},
		{"$dGVzdA==", "", false},
	}

	for _, test := range tests {
		ek := EncodedCiphertext(test.input)

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
		ek := EncodedCiphertext(test.input)

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
		ek := EncodedCiphertext(test.input)

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

func TestNewEncodedCiphertextMetadata(t *testing.T) {

	tests := []struct {
		input  map[string]string
		output EncodedCiphertextMetadata
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
			output: EncodedCiphertextMetadata("next=bar,param=foo"),
		},
		{
			input: map[string]string{
				"param":  "foo",
				"base64": "YWVzX2RhdGE=",
			},
			output: EncodedCiphertextMetadata("base64=YWVzX2RhdGE=,param=foo"),
		},
	}

	for _, test := range tests {

		output := NewEncodedCiphertextMetadata(test.input)

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
		ek := EncodedCiphertext(test.input)

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
		ek := EncodedCiphertext(test.input)

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
