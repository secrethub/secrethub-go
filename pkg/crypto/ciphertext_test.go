package crypto

import (
	"bytes"
	"testing"
)

var (
	testCiphertextAES = CiphertextAES{
		Data:  []byte("testdata"),
		Nonce: []byte("testnonce"),
	}

	testCiphertextRSA = CiphertextRSA{
		Data: []byte("testdata"),
	}

	testCiphertextRSAAES = CiphertextRSAAES{
		CiphertextAES: &testCiphertextAES,
		CiphertextRSA: &testCiphertextRSA,
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

	ciphertext, err := EncryptRSAAES(input, rsaKey1.RSAPublicKey)
	if err != nil {
		t.Fatal(err)
	}

	if bytes.Equal(ciphertext.CiphertextAES.Data, input) {
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

	ciphertext := CiphertextRSAAES{}

	_, err := ciphertext.Decrypt(rsaKey)

	if err != ErrInvalidCiphertext {
		t.Error("did not return an error for decrypting with nil ciphertext")
	}
}

func TestAES_Success(t *testing.T) {
	aesKey1 := generateAESKey(t)
	aesKey2 := generateAESKey(t)

	input := []byte("secret message")

	ciphertext, err := aesKey1.Encrypt(input)
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

	ciphertext := CiphertextAES{
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

	ciphertext, err := EncryptRSA(input, rsaKey1.RSAPublicKey)
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

	ciphertext := CiphertextRSA{}

	_, err := ciphertext.Decrypt(rsaKey)

	if err != ErrInvalidCiphertext {
		t.Error("did not return an error for decrypting nil ciphertext")
	}
}
