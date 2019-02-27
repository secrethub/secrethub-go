package crypto

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"

	"github.com/keylockerbv/secrethub-go/pkg/errio"
)

const (
	// RSAKeyLength defines the number of bits to use as key length for RSA keys.
	//
	// The size of 4096 bits has been chosen because 2048 bits is assumed to
	// last up to the year 2020. Have a look at https://keylength.org
	// Additionally, because 2048 bits and 4096 bits are the most commonly used
	// key lengths, we expect those key lengths to be more future proof in terms
	// of usability and we expect (more) efficient implementations to be developed
	// for those key lengths over less frequently used ones (e.g. 3072).
	RSAKeyLength = 4096
)

// Errors
var (
	errCrypto = errio.Namespace("crypto")

	ErrGenerateRSAKey                  = errCrypto.Code("rsa_generate_fail").Error("could not generate RSA key")
	ErrRSADecrypt                      = errCrypto.Code("rsa_decrypt_failed").ErrorPref("could not decrypt data: %s")
	ErrRSAEncrypt                      = errCrypto.Code("rsa_encrypt_failed").ErrorPref("could not encrypt data: %s")
	ErrNoKeyInFile                     = errCrypto.Code("no_key_in_file").Error("no key found in file")
	ErrMultipleKeysInFile              = errCrypto.Code("multiple_keys_in_file").Error("multiple keys found in file")
	ErrNotPKCS1Format                  = errCrypto.Code("key_wrong_format").Error("key must be in pkcs1 format")
	ErrNoPublicKeyFoundInImport        = errCrypto.Code("no_public_key_in_import").Error("no public key found in import")
	ErrMultiplePublicKeysFoundInImport = errCrypto.Code("multiple_public_keys_in_import").Error("multiple public keys found in import")
	ErrKeyTypeNotSupported             = errCrypto.Code("key_type_not_supported").Error("key type is not supported")
	ErrEmptyPassphrase                 = errCrypto.Code("empty_passphrase").Error("passphrase is empty")

	ErrEmptyPublicKey = errors.New("public key should not be empty")
)

// RSAPublicKey provides asymmetric encryption and signature verification functions.
type RSAPublicKey struct {
	publicKey *rsa.PublicKey
}

// Encrypt uses the public key to encrypt given data with the RSA-OAEP algorithm,
// returning the resulting ciphertext. In order to encrypt the given bytes, it
// first generates a random symmetric key and uses the AES-GCM algorithm to encrypt
// the data. Then, it uses the RSA public key to encrypt the intermediate symmetric
// key with the RSA-OAEP algorithm and combines both ciphertexts into one result.
func (pub RSAPublicKey) Encrypt(data []byte) (CiphertextRSAAES, error) {
	aesKey, err := GenerateSymmetricKey()
	if err != nil {
		return CiphertextRSAAES{}, errio.Error(err)
	}

	aesData, err := aesKey.Encrypt(data)
	if err != nil {
		return CiphertextRSAAES{}, errio.Error(err)
	}

	rsaData, err := pub.Wrap(aesKey.key)
	if err != nil {
		return CiphertextRSAAES{}, errio.Error(err)
	}

	return CiphertextRSAAES{
		aes: aesData,
		rsa: rsaData,
	}, nil
}

// Wrap uses the public key to encrypt a small number of bytes with the RSA-OAEP
// algorithm, returning the resulting ciphertext. The number of bytes may not exceed
// the maximum input length of the key, which can be calculated using the MaxInputLen
// function. To encrypt an arbitrary number of bytes, use the Encrypt function instead.
//
// TODO: implement a pub.MaxInputLen() int function that returns the max length of data to be used for the Wrap function.
// The message must be no longer than the length of the public modulus minus twice the hash length, minus a further 2.
// https://crypto.stackexchange.com/questions/42097/what-is-the-maximum-size-of-the-plaintext-message-for-rsa-oaep
func (pub RSAPublicKey) Wrap(data []byte) (CiphertextRSA, error) {
	encrypted, err := pub.wrap(data)
	if err != nil {
		return CiphertextRSA{}, err
	}

	return CiphertextRSA{
		Data: encrypted,
	}, nil
}

// WrapBytes uses the public key to encrypt a small number of bytes with the RSA-OAEP
// algorithm, returning the resulting encrypted bytes. Note that this function will be
// deprecated soon, so use Wrap instead.
func (pub RSAPublicKey) WrapBytes(data []byte) ([]byte, error) {
	return pub.wrap(data)
}

// wrap uses the public key to encrypt a small number of bytes with the RSA-OAEP
// algorithm, returning the resulting encrypted bytes.
func (pub RSAPublicKey) wrap(data []byte) ([]byte, error) {
	encrypted, err := rsa.EncryptOAEP(sha256.New(), rand.Reader, pub.publicKey, data, []byte{})
	if err != nil {
		return nil, ErrRSAEncrypt(err)
	}
	return encrypted, nil
}

// Verify returns nil when the given signature is the result of hashing the given
// message and signing it with the private key that corresponds to this public key.
// It returns an error when the signature is not valid (for this public key).
func (pub RSAPublicKey) Verify(message, signature []byte) error {
	hashedMessage := sha256.Sum256(message)

	return rsa.VerifyPKCS1v15(pub.publicKey, crypto.SHA256, hashedMessage[:], signature)
}

// Verify decodes the given public key and returns nil when the given signature is
// the result of hashing the given message and signing it with the private key that
// corresponds to the given public key. It returns an error when the signature is not
// valid (for this public key).
func Verify(encodedPublicKey, message, signature []byte) error {
	publicKey, err := ImportRSAPublicKey(encodedPublicKey)
	if err != nil {
		return errio.Error(err)
	}

	return publicKey.Verify(message, signature)
}

// Export uses PEM encoding to encode the public key as bytes so it
// can be easily stored and transferred between systems.
func (pub RSAPublicKey) Export() ([]byte, error) {
	asn1, err := x509.MarshalPKIXPublicKey(pub.publicKey)
	if err != nil {
		return nil, errio.Error(err)
	}

	bytes := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PUBLIC KEY",
		Bytes: asn1,
	})

	return bytes, nil
}

// Fingerprint returns the SHA256 hash of the public key, encoded as a hexadecimal string.
func (pub RSAPublicKey) Fingerprint() (string, error) {
	exported, err := pub.Export()
	if err != nil {
		return "", errio.Error(err)
	}

	sum := sha256.Sum256(exported)
	return hex.EncodeToString(sum[:]), nil
}

// ImportRSAPublicKey decodes a PEM encoded RSA public key into a public key that can be
// used for encryption and signature verification.
//
// TODO: move Import and Export together
func ImportRSAPublicKey(encodedPublicKey []byte) (RSAPublicKey, error) {
	if len(encodedPublicKey) == 0 {
		return RSAPublicKey{}, ErrEmptyPublicKey
	}

	pemBlock, rest := pem.Decode(encodedPublicKey)
	if pemBlock == nil {
		return RSAPublicKey{}, ErrNoPublicKeyFoundInImport
	} else if len(rest) > 0 {
		return RSAPublicKey{}, ErrMultiplePublicKeysFoundInImport
	}

	publicKey, err := x509.ParsePKIXPublicKey(pemBlock.Bytes)
	if err != nil {
		return RSAPublicKey{}, ErrNotPKCS1Format
	}

	rsaPublicKey, ok := publicKey.(*rsa.PublicKey)
	if !ok {
		return RSAPublicKey{}, ErrKeyTypeNotSupported
	}

	return RSAPublicKey{
		publicKey: rsaPublicKey,
	}, nil
}

// RSAKey provides asymmetric decryption and signing functionality using the RSA algorithm.
// For encryption and signature verification, see RSAPublicKey instead.
//
// TODO: rename this to RSAPrivateKey, then the RSAPrivateKey.Export function makes more sense. We don't have to be explicit about it being a private key because the type already is.
type RSAKey struct {
	private *rsa.PrivateKey
}

// NewRSAKey is used to construct an RSA key from the given private key.
// Use GenerateRSAKey to randomly generate a new RSA key.
func NewRSAKey(privateKey *rsa.PrivateKey) RSAKey {
	return RSAKey{
		private: privateKey,
	}
}

// GenerateRSAKey generates a new RSA key with the given key length.
func GenerateRSAKey(length int) (RSAKey, error) {
	privateKey, err := rsa.GenerateKey(rand.Reader, length)
	if err != nil {
		return RSAKey{}, ErrGenerateRSAKey
	}

	return NewRSAKey(privateKey), nil
}

// Public returns the public part of the RSA key pair.
func (prv RSAKey) Public() RSAPublicKey {
	return RSAPublicKey{
		publicKey: &prv.private.PublicKey,
	}
}

// Sign creates a SHA256 hash of the given message and uses the private key to
// sign the hash, returning the resulting signature.
func (prv RSAKey) Sign(message []byte) ([]byte, error) {
	hashedMessage := sha256.Sum256(message)

	return rsa.SignPKCS1v15(rand.Reader, prv.private, crypto.SHA256, hashedMessage[:])
}

// Decrypt uses the private key to decrypt the provided ciphertext, returning
// the resulting decrypted bytes. In order to decrypt the given ciphertext, it
// first unwraps the encrypted symmetric key using the RSA-OAEP algorithm and
// then uses the decrypted symmetric key to decrypt the rest of the ciphertext
// with the AES-GCM algorithm.
func (prv RSAKey) Decrypt(ciphertext CiphertextRSAAES) ([]byte, error) {
	aesKeyData, err := prv.Unwrap(ciphertext.rsa)
	if err != nil {
		return nil, err
	}

	return NewSymmetricKey(aesKeyData).decrypt(ciphertext.aes.Data, ciphertext.aes.Nonce)
}

// Unwrap uses the private key to decrypt a small ciphertext that has been encrypted
// with the RSA-OAEP algorithm, returning the resulting decrypted bytes. Note that
// this should only be used for ciphertexts encrypted with RSA-OAEP. Use the Decrypt
// function for decrypting large ciphertexts.
func (prv RSAKey) Unwrap(ciphertext CiphertextRSA) ([]byte, error) {
	if len(ciphertext.Data) == 0 {
		return []byte{}, nil
	}

	return prv.unwrap(ciphertext.Data)
}

// ReWrap uses the private key to re-encrypt a small number of encrypted bytes for
// the given public key. Note that this function will be deprecated. Directly use
// Unwrap and Wrap when possible.
//
// TODO: rename this to `ReWrapBytes`
func (prv RSAKey) ReWrap(pub RSAPublicKey, encData []byte) ([]byte, error) {

	decData, err := prv.UnwrapBytes(encData)
	if err != nil {
		return nil, errio.Error(err)
	}

	return pub.WrapBytes(decData)
}

// UnwrapBytes uses the private key to decrypt a small number of encrypted bytes with
// the RSA-OAEP algorithm, returning the resulting decrypted bytes. Note that this
// function will be deprecated. Directly use Unwrap instead when possible.
func (prv RSAKey) UnwrapBytes(encryptedData []byte) ([]byte, error) {
	return prv.unwrap(encryptedData)
}

// unwrap is a helper function that uses the private key to decrypt a small number of
// encrypted bytes with the RSA-OAEP algorithm, returning the resulting decrypted bytes.
func (prv RSAKey) unwrap(encryptedData []byte) ([]byte, error) {
	output, err := rsa.DecryptOAEP(sha256.New(), rand.Reader, prv.private, encryptedData, []byte{})
	if err != nil {
		return nil, ErrRSADecrypt(err)
	}
	return output, nil
}

// ExportPrivateKey returns the private key in PEM encoded format. After using ExportPrivateKey,
// make sure to keep the result private.
//
// TODO: rename this to ExportPEM()
func (prv RSAKey) ExportPrivateKey() ([]byte, error) {
	privateASN1 := x509.MarshalPKCS1PrivateKey(prv.private)

	privateBytes := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: privateASN1,
	})

	return privateBytes, nil
}

// Export returns the private key in ASN.1 DER encoded format.
func (prv RSAKey) Export() []byte {
	return x509.MarshalPKCS1PrivateKey(prv.private)
}

// ImportRSAPrivateKey decodes a given PEM encoded private key into an RSA private key.
//
// TODO: rename to ImportRSAPrivateKeyPEM
func ImportRSAPrivateKey(privateKey []byte) (RSAKey, error) {
	pemBlock, rest := pem.Decode(privateKey)
	if pemBlock == nil {
		return RSAKey{}, ErrNoKeyInFile

	} else if len(rest) > 0 {
		return RSAKey{}, ErrMultipleKeysInFile
	}

	privateRSAKey, err := x509.ParsePKCS1PrivateKey(pemBlock.Bytes)
	if err != nil {
		return RSAKey{}, ErrNotPKCS1Format
	}

	return NewRSAKey(privateRSAKey), nil
}

// ExportPrivateKeyWithPassphrase exports the rsa private key in a
// PKIX pem encoded format, encrypted with the given passphrase.
//
// TODO: this should be removed or deprecated if not possible.
func (prv RSAKey) ExportPrivateKeyWithPassphrase(pass string) ([]byte, error) {
	if pass == "" {
		return nil, ErrEmptyPassphrase
	}

	plain := &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(prv.private),
	}

	encrypted, err := x509.EncryptPEMBlock(rand.Reader, plain.Type, plain.Bytes, []byte(pass), x509.PEMCipherAES256)
	if err != nil {
		return nil, errio.Error(err)
	}

	return pem.EncodeToMemory(encrypted), nil
}

// CiphertextRSAAES represents data encrypted with AES-GCM, where the AES key is encrypted with RSA-OAEP.
type CiphertextRSAAES struct {
	aes CiphertextAES
	rsa CiphertextRSA
}

// MarshalJSON encodes the ciphertext in a string.
func (ct CiphertextRSAAES) MarshalJSON() ([]byte, error) {
	data := base64.StdEncoding.EncodeToString(ct.aes.Data)

	metadata := newEncodedCiphertextMetadata(map[string]string{
		"nonce": base64.StdEncoding.EncodeToString(ct.aes.Nonce),
		"key":   base64.StdEncoding.EncodeToString(ct.rsa.Data),
	})

	return json.Marshal(fmt.Sprintf("%s$%s$%s", algorithmRSAAES, data, metadata))
}

// UnmarshalJSON decodes a string into a ciphertext.
func (ct *CiphertextRSAAES) UnmarshalJSON(b []byte) error {
	var s string
	err := json.Unmarshal(b, &s)
	if err != nil {
		return err
	}

	if s == "" {
		return nil
	}

	encoded, err := newEncodedCiphertext(s)
	if err != nil {
		return err
	}

	algorithm, err := encoded.algorithm()
	if err != nil {
		return errio.Error(err)
	}

	if algorithm != algorithmRSAAES {
		return ErrWrongAlgorithm
	}

	encryptedData, err := encoded.data()
	if err != nil {
		return errio.Error(err)
	}

	metadata, err := encoded.metadata()
	if err != nil {
		return errio.Error(err)
	}

	aesNonce, err := metadata.getDecodedValue("nonce")
	if err != nil {
		return errio.Error(err)
	}

	aesKey, err := metadata.getDecodedValue("key")
	if err != nil {
		return errio.Error(err)
	}

	ct.aes = CiphertextAES{
		Data:  encryptedData,
		Nonce: aesNonce,
	}

	ct.rsa = CiphertextRSA{
		Data: aesKey,
	}

	return nil
}

// CiphertextRSA represents data encrypted with RSA-OAEP.
type CiphertextRSA struct {
	Data []byte
}

// MarshalJSON encodes the ciphertext in a string.
func (ct CiphertextRSA) MarshalJSON() ([]byte, error) {
	encodedKey := base64.StdEncoding.EncodeToString(ct.Data)

	return json.Marshal(fmt.Sprintf("%s$%s$", algorithmRSA, encodedKey))
}

// UnmarshalJSON decodes a string into a ciphertext.
func (ct *CiphertextRSA) UnmarshalJSON(b []byte) error {
	var s string
	err := json.Unmarshal(b, &s)
	if err != nil {
		return err
	}

	if s == "" {
		return nil
	}

	encoded, err := newEncodedCiphertext(s)
	if err != nil {
		return err
	}

	algorithm, err := encoded.algorithm()
	if err != nil {
		return errio.Error(err)
	}

	if algorithm != algorithmRSA {
		return ErrWrongAlgorithm
	}

	encryptedData, err := encoded.data()
	if err != nil {
		return errio.Error(err)
	}

	ct.Data = encryptedData

	return nil
}
