package crypto_test

import (
	"reflect"
	"testing"

	"github.com/keylockerbv/secrethub-go/pkg/assert"
	"github.com/keylockerbv/secrethub-go/pkg/crypto"
)

// TestReEncryptionRepoKey tests to wrap a new repo key, and ReWrap this into a AESKey for another user.
func TestReEncryptionRepoKey(t *testing.T) {
	key1 := getTestKey1(t)
	key2 := getTestKey2(t)

	repoKey1, err := crypto.GenerateAESKey()
	if err != nil {
		t.Error(err)
	}

	exportedRepoKey1, err := key1.Encrypt(repoKey1.Export())
	if err != nil {
		t.Error(err)
	}

	exportedRepoKey2, err := key1.ReEncrypt(key2.RSAPublicKey, exportedRepoKey1)
	if err != nil {
		t.Error(err)
	}

	_, err = key2.Decrypt(exportedRepoKey2)
	if err != nil {
		t.Error(err)
	}
}

func TestSign_Verify(t *testing.T) {
	key1 := getTestKey1(t)

	message := []byte("TESTSIGNMESSAGE")
	signature, err := key1.Sign(message)
	if err != nil {
		t.Error(err)

	}
	pk, _ := key1.ExportPublicKey()

	err = crypto.Verify(pk, message, signature)
	if err != nil {
		t.Errorf("Crypto.Verify returned error: %s", err)
	}
}

func TestImport_Exported_PublicKey(t *testing.T) {
	key1 := getTestKey1(t)

	exportedPublicKey, err := key1.ExportPublicKey()
	if err != nil {
		t.Error(err)
	}

	_, err = crypto.ImportRSAPublicKey(exportedPublicKey)
	if err != nil {
		t.Error(err)
	}
}

func TestImport_Exported_ServiceKey(t *testing.T) {
	clientKey, err := crypto.GenerateServiceKey()
	if err != nil {
		t.Errorf("generateServiceKey generates error: %s", err)
	}

	public, err := clientKey.ExportPublicKey()
	if err != nil {
		t.Errorf("cannot import generated public key: %s", err)
	}
	_, err = crypto.ImportRSAPublicKey(public)
	if err != nil {
		t.Errorf("cannot import generated public key: %s", err)
	}

	private, err := clientKey.ExportPrivateKey()
	if err != nil {
		t.Errorf("cannot import generated public key: %s", err)
	}

	pemKey, err := crypto.ReadPEM(private)
	assert.OK(t, err)

	_, err = pemKey.Decode()
	assert.OK(t, err)
}

func TestImport_ExportedWithPassphrase(t *testing.T) {
	expected, err := crypto.GenerateRSAKey(1024)
	if err != nil {
		t.Fatal(err)
	}

	pass := "wachtwoord123"

	encrypted, err := expected.ExportPrivateKeyWithPassphrase(pass)
	if err != nil {
		t.Fatal(err)
	}

	plain, err := expected.ExportPrivateKey()
	if err != nil {
		t.Fatal(err)
	}

	if reflect.DeepEqual(plain, encrypted) {
		t.Fatalf("encrypted is the same as plain: %v (plain) == %v (encrypted)", plain, encrypted)
	}

	pemKey, err := crypto.ReadPEM(encrypted)
	assert.OK(t, err)

	actual, err := pemKey.Decrypt([]byte(pass))
	assert.OK(t, err)

	if !reflect.DeepEqual(actual, expected) {
		t.Errorf("%+v (actual) != %+v (expected)", actual, expected)
	}
}

func TestExportPrivateKeyWithEmptyPassphrase(t *testing.T) {
	expected, err := crypto.GenerateRSAKey(1024)
	if err != nil {
		t.Fatal(err)
	}

	_, err = expected.ExportPrivateKeyWithPassphrase("")
	if err != crypto.ErrEmptyPassphrase {
		t.Fatalf("unexpected error value: %v (actual) != %v (expected)", err, crypto.ErrEmptyPassphrase)
	}
}

func getTestKey1(t testing.TB) *crypto.RSAKey {
	pemKey1, err := crypto.ReadPEM(testKey1)
	assert.OK(t, err)

	key1, err := pemKey1.Decode()
	assert.OK(t, err)
	return key1
}

func getTestKey2(t testing.TB) *crypto.RSAKey {
	pemKey2, err := crypto.ReadPEM(testKey2)
	assert.OK(t, err)

	key2, err := pemKey2.Decrypt(passphraseKey2)
	assert.OK(t, err)
	return key2
}
