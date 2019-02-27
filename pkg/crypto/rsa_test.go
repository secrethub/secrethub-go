package crypto

import (
	"encoding/json"
	"reflect"
	"testing"

	"github.com/keylockerbv/secrethub-go/pkg/assert"
)

var (
	testKey1 = []byte("-----BEGIN RSA PRIVATE KEY-----\n" +
		"MIIEowIBAAKCAQEArPhwBeLxDvtsDK96lByxhx0wUFjgZmhx4d/rzEn3my8XGVB2\n" +
		"6BMwsrNtpcGIZkn+MFDRA1lRhaAM++pCLHdrjBVxXTLewMAO2iKZEb225U31At3G\n" +
		"4k4Pf0vBvyAqpMd+S4IQXSB68SC4H9B/OnY5WbxY0WSab1yo7pyjrHtEPfYFOCbv\n" +
		"Rx4ESyicqLgbAqtB2NRr/WksuCVnPDJbV02IzaYCTRdv4V5GrX2XkOqO5p4pp3Kh\n" +
		"6d/FxHCQ49sHitG8dY3LzNkTjWt0gJap+nw0vVR/ZqJMrAFBTa+iV7HryMBCpQPc\n" +
		"C3EI3uCI9cdMHXDFJKm+q3xwl1JDfbC6tY310wIDAQABAoIBAAJrk32xmDficreW\n" +
		"uPtbj2xZjzSAmds0+Or1LCJ2on1MYmFbS96hbhwCALXCCHuN632Xk+UdGdPp0mSv\n" +
		"+W8P2LRkFGr+bDl8Nnj85PFnmyiIN7Zrjf3ao8LfN33KIG6fz/eUgVAcRTwcfhcL\n" +
		"3svdnZ3Q0dlUNAj83exAytV+AA1x3utMGfAyV5TI56ci05mVZy+s+YlqVX3GPxtO\n" +
		"N+2ty42nROQ9KJWS9HBrjYhsh3MaBq/MlZfcIWuKS7+WKdsk/ajBjfOjN6WlCc9m\n" +
		"t8g9MJt50SIyRgM+hZDrMfUc1z7dljBeLD2Ui7HhfXpXTc62NIdMsU/N6JhjCsBG\n" +
		"uxGrsIkCgYEA0nsQoKkPtNXV8I6xgHxRplG+VyjOgHOLE50m7YrgKmwJ39G9njFs\n" +
		"/bm1aR7ig9PS/VLHF+EgoV1zl1RfizDHaC/V2DjpQphoChZ57JqtarAWaecIIwCc\n" +
		"wIzQ+BnYMgm4FdJEE0naLFU951pN4xUy7NblMvU2Wk/Jixks5EF/q18CgYEA0mCs\n" +
		"/ml+Ue9216QU6kDV5yk9Ypw/aPUcu5kXXjGQertF/3GQ3Xy0JI4qdnpjpY7kW484\n" +
		"aT9DHK1rKro4XHCyKneha5FghZ6O39Knb8bUamOqymXOB77JDrqD+Atgdxs0jE/+\n" +
		"/HjJCRYBuoAtJ7OmMBoPMWamAqerlALzIXA2/g0CgYAPAgloe0WMbmbn1TTg5Xxo\n" +
		"8JEy48z9qb9z8ZOyAmIDhFqb4/eyTPHpkZFW4oXiQntb5sgdcscB2okAdFqvsRW2\n" +
		"3xpPZZd0USux9HJTJaBR6CZg/ME+xa9np2LLHgSlZL4EiE6kVXLCEH3ufijplTxh\n" +
		"WN1U6dkrTV8glPX3fJge3wKBgEtc0Hvu5I6LfwIuyENGaJn/fvr1SA3cSKe3ZtSa\n" +
		"Ysxki+W/FAsT4iB6QSHiJBIpxwo5mxawz+TVBt/uh8QtptVpt4ymLnKPY1UwzERR\n" +
		"cMSP4Z3RrGW/5Zx+GkpgIPVp7IAbJBfjWPkFRic+RW7Ef1MZ8rlasTugPumtyNUA\n" +
		"suJ9AoGBAIOGpM7yBGQBSgOz9ayx2CtoFr77Iv7PUDArsa6JxkB4Sb1NwYvbu4Wz\n" +
		"ikXPPeQ+FkawuZtfuBfAeBbpf6Fu4Leiiza92E+2Q5babmb2LseAvGkCtcqv+ZY9\n" +
		"Fe1iVDJ10uuYfR9t+cbM4pguE6Fs2e83HjE+cuDAz23dJyUan7v8\n" +
		"-----END RSA PRIVATE KEY-----")

	// passphraseKey2 is a passphrase for testKey2.
	passphraseKey2 = []byte("testPassword")
	// testKey2 is an RSA key encrypted with a passphrase.
	testKey2 = []byte("-----BEGIN RSA PRIVATE KEY-----\n" +
		"Proc-Type: 4,ENCRYPTED\n" +
		"DEK-Info: AES-128-CBC,25E2C0FE3877B403A630EB89B674A5E6\n" +
		"\n" +
		"ah4+WGjW3/riCUOZ4yW9B11oZU1bPaZLKqlOPs9NlvUoGGmK6oGhE8bBlaJwuAQq\n" +
		"828xjSJDka/8D+ECMteiAc310JzPlCEJ04WKqdrskm7D9kSq7TTL6MA4+OGXi5aE\n" +
		"SYa1JyUdfvCdCx4Uxvd7GSrVG69+Y1gJYvBoJ7JlQEVEQGcs+jLrKStx9EVMgFdK\n" +
		"hcThKUqQz+6Qv2G4eqJBNtkinP+75dxhd8n1eCGtQ7Y6YsDN67FmfAeKTocA0DGl\n" +
		"C6FVCUKkpQCJ7rBYJIvfNPXAMFtw8Fa6F0rtsWXHihdaVgyyewfsXaUtlHWWKNC+\n" +
		"Npy2TCl3VpO9ReqHJ10RgNDVHOr3BavCW/jhltHYh8dDuhaDz+41VO0s4cPv/AVx\n" +
		"X2pJyhzET4EDVjpN05bLAKDYJWQzEif2fN1h1cPtV285i3U1xbWuBMxUYPYtUXZ7\n" +
		"UYvPGubhb6cMSt5w6OYieG8GmraD1fDFNjZv8mx7mVK8doJEoWWOzftUsMorK/W/\n" +
		"4jeNRuWZU/PAgZUa3rSpuZuRxwUsfWgeCkSN9lU0uIZumk4oy7zBzf4ZFs1K7kgs\n" +
		"ojjTxVf1JZj2hU7pApiLG7SOdkPNHIG49EfLod3lX66tk9hWd1/5dzhuAEAtUKua\n" +
		"6Rl4n3w+lBm3Ry+kkJ3f3O/AETroZzdjqRGD3GDn7X+kynJDb+cN5wOpfYHcCbnE\n" +
		"Iaf7wM5C/h2Q1fcGcxqz0t08a37KNco1yCkkbn69PcmJtHFU2zZqzsCMRXFFkEfF\n" +
		"lD+zMUrw8daopIeHDQiktaiqdUO0bpzQTE9QbKnX+XUFYX67Dk17UhjJlF1bzinp\n" +
		"J8sSn9vSGRq498nWQi5jjr8enXszPtm2oZ6QR12Xz2lZyyG1rUS1SHFtOIVYrqVn\n" +
		"T30muqY/AFaupAQZTY8XdTDAC5j4f/1OPh4xRsZOu7qaq1FFLmrRPWuM4YaU/Ziz\n" +
		"LAkJbV4mk6ev7mIVPbTGLYLnrj1KcM9S99D871t25nmJo1mD//rrB0HST2D7E/HN\n" +
		"cPmyl+y2/ri85uGKmITxh5gQLB3e1+7UYQ3CNpZVJIhEjjCZtCjnrfJhBjDJw8sA\n" +
		"AO0fGV0OlaBkOeRhAzhEO+mSF80k4upAKTKoLrkSta6687y7fj5hUN9uIn85jAIo\n" +
		"1Eka5/JgpOWEvYvpP5XfYmvOxT6VHxL4vS18ICkH7K7mjCvOK39AWAs9j/7qiUzw\n" +
		"m4U1MWq0blcpPscJiQ+wLib6Qprz60CcFSc3fiA70TPEkDe+MgFDmPMaptx+jf9w\n" +
		"I2NUPMGpZlpLdq3KU6eyS7uE5mRO5oF/XYw1BPMUPMqYpbvGfJRpEId/zRqEa6Xs\n" +
		"zR7S0dIDNimUQ5DUNXT7ZsjXQbqALIuKlGBaIMimNnBQGRCAuWpuezmNZMlKibAJ\n" +
		"CxBojuNtyvDeaQ9KUtU9NxyoVVj9VzMTAxLiXuF01F2zvg2+ZkZlbpBw837g2PQ6\n" +
		"z/6z8frm4vyZHWdRBV83qo6EWi+B7jix832TvKys84CsV87XTxQEIIVS2cuSnrTk\n" +
		"PIOGFbELkWoWJEvjpdj/w9kmtN2V1DcHog0cPNoTHwy5wauQtCwNTn6p6N8H6AUm\n" +
		"-----END RSA PRIVATE KEY-----\n")
)

// TestReEncryptionRepoKey tests to wrap a new repo key, and ReWrap this into a SymmetricKey for another user.
func TestReEncryptionRepoKey(t *testing.T) {
	key1 := getTestKey1(t)
	key2 := getTestKey2(t)

	repoKey1, err := GenerateSymmetricKey()
	if err != nil {
		t.Error(err)
	}

	exportedRepoKey1, err := key1.Public().WrapBytes(repoKey1.Export())
	if err != nil {
		t.Error(err)
	}

	exportedRepoKey2, err := key1.ReWrap(key2.Public(), exportedRepoKey1)
	if err != nil {
		t.Error(err)
	}

	_, err = key2.UnwrapBytes(exportedRepoKey2)
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
	pk, _ := key1.Public().Export()

	err = Verify(pk, message, signature)
	if err != nil {
		t.Errorf("Crypto.Verify returned error: %s", err)
	}
}

func TestImport_Exported_PublicKey(t *testing.T) {
	key1 := getTestKey1(t)

	exportedPublicKey, err := key1.Public().Export()
	if err != nil {
		t.Error(err)
	}

	_, err = ImportRSAPublicKey(exportedPublicKey)
	if err != nil {
		t.Error(err)
	}
}

func TestImport_Exported_ServiceKey(t *testing.T) {
	clientKey, err := GenerateRSAKey(RSAKeyLength)
	if err != nil {
		t.Errorf("generateServiceKey generates error: %s", err)
	}

	public, err := clientKey.Public().Export()
	if err != nil {
		t.Errorf("cannot import generated public key: %s", err)
	}
	_, err = ImportRSAPublicKey(public)
	if err != nil {
		t.Errorf("cannot import generated public key: %s", err)
	}

	private, err := clientKey.ExportPrivateKey()
	if err != nil {
		t.Errorf("cannot import generated public key: %s", err)
	}

	pemKey, err := ReadPEM(private)
	assert.OK(t, err)

	_, err = pemKey.Decode()
	assert.OK(t, err)
}

func TestImport_ExportedWithPassphrase(t *testing.T) {
	expected, err := GenerateRSAKey(1024)
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

	pemKey, err := ReadPEM(encrypted)
	assert.OK(t, err)

	actual, err := pemKey.Decrypt([]byte(pass))
	assert.OK(t, err)

	if !reflect.DeepEqual(actual, expected) {
		t.Errorf("%+v (actual) != %+v (expected)", actual, expected)
	}
}

func TestExportPrivateKeyWithEmptyPassphrase(t *testing.T) {
	expected, err := GenerateRSAKey(1024)
	if err != nil {
		t.Fatal(err)
	}

	_, err = expected.ExportPrivateKeyWithPassphrase("")
	if err != ErrEmptyPassphrase {
		t.Fatalf("unexpected error value: %v (actual) != %v (expected)", err, ErrEmptyPassphrase)
	}
}

func getTestKey1(t testing.TB) RSAPrivateKey {
	pemKey1, err := ReadPEM(testKey1)
	assert.OK(t, err)

	key1, err := pemKey1.Decode()
	assert.OK(t, err)
	return key1
}

func getTestKey2(t testing.TB) RSAPrivateKey {
	pemKey2, err := ReadPEM(testKey2)
	assert.OK(t, err)

	key2, err := pemKey2.Decrypt(passphraseKey2)
	assert.OK(t, err)
	return key2
}

func TestCiphertextRSA_MarshalJSON(t *testing.T) {
	cases := map[string]struct {
		ciphertext CiphertextRSA
		expected   string
	}{
		"success": {
			ciphertext: CiphertextRSA{
				Data: []byte("rsa_data"),
			},
			expected: "RSA-OAEP$cnNhX2RhdGE=$",
		},
	}

	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			// Act
			actual, err := tc.ciphertext.MarshalJSON()
			assert.OK(t, err)
			expected, err := json.Marshal(tc.expected)
			assert.OK(t, err)

			// Assert
			assert.Equal(t, actual, expected)
		})
	}
}
