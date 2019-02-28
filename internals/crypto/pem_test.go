package crypto_test

import (
	"testing"

	"github.com/keylockerbv/secrethub-go/pkg/assert"
	"github.com/keylockerbv/secrethub-go/internals/crypto"
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

func TestReadRSAKey_Plain(t *testing.T) {
	pemKey, err := crypto.ReadPEM(testKey1)
	assert.OK(t, err)

	isEncrypted := pemKey.IsEncrypted()
	assert.Equal(t, isEncrypted, false)

	_, err = pemKey.Decode()
	assert.OK(t, err)
}

func TestReadRSAKey_PlainWithPassphrase(t *testing.T) {
	pemKey, err := crypto.ReadPEM(testKey1)
	assert.OK(t, err)

	_, err = pemKey.Decrypt([]byte("some_passphrase"))
	assert.Equal(t, err, crypto.ErrDecryptionUnarmoredKey)
}

func TestReadRSAKey_Armored(t *testing.T) {
	pemKey, err := crypto.ReadPEM(testKey2)
	assert.OK(t, err)

	isEncrypted := pemKey.IsEncrypted()
	assert.Equal(t, isEncrypted, true)

	_, err = pemKey.Decrypt(passphraseKey2)
	assert.OK(t, err)
}

func TestReadRSAKey_Armored_WrongPassphrase(t *testing.T) {
	pemKey, err := crypto.ReadPEM(testKey2)
	assert.OK(t, err)

	isEncrypted := pemKey.IsEncrypted()
	assert.Equal(t, isEncrypted, true)

	_, err = pemKey.Decrypt([]byte("wrong_passphrase"))
	assert.Equal(t, err, crypto.ErrIncorrectPassphrase)
}
