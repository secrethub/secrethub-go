package secrethub

import (
	"fmt"
	"testing"
	"time"

	"github.com/secrethub/secrethub-go/internals/api"
	"github.com/secrethub/secrethub-go/internals/api/uuid"
	"github.com/secrethub/secrethub-go/internals/assert"
	"github.com/secrethub/secrethub-go/internals/crypto"
	"github.com/secrethub/secrethub-go/pkg/secrethub/internals/http"
)

func TestReencypter_reencrypt(t *testing.T) {
	fromPrivateKey, err := crypto.GenerateRSAPrivateKey(2048)
	assert.OK(t, err)

	fromPublicKey := fromPrivateKey.Public()
	fromEncodedPublicKey, err := fromPublicKey.Encode()
	assert.OK(t, err)

	forPrivateKey, err := crypto.GenerateRSAPrivateKey(2048)
	assert.OK(t, err)

	forPublicKey := forPrivateKey.Public()
	forEncodedPublicKey, err := forPublicKey.Encode()
	if err != nil {
		fmt.Print(err.Error())
	}

	firstAccount := api.Account{
		AccountID:   uuid.New(),
		Name:        "first-user",
		PublicKey:   fromEncodedPublicKey,
		AccountType: "",
		CreatedAt:   time.Time{},
	}

	secondAccount := api.Account{
		AccountID:   uuid.New(),
		Name:        "second-user",
		PublicKey:   forEncodedPublicKey,
		AccountType: "",
		CreatedAt:   time.Time{},
	}

	fakeClient := Client{
		httpClient: &http.Client{},
		account:    &secondAccount,
		accountKey: &forPrivateKey,
	}

	cases := map[string]struct {
		dirs    []*api.Dir
		secrets []*api.Secret
	}{
		"no directories": {
			dirs:    nil,
			secrets: nil,
		},
		"one directory": {
			dirs: []*api.Dir{
				{
					DirID: uuid.New(),
					Name:  "first-dir",
				},
			},
			secrets: nil,
		},
		"multiple directories": {
			dirs: []*api.Dir{
				{
					DirID: uuid.New(),
					Name:  "first-dir",
				},
				{
					DirID: uuid.New(),
					Name:  "second-dir",
				},
				{
					DirID: uuid.New(),
					Name:  "third-dir",
				},
				{
					DirID: uuid.New(),
					Name:  "fourth-dir",
				},
				{
					DirID: uuid.New(),
					Name:  "fifth-dir",
				},
			},
			secrets: nil,
		},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			fakeReencrypter := reencrypter{
				dirs:       make(map[uuid.UUID]api.EncryptedNameForNodeRequest),
				secrets:    make(map[uuid.UUID]api.SecretAccessRequest),
				encryptFor: &secondAccount,
				client:     &fakeClient,
			}

			encryptedTree := createEncryptedTree(t, tc.dirs, tc.secrets, fakeReencrypter, firstAccount)
			err = fakeReencrypter.reencrypt(&encryptedTree, &fromPrivateKey)
			if err != nil {
				fmt.Print(err.Error())
			}

			count := 0
			for _, dir := range fakeReencrypter.dirs {
				assert.Equal(t, dir.AccountID, secondAccount.AccountID)
				decryptedDir, err := encryptedTree.Directories[tc.dirs[count].DirID].Decrypt(&fromPrivateKey)
				assert.OK(t, err)
				assert.Equal(t, tc.dirs[count].Name, decryptedDir.Name)
				count++
			}

			//TODO: In order to test for secrets encryption and decryption, a refactoring of the Client is in order, as to be able to mock the HTTP Go client.
			count = 0
			for _, secret := range fakeReencrypter.secrets {
				assert.Equal(t, secret.Name.AccountID, secondAccount.AccountID)
				decryptedSecret, err := encryptedTree.Secrets[count].Decrypt(&fromPrivateKey)
				assert.OK(t, err)
				assert.Equal(t, tc.secrets[count].Name, decryptedSecret.Name)
				count++
			}
		})
	}
}

func createEncryptedTree(t *testing.T, dirs []*api.Dir, secrets []*api.Secret, reencrypter reencrypter, account api.Account) api.EncryptedTree {
	encryptedTree := api.EncryptedTree{
		Directories: make(map[uuid.UUID]*api.EncryptedDir),
		Secrets:     make([]*api.EncryptedSecret, len(secrets)),
	}
	for _, dir := range dirs {
		request, err := reencrypter.client.encryptDirFor(dir, &account)
		assert.OK(t, err)
		encryptedTree.Directories[dir.DirID] = &api.EncryptedDir{
			DirID:         dir.DirID,
			EncryptedName: request.EncryptedName,
		}
	}

	for i, secret := range secrets {
		request, err := reencrypter.client.encryptSecretFor(secret, &account)
		assert.OK(t, err)
		encryptedTree.Secrets[i] = &api.EncryptedSecret{
			DirID:         secret.DirID,
			EncryptedName: request.Name.EncryptedName,
		}
	}

	return encryptedTree
}
