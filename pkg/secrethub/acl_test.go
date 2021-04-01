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
	if err != nil {
		fmt.Print(err.Error())
	}

	fromPublicKey := fromPrivateKey.Public()
	fromEncodedPublicKey, err := fromPublicKey.Encode()
	if err != nil {
		fmt.Print(err.Error())
	}

	forPrivateKey, err := crypto.GenerateRSAPrivateKey(2048)
	if err != nil {
		fmt.Print(err.Error())
	}

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
	for _, tc := range cases {
		fakeReencrypter := reencrypter{
			dirs:       make(map[uuid.UUID]api.EncryptedNameForNodeRequest),
			secrets:    make(map[uuid.UUID]api.SecretAccessRequest),
			encryptFor: &secondAccount,
			client:     &fakeClient,
		}

		encryptedTree := createEncryptedTree(tc.dirs, tc.secrets, fakeReencrypter, firstAccount)
		err = fakeReencrypter.reencrypt(&encryptedTree, &fromPrivateKey)
		if err != nil {
			fmt.Print(err.Error())
		}

		count := 0
		for _, dirTemp := range fakeReencrypter.dirs {
			assert.Equal(t, dirTemp.AccountID, secondAccount.AccountID)
			decryptedDir, err := encryptedTree.Directories[tc.dirs[count].DirID].Decrypt(&fromPrivateKey)
			if err != nil {
				fmt.Print(err.Error())
			}
			assert.Equal(t, tc.dirs[count].Name, decryptedDir.Name)
			count++
		}

		//TODO: In order to test for secrets encryption and decryption, a refactoring of the Client is in order, as to be able to mock the HTTP Go client.
		count = 0
		for _, secretTemp := range fakeReencrypter.secrets {
			assert.Equal(t, secretTemp.Name.AccountID, secondAccount.AccountID)
			decryptedSecret, err := encryptedTree.Secrets[count].Decrypt(&fromPrivateKey)
			if err != nil {
				fmt.Print(err.Error())
			}
			assert.Equal(t, tc.secrets[count].Name, decryptedSecret.Name)
			count++
		}
	}
}

func createEncryptedTree(dirs []*api.Dir, secrets []*api.Secret, reencrypter reencrypter, account api.Account) api.EncryptedTree {
	encryptedTree := api.EncryptedTree{
		Directories: make(map[uuid.UUID]*api.EncryptedDir),
		Secrets:     make([]*api.EncryptedSecret, len(secrets)),
	}
	for _, dir := range dirs {
		request, err := reencrypter.client.encryptDirFor(dir, &account)
		if err != nil {
			fmt.Print(err.Error())
		}
		encryptedTree.Directories[dir.DirID] = &api.EncryptedDir{
			DirID:         dir.DirID,
			EncryptedName: request.EncryptedName,
		}
	}

	for i, secret := range secrets {
		request, err := reencrypter.client.encryptSecretFor(secret, &account)
		if err != nil {
			fmt.Print(err.Error())
		}
		encryptedTree.Secrets[i] = &api.EncryptedSecret{
			DirID:         secret.DirID,
			EncryptedName: request.Name.EncryptedName,
		}
	}

	return encryptedTree
}
