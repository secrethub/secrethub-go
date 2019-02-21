package api_test

import (
	"sort"
	"testing"

	"github.com/keylockerbv/secrethub-go/pkg/api"
	"github.com/keylockerbv/secrethub-go/pkg/api/uuid"
	"github.com/keylockerbv/secrethub-go/pkg/crypto"
	"github.com/keylockerbv/secrethub-go/pkg/testutil"
)

func TestSortSecretByName(t *testing.T) {
	listIn := []string{
		"test1",
		"test3",
		"test10",
		"test2",
		"test",
		"test11",
		"test20",
		"test_",
		"test_1",
		"test-",
		"test-1",
		"test-2",
	}

	listOut := []string{
		"test",
		"test-",
		"test-1",
		"test-2",
		"test1",
		"test2",
		"test3",
		"test10",
		"test11",
		"test20",
		"test_",
		"test_1",
	}

	secretList := make([]*api.Secret, len(listIn))
	for i, name := range listIn {
		secretList[i] = &api.Secret{Name: name}
	}

	sort.Sort(api.SortSecretByName(secretList))
	for i, secret := range secretList {
		if secret.Name != listOut[i] {
			t.Errorf("expected %s at position %d, got %s", listOut[i], i, secret.Name)
		}
	}
}

func TestCreateSecretRequest_Validate_Unique(t *testing.T) {
	// the set of accounts in EncryptedNames is equal to the set of accounts in EncryptedKeys.
	blindKey, err := crypto.GenerateAESKey()
	testutil.OK(t, err)

	secretPath := api.SecretPath("owner/repo/dir/secret")
	blindname, err := secretPath.BlindName(blindKey)
	testutil.OK(t, err)

	accountID := uuid.New()
	tests := []struct {
		CreateSecretRequest api.CreateSecretRequest
		expected            error
	}{
		{
			CreateSecretRequest: api.CreateSecretRequest{
				BlindName:     blindname,
				EncryptedData: getValidEncodedCipherTextAES(),

				EncryptedNames: []api.EncryptedNameRequest{{
					AccountID:     accountID,
					EncryptedName: getValidEncodedCipherTextRSA(),
				},
					{
						AccountID:     accountID,
						EncryptedName: getValidEncodedCipherTextRSA(),
					},
				},
				EncryptedKeys: []api.EncryptedKeyRequest{{
					AccountID:    accountID,
					EncryptedKey: getValidEncodedCipherTextRSA(),
				},
				},
			},
			expected: api.ErrNotUniquelyEncryptedForAccounts,
		},
		{
			CreateSecretRequest: api.CreateSecretRequest{
				BlindName:     blindname,
				EncryptedData: getValidEncodedCipherTextAES(),

				EncryptedNames: []api.EncryptedNameRequest{{
					AccountID:     accountID,
					EncryptedName: getValidEncodedCipherTextRSA(),
				},
				},
				EncryptedKeys: []api.EncryptedKeyRequest{{
					AccountID:    accountID,
					EncryptedKey: getValidEncodedCipherTextRSA(),
				},
					{
						AccountID:    accountID,
						EncryptedKey: getValidEncodedCipherTextRSA(),
					},
				},
			},
			expected: api.ErrNotUniquelyEncryptedForAccounts,
		},
	}

	for _, test := range tests {
		result := test.CreateSecretRequest.Validate()
		testutil.Compare(t, result, test.expected)
	}

}

func TestCreateSecretRequest_Validate_EncryptedNameAndKeyForEachAccount(t *testing.T) {
	blindKey, err := crypto.GenerateAESKey()
	testutil.OK(t, err)

	secretPath := api.SecretPath("owner/repo/dir/secret")

	blindname, err := secretPath.BlindName(blindKey)
	testutil.OK(t, err)

	// the set of accounts in EncryptedNames is equal to the set of accounts in EncryptedKeys.
	createSecretRequest := api.CreateSecretRequest{
		BlindName:     blindname,
		EncryptedData: getValidEncodedCipherTextAES(),

		EncryptedNames: []api.EncryptedNameRequest{{
			AccountID:     uuid.New(),
			EncryptedName: getValidEncodedCipherTextRSA(),
		},
		},
		EncryptedKeys: []api.EncryptedKeyRequest{{
			AccountID:    uuid.New(),
			EncryptedKey: getValidEncodedCipherTextRSA(),
		},
		},
	}

	result := createSecretRequest.Validate()
	testutil.Compare(t, result, api.ErrNotEncryptedForAccounts)

}

func TestExistingNameMemberRequest_Validate(t *testing.T) {
	tests := []struct {
		EncryptedNameRequest api.EncryptedNameForNodeRequest
		expected             error
	}{
		{
			EncryptedNameRequest: api.EncryptedNameForNodeRequest{
				EncryptedNameRequest: api.EncryptedNameRequest{
					AccountID:     uuid.New(),
					EncryptedName: getValidEncodedCipherTextRSA(),
				},
				NodeID: uuid.New(),
			},
			expected: nil,
		},
		{
			EncryptedNameRequest: api.EncryptedNameForNodeRequest{
				EncryptedNameRequest: api.EncryptedNameRequest{
					AccountID:     uuid.New(),
					EncryptedName: getValidEncodedCipherTextRSA(),
				},
			},
			expected: api.ErrInvalidNodeID,
		},
		{
			EncryptedNameRequest: api.EncryptedNameForNodeRequest{
				NodeID: uuid.New(),
				EncryptedNameRequest: api.EncryptedNameRequest{
					EncryptedName: getValidEncodedCipherTextRSA(),
				},
			},
			expected: api.ErrInvalidAccountID,
		},
		{
			EncryptedNameRequest: api.EncryptedNameForNodeRequest{
				NodeID: uuid.New(),
				EncryptedNameRequest: api.EncryptedNameRequest{
					AccountID:     uuid.New(),
					EncryptedName: "INVALID CIPHERTEXT",
				},
			},
			expected: api.ErrInvalidCiphertext,
		},
	}

	for _, test := range tests {
		err := test.EncryptedNameRequest.Validate()
		if err != test.expected {
			t.Errorf("Unexpected result on %s: %s (actual) != %s (expected)", test.EncryptedNameRequest, err, test.expected)
		}
	}
}

func TestSecretAccessRequest_Validate_AccountIDs(t *testing.T) {
	testAccountID := uuid.New()

	tests := map[string]struct {
		Description string
		Request     api.SecretAccessRequest
		Expected    error
	}{
		"Every name and every key have different accountID": {
			Request: api.SecretAccessRequest{
				Name: api.EncryptedNameForNodeRequest{
					EncryptedNameRequest: api.EncryptedNameRequest{
						AccountID:     uuid.New(),
						EncryptedName: getValidEncodedCipherTextRSA(),
					},
					NodeID: uuid.New(),
				},
				Keys: []api.SecretKeyMemberRequest{{
					AccountID:    uuid.New(),
					SecretKeyID:  uuid.New(),
					EncryptedKey: getValidEncodedCipherText(),
				},
				},
			},
			Expected: api.ErrInvalidAccountID,
		},
		"Every name and every key has the same accountID": {
			Request: api.SecretAccessRequest{
				Name: api.EncryptedNameForNodeRequest{
					EncryptedNameRequest: api.EncryptedNameRequest{
						AccountID:     testAccountID,
						EncryptedName: getValidEncodedCipherTextRSA(),
					},
					NodeID: uuid.New(),
				},
				Keys: []api.SecretKeyMemberRequest{{
					AccountID:    testAccountID,
					SecretKeyID:  uuid.New(),
					EncryptedKey: getValidEncodedCipherText(),
				},
				},
			},
			Expected: nil,
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			err := tc.Request.Validate()
			testutil.Compare(t, err, tc.Expected)
		})
	}
}
