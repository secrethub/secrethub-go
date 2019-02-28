package api_test

import (
	"sort"
	"testing"

	"github.com/secrethub/secrethub-go/internals/api"
	"github.com/secrethub/secrethub-go/internals/api/uuid"
	"github.com/secrethub/secrethub-go/internals/assert"
	"github.com/secrethub/secrethub-go/internals/crypto"
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
	blindKey, err := crypto.GenerateSymmetricKey()
	assert.OK(t, err)

	secretPath := api.SecretPath("owner/repo/dir/secret")
	blindname, err := secretPath.BlindName(blindKey)
	assert.OK(t, err)

	accountID := uuid.New()
	tests := []struct {
		CreateSecretRequest api.CreateSecretRequest
		expected            error
	}{
		{
			CreateSecretRequest: api.CreateSecretRequest{
				BlindName:     blindname,
				EncryptedData: testCiphertextAES,

				EncryptedNames: []api.EncryptedNameRequest{{
					AccountID:     accountID,
					EncryptedName: testCiphertextRSA,
				},
					{
						AccountID:     accountID,
						EncryptedName: testCiphertextRSA,
					},
				},
				EncryptedKeys: []api.EncryptedKeyRequest{{
					AccountID:    accountID,
					EncryptedKey: testCiphertextRSA,
				},
				},
			},
			expected: api.ErrNotUniquelyEncryptedForAccounts,
		},
		{
			CreateSecretRequest: api.CreateSecretRequest{
				BlindName:     blindname,
				EncryptedData: testCiphertextAES,

				EncryptedNames: []api.EncryptedNameRequest{{
					AccountID:     accountID,
					EncryptedName: testCiphertextRSA,
				},
				},
				EncryptedKeys: []api.EncryptedKeyRequest{{
					AccountID:    accountID,
					EncryptedKey: testCiphertextRSA,
				},
					{
						AccountID:    accountID,
						EncryptedKey: testCiphertextRSA,
					},
				},
			},
			expected: api.ErrNotUniquelyEncryptedForAccounts,
		},
	}

	for _, test := range tests {
		result := test.CreateSecretRequest.Validate()
		assert.Equal(t, result, test.expected)
	}

}

func TestCreateSecretRequest_Validate_EncryptedNameAndKeyForEachAccount(t *testing.T) {
	blindKey, err := crypto.GenerateSymmetricKey()
	assert.OK(t, err)

	secretPath := api.SecretPath("owner/repo/dir/secret")

	blindname, err := secretPath.BlindName(blindKey)
	assert.OK(t, err)

	// the set of accounts in EncryptedNames is equal to the set of accounts in EncryptedKeys.
	createSecretRequest := api.CreateSecretRequest{
		BlindName:     blindname,
		EncryptedData: testCiphertextAES,

		EncryptedNames: []api.EncryptedNameRequest{{
			AccountID:     uuid.New(),
			EncryptedName: testCiphertextRSA,
		},
		},
		EncryptedKeys: []api.EncryptedKeyRequest{{
			AccountID:    uuid.New(),
			EncryptedKey: testCiphertextRSA,
		},
		},
	}

	result := createSecretRequest.Validate()
	assert.Equal(t, result, api.ErrNotEncryptedForAccounts)

}

func TestExistingNameMemberRequest_Validate(t *testing.T) {
	cases := map[string]struct {
		EncryptedNameRequest api.EncryptedNameForNodeRequest
		expected             error
	}{
		"success": {
			EncryptedNameRequest: api.EncryptedNameForNodeRequest{
				EncryptedNameRequest: api.EncryptedNameRequest{
					AccountID:     uuid.New(),
					EncryptedName: testCiphertextRSA,
				},
				NodeID: uuid.New(),
			},
			expected: nil,
		},
		"invalid node id": {
			EncryptedNameRequest: api.EncryptedNameForNodeRequest{
				EncryptedNameRequest: api.EncryptedNameRequest{
					AccountID:     uuid.New(),
					EncryptedName: testCiphertextRSA,
				},
			},
			expected: api.ErrInvalidNodeID,
		},
		"invalid account id": {
			EncryptedNameRequest: api.EncryptedNameForNodeRequest{
				NodeID: uuid.New(),
				EncryptedNameRequest: api.EncryptedNameRequest{
					EncryptedName: testCiphertextRSA,
				},
			},
			expected: api.ErrInvalidAccountID,
		},
	}

	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {

			// Act
			err := tc.EncryptedNameRequest.Validate()

			// Assert
			assert.Equal(t, err, tc.expected)
		})
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
						EncryptedName: testCiphertextRSA,
					},
					NodeID: uuid.New(),
				},
				Keys: []api.SecretKeyMemberRequest{{
					AccountID:    uuid.New(),
					SecretKeyID:  uuid.New(),
					EncryptedKey: testCiphertextRSA,
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
						EncryptedName: testCiphertextRSA,
					},
					NodeID: uuid.New(),
				},
				Keys: []api.SecretKeyMemberRequest{{
					AccountID:    testAccountID,
					SecretKeyID:  uuid.New(),
					EncryptedKey: testCiphertextRSA,
				},
				},
			},
			Expected: nil,
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			err := tc.Request.Validate()
			assert.Equal(t, err, tc.Expected)
		})
	}
}
