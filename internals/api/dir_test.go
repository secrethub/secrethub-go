package api_test

import (
	"testing"

	"github.com/secrethub/secrethub-go/internals/api"
	"github.com/secrethub/secrethub-go/internals/api/uuid"
	"github.com/secrethub/secrethub-go/internals/assert"
	"github.com/secrethub/secrethub-go/internals/crypto"
)

func TestCreateDirRequest_Validate(t *testing.T) {
	blindKey, err := crypto.GenerateSymmetricKey()
	assert.OK(t, err)

	dirPath := api.DirPath("owner/repo/dir")
	parentPath := api.DirPath("owner/repo/parent/dir")

	dirPathBlindName, err := dirPath.BlindName(blindKey)
	assert.OK(t, err)
	parentPathBlindName, err := parentPath.BlindName(blindKey)
	assert.OK(t, err)

	tests := []struct {
		createDirRequest *api.CreateDirRequest
		expected         error
	}{
		{
			createDirRequest: getTestCreateDirRequest(t),
			expected:         nil,
		},
		{
			createDirRequest: &api.CreateDirRequest{
				ParentBlindName: parentPathBlindName,

				EncryptedNames: []api.EncryptedNameRequest{{
					AccountID:     uuid.New(),
					EncryptedName: testCiphertextRSA,
				},
				},
			},
			expected: api.ErrInvalidDirBlindName,
		},
		{
			createDirRequest: &api.CreateDirRequest{
				BlindName: dirPathBlindName,
				EncryptedNames: []api.EncryptedNameRequest{{
					AccountID:     uuid.New(),
					EncryptedName: testCiphertextRSA,
				},
				},
			},
			expected: api.ErrInvalidParentBlindName,
		},
	}

	for _, test := range tests {
		result := test.createDirRequest.Validate()
		assert.Equal(t, result, test.expected)
	}

}

func TestCreateDirRequest_Validate_UniqueEncryptedFor(t *testing.T) {
	accountID := uuid.New()
	blindKey, err := crypto.GenerateSymmetricKey()
	assert.OK(t, err)

	dirPath := api.DirPath("owner/repo/dir")
	parentPath := api.DirPath("owner/repo/parent/dir")

	dirPathBlindName, err := dirPath.BlindName(blindKey)
	assert.OK(t, err)
	parentPathBlindName, err := parentPath.BlindName(blindKey)
	assert.OK(t, err)

	cdr := api.CreateDirRequest{
		BlindName:       dirPathBlindName,
		ParentBlindName: parentPathBlindName,

		EncryptedNames: []api.EncryptedNameRequest{
			{
				AccountID:     accountID,
				EncryptedName: testCiphertextRSA,
			},
			{
				AccountID:     accountID,
				EncryptedName: testCiphertextRSA,
			},
		},
	}

	result := cdr.Validate()
	assert.Equal(t, result, api.ErrNotUniquelyEncryptedForAccounts)
}

func getTestCreateDirRequest(t *testing.T) *api.CreateDirRequest {
	blindKey, err := crypto.GenerateSymmetricKey()
	assert.OK(t, err)

	dirPath := api.DirPath("owner/repo/dir")
	parentPath := api.DirPath("owner/repo/parent/dir")

	dirPathBlindName, err := dirPath.BlindName(blindKey)
	assert.OK(t, err)
	parentPathBlindName, err := parentPath.BlindName(blindKey)
	assert.OK(t, err)

	return &api.CreateDirRequest{
		BlindName:       dirPathBlindName,
		ParentBlindName: parentPathBlindName,

		EncryptedNames: []api.EncryptedNameRequest{{
			AccountID:     uuid.New(),
			EncryptedName: testCiphertextRSA,
		},
		},
	}
}
