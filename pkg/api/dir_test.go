package api_test

import (
	"testing"

	"github.com/keylockerbv/secrethub-go/internal/testutil"
	"github.com/keylockerbv/secrethub-go/pkg/api"
	"github.com/keylockerbv/secrethub-go/pkg/api/uuid"
	"github.com/keylockerbv/secrethub-go/pkg/crypto"
)

func TestCreateDirRequest_Validate(t *testing.T) {
	blindKey, err := crypto.GenerateAESKey()
	testutil.OK(t, err)

	dirPath := api.DirPath("owner/repo/dir")
	parentPath := api.DirPath("owner/repo/parent/dir")

	dirPathBlindName, err := dirPath.BlindName(blindKey)
	testutil.OK(t, err)
	parentPathBlindName, err := parentPath.BlindName(blindKey)
	testutil.OK(t, err)

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
					EncryptedName: getValidEncodedCipherText(),
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
					EncryptedName: getValidEncodedCipherText(),
				},
				},
			},
			expected: api.ErrInvalidParentBlindName,
		},
	}

	for _, test := range tests {
		result := test.createDirRequest.Validate()
		testutil.Compare(t, result, test.expected)
	}

}

func TestCreateDirRequest_Validate_UniqueEncryptedFor(t *testing.T) {
	accountID := uuid.New()
	blindKey, err := crypto.GenerateAESKey()
	testutil.OK(t, err)

	dirPath := api.DirPath("owner/repo/dir")
	parentPath := api.DirPath("owner/repo/parent/dir")

	dirPathBlindName, err := dirPath.BlindName(blindKey)
	testutil.OK(t, err)
	parentPathBlindName, err := parentPath.BlindName(blindKey)
	testutil.OK(t, err)

	cdr := api.CreateDirRequest{
		BlindName:       dirPathBlindName,
		ParentBlindName: parentPathBlindName,

		EncryptedNames: []api.EncryptedNameRequest{
			{
				AccountID:     accountID,
				EncryptedName: getValidEncodedCipherText(),
			},
			{
				AccountID:     accountID,
				EncryptedName: getValidEncodedCipherText(),
			},
		},
	}

	result := cdr.Validate()
	testutil.Compare(t, result, api.ErrNotUniquelyEncryptedForAccounts)
}

func getTestCreateDirRequest(t *testing.T) *api.CreateDirRequest {
	blindKey, err := crypto.GenerateAESKey()
	testutil.OK(t, err)

	dirPath := api.DirPath("owner/repo/dir")
	parentPath := api.DirPath("owner/repo/parent/dir")

	dirPathBlindName, err := dirPath.BlindName(blindKey)
	testutil.OK(t, err)
	parentPathBlindName, err := parentPath.BlindName(blindKey)
	testutil.OK(t, err)

	return &api.CreateDirRequest{
		BlindName:       dirPathBlindName,
		ParentBlindName: parentPathBlindName,

		EncryptedNames: []api.EncryptedNameRequest{{
			AccountID:     uuid.New(),
			EncryptedName: getValidEncodedCipherText(),
		},
		},
	}
}
