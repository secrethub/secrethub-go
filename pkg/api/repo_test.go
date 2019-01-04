package api_test

import (
	"testing"

	"sort"

	"github.com/keylockerbv/secrethub-go/internal/testutil"
	"github.com/keylockerbv/secrethub-go/pkg/api"
	"github.com/keylockerbv/secrethub-go/pkg/api/uuid"
)

var (
	accountIDUser1 = uuid.New()

	repoMemberRequest1 = &api.CreateRepoMemberRequest{
		RepoEncryptionKey: []byte{1, 2, 3},
		RepoIndexKey:      []byte{1, 2, 3},
	}
)

func TestCreateRepoRequest_Validate(t *testing.T) {
	tests := []struct {
		crr      api.CreateRepoRequest
		expected error
	}{
		{
			crr: api.CreateRepoRequest{
				Name:       "SomeRepoName",
				RootDir:    nil,
				RepoMember: nil,
			},
			expected: api.ErrNoRootDir,
		},
		{
			crr: api.CreateRepoRequest{
				Name:       "SomeRepoName",
				RootDir:    getTestCreateDirRequest(t),
				RepoMember: nil,
			},
			expected: api.ErrNoRepoMember,
		},
	}

	for _, test := range tests {
		err := test.crr.Validate()
		testutil.Compare(t, err, test.expected)
	}
}

func TestInviteUserRequest_Validate_Success(t *testing.T) {

	inviteRequest := &api.InviteUserRequest{
		AccountID:  accountIDUser1,
		RepoMember: repoMemberRequest1,
	}

	err := inviteRequest.Validate()
	if err != nil {
		t.Error(err)
	}

}

func TestInviteUserRequest_Validate_InvalidRepoMember(t *testing.T) {

	inviteRequest := &api.InviteUserRequest{
		AccountID:  accountIDUser1,
		RepoMember: &api.CreateRepoMemberRequest{},
	}

	err := inviteRequest.Validate()
	if err == nil {
		t.Error("did not throw an error for having an invalid CreateSRepoMemberRequest")
	}

}

func TestSortRepoByName(t *testing.T) {
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

	// Test for namespace sorting
	byNamespace := make([]*api.Repo, len(listIn))
	for i, name := range listIn {
		byNamespace[i] = &api.Repo{Owner: name, Name: "same"}
	}

	sort.Sort(api.SortRepoByName(byNamespace))
	for i, repo := range byNamespace {
		if repo.Owner != listOut[i] {
			t.Errorf("expected %s at position %d, got %s", listOut[i], i, repo.Owner)
		}
	}

	// Test for name sorting
	byName := make([]*api.Repo, len(listIn))
	for i, name := range listIn {
		byName[i] = &api.Repo{Owner: "same", Name: name}
	}

	sort.Sort(api.SortRepoByName(byName))
	for i, repo := range byName {
		if repo.Name != listOut[i] {
			t.Errorf("expected %s at position %d, got %s", listOut[i], i, repo.Name)
		}
	}
}
