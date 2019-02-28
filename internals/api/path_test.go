package api_test

import (
	"strconv"
	"testing"

	"github.com/keylockerbv/secrethub-go/internals/api"
	"github.com/keylockerbv/secrethub-go/internals/assert"
	"github.com/keylockerbv/secrethub-go/internals/crypto"
)

func TestPath_HasVersion(t *testing.T) {
	// Arrange
	tests := []struct {
		path     api.DirPath
		expected bool
	}{
		{
			path:     "namespace",
			expected: false,
		},
		{
			path:     "namespace/repo",
			expected: false,
		},
		{
			path:     "namespace/repo/grandparent/parent/dir",
			expected: false,
		},
		{
			path:     "namespace/repo/directory/secret",
			expected: false,
		},

		{
			path:     "namespace/repo/directory/secret:latest",
			expected: true,
		},
		{
			path:     "namespace/repo/parent/secret:12",
			expected: true,
		},
		{
			path:     "namespace/repo/secret:latest",
			expected: true,
		},
		{
			path:     "namespace/repo/secret:12",
			expected: true,
		},
	}

	for _, test := range tests {
		// Act
		actual := api.Path(test.path).HasVersion()

		// Assert
		if actual != test.expected {
			t.Errorf(
				"unexpected result for path %s:\n\t%v (actual) != %v (expected)",
				test.path,
				actual,
				test.expected,
			)
		}
	}
}

func TestValidateSecretPath_Root(t *testing.T) {
	testPath := "owner/repo/secret"

	err := api.ValidateSecretPath(testPath)
	assert.OK(t, err)
}

func TestValidateSecretPath_Dir(t *testing.T) {
	testPath := "owner/repo/dir/subdir/secret"

	err := api.ValidateSecretPath(testPath)
	assert.OK(t, err)
}

func TestValidateSecretPath_NoUniformSecretName(t *testing.T) {
	testPath := "owner/repo/+"

	result := api.ValidateSecretPath(testPath)
	assert.Equal(t, result, api.ErrInvalidSecretName)
}

func TestValidateSecretPath_PrependSlash(t *testing.T) {
	testPath := "/owner/repo/dir/secret"

	result := api.ValidateSecretPath(testPath)
	if result == nil {
		t.Fatal("ValidateSecretPath should have thrown error.")
	}
}

func TestValidateSecretPath_AppendSlash(t *testing.T) {
	testPath := "owner/repo/dir/secret/"

	result := api.ValidateSecretPath(testPath)
	if result == nil {
		t.Fatal("ValidateSecretPath should have thrown error.")
	}
}

func TestValidateSecretPath_EmptyName(t *testing.T) {
	testPath := "owner/repo/"

	result := api.ValidateSecretPath(testPath)
	if result == nil {
		t.Fatal("ValidateSecretPath should have thrown error.")
	}

}

func TestValidateSecretPath_DirEmptyName(t *testing.T) {
	testPath := "owner/repo/dir/"

	result := api.ValidateSecretPath(testPath)
	if result == nil {
		t.Fatal("ValidateSecretPath should have thrown error.")
	}

}

func TestValidateSecretPath_NoSecret(t *testing.T) {
	testPath := "owner/repo"

	result := api.ValidateSecretPath(testPath)
	if result == nil {
		t.Fatal("ValidateSecretPath should have thrown error.")
	}
}

func TestValidateSecretPath_OnlyOwner(t *testing.T) {
	testPath := "owner"

	result := api.ValidateSecretPath(testPath)
	if result == nil {
		t.Fatal("ValidateSecretPath should have thrown error.")
	}
}

func TestValidateSecretPath_EmptyOwner(t *testing.T) {
	testPath := "/repo/secret"

	result := api.ValidateSecretPath(testPath)
	if result == nil {
		t.Fatal("ValidateSecretPath should have thrown error.")
	}
}

func TestValidateSecretPath_EmptyRepo(t *testing.T) {
	testPath := "owner//secret"

	result := api.ValidateSecretPath(testPath)
	if result == nil {
		t.Fatal("ValidateSecretPath should have thrown error.")
	}
}

func TestValidateSecretPath_CorrectVersion(t *testing.T) {
	testPath := "owner/repo/dir/secret:123"

	result := api.ValidateSecretPath(testPath)
	if result != nil {
		t.Fatal(result)
	}
}

func TestValidateSecretPath_EmptyVersion(t *testing.T) {
	testPath := "owner/repo/dir/secret:"

	result := api.ValidateSecretPath(testPath)
	if result == nil {
		t.Fatal("ValidateSecretPath should have thrown error.")
	}
}

func TestValidateSecretPath_LetterVersion(t *testing.T) {
	testPath := "owner/repo/dir/secret:ab1"

	result := api.ValidateSecretPath(testPath)
	if result == nil {
		t.Fatal("ValidateSecretPath should have thrown error.")
	}
}

func TestValidateSecretPath_SpecialCharacterVersion(t *testing.T) {
	testPath := "owner/repo/dir/secret:1$"

	result := api.ValidateSecretPath(testPath)
	if result == nil {
		t.Fatal("ValidateSecretPath should have thrown error.")
	}
}

func TestSecretPath_GetVersion(t *testing.T) {
	testPath := api.SecretPath("owner/repo/dir/secret:123")

	result, err := testPath.GetVersion()
	if err != nil {
		t.Fatal(err)
	}

	if result != "123" {
		t.Fatal("GetVersion gave wrong result")
	}
}

func TestSecretPath_GetVersion_Latest(t *testing.T) {
	testPath := api.SecretPath("owner/repo/dir/secret:latest")

	result, err := testPath.GetVersion()
	if err != nil {
		t.Fatal(err)
	}

	if result != "latest" {
		t.Fatal("GetVersion gave wrong result")
	}
}

func TestSecretPath_GetVersion_NoVersion(t *testing.T) {
	testPath := api.SecretPath("owner/repo/dir/secret")

	_, err := testPath.GetVersion()
	if err != api.ErrPathHasNoVersion {
		t.Fatal("GetVersion should have returned ErrPathHasNoVersion when retrieving nonexisting version")
	}

}

func TestSecretPath_AddVersion(t *testing.T) {
	cases := map[string]struct {
		path    api.SecretPath
		version int
		err     error
	}{
		"normal_version": {
			path:    "owner/repo/dir/secret",
			version: 123,
		},
		"negative_version": {
			path:    "owner/repo/dir/secret",
			version: -1,
			err:     api.ErrInvalidSecretVersion,
		},
		"zero_version": {
			path:    "owner/repo/dir/secret",
			version: 0,
		},
		"already_has_version": {
			path:    "owner/repo/dir/secret:1",
			version: 1,
			err:     api.ErrPathAlreadyHasVersion,
		},
	}

	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			// Act
			result, err := tc.path.AddVersion(tc.version)

			// Assert
			assert.Equal(t, err, tc.err)
			if tc.err == nil {
				actual, err := result.GetVersion()
				assert.OK(t, err)

				assert.Equal(t, actual, strconv.Itoa(tc.version))

				err = result.Validate()
				assert.OK(t, err)
			}
		})
	}
}

func TestSecretPath_GetVersion_IllegalVersion(t *testing.T) {
	testPath := api.SecretPath("owner/repo/dir/secret:abc")

	_, err := testPath.GetVersion()
	if err != api.ErrPathHasNoVersion {
		t.Fatal("GetVersion should have returned ErrPathHasNoVersion when retrieving illegal version")
	}

}

func TestSecretPath_GetSecret(t *testing.T) {
	testPath := api.SecretPath("owner/repo/dir/secret")

	result := testPath.GetSecret()

	assert.Equal(t, result, "secret")
}

func TestSecretPath_GetRepoPath(t *testing.T) {
	testPath := api.SecretPath("owner/repo/dir/secret:latest")

	result := testPath.GetRepoPath()

	assert.Equal(t, result, "owner/repo")
}

func TestSecretPath_GetParentPath(t *testing.T) {
	tests := []struct {
		path     api.SecretPath
		expected api.ParentPath
	}{
		{
			path:     "namespace/repo/secret",
			expected: "namespace/repo",
		},
		{
			path:     "namespace/repo/parent/secret",
			expected: "namespace/repo/parent",
		},
		{
			path:     "namespace/repo/grandparent/parent/secret",
			expected: "namespace/repo/grandparent/parent",
		},
		{
			path:     "namespace/repo/parent/secret:123",
			expected: "namespace/repo/parent",
		},
		{
			path:     "namespace/repo/parent/secret:latest",
			expected: "namespace/repo/parent",
		},
	}

	for _, test := range tests {
		// Act
		actual, err := test.path.GetParentPath()
		if err != nil {
			t.Errorf("unexpected result for path %s: %s", test.path.String(), err)
		}

		// Assert
		if actual != test.expected {
			t.Errorf(
				"unexpected error for path %s:\n\t%v (actual) != %v (expected)",
				test.path,
				actual,
				test.expected,
			)
		}
	}
}

func TestSecretPath_HasVersion(t *testing.T) {
	tests := []struct {
		path     string
		expected bool
	}{
		{
			"owner/repo/dir/secret:1",
			true,
		},

		{
			"owner/repo/dir/secret",
			false,
		},
		{
			"owner/repo/dir/secret:latest",
			true,
		},
		{
			"owner/repo/secret:1",
			true,
		},
		{
			"owner/repo/secret",
			false,
		},
		{
			"owner/repo/secret:latest",
			true,
		},
		{"owner/repo/secret:",
			false,
		},
		{
			"owner/repo/dir/secret:",
			false,
		},
	}

	for _, test := range tests {
		secretPath := api.SecretPath(test.path)
		result := secretPath.HasVersion()

		if result != test.expected {
			t.Fatalf("did not correctly detect version on %v, %v (actual) != %v (expected)",
				test.path, result, test.expected)
		}

	}

}

func TestValidateRepoPath(t *testing.T) {
	testPath := "owner/repo"

	err := api.ValidateRepoPath(testPath)
	assert.OK(t, err)
}

func TestValidateRepoPath_Secret(t *testing.T) {
	testPath := "owner/repo/secret"

	result := api.ValidateRepoPath(testPath)
	if result == nil {
		t.Fatal("ValidateRepoPath should have thrown error.")
	}
}

func TestValidateRepoPath_Dir(t *testing.T) {
	testPath := "owner/repo/dir"

	result := api.ValidateRepoPath(testPath)
	if result == nil {
		t.Fatal("ValidateRepoPath should have thrown error.")
	}
}

func TestValidateRepoPath_NoUniformSecretName(t *testing.T) {
	testPath := "owner/+"

	result := api.ValidateRepoPath(testPath)
	if result != api.ErrInvalidRepoName {
		t.Errorf("unexpected error:\n\t%v (actual) != %v (expected)", result, api.ErrInvalidRepoName)
	}
}

func TestValidateRepoPath_EmptyName(t *testing.T) {
	testPath := "owner/"

	result := api.ValidateRepoPath(testPath)
	if result == nil {
		t.Fatal("ValidateRepoPath should have thrown error.")
	}
}

func TestValidateRepoPath_OnlyOwner(t *testing.T) {
	testPath := "owner"

	result := api.ValidateRepoPath(testPath)
	if result == nil {
		t.Fatal("ValidateRepoPath should have thrown error.")
	}
}

func TestValidateRepoPath_EmptyOwner(t *testing.T) {
	testPath := "/repo"

	result := api.ValidateRepoPath(testPath)
	if result == nil {
		t.Fatal("ValidateRepoPath should have thrown error.")
	}
}

func TestValidateRepoPath_PrependSlash(t *testing.T) {
	testPath := "/owner/repo"

	result := api.ValidateRepoPath(testPath)
	if result == nil {
		t.Fatal("ValidateRepoPath should have thrown error.")
	}
}

func TestValidateRepoPath_AppendSlash(t *testing.T) {
	testPath := "owner/repo/"

	result := api.ValidateRepoPath(testPath)
	if result == nil {
		t.Fatal("ValidateRepoPath should have thrown error.")
	}
}

func TestRepoPathValue_GetRepo(t *testing.T) {
	testPath := api.RepoPath("owner/repo")

	result := testPath.GetRepo()

	if result != "repo" {
		t.Fatal("GetSecret gave wrong result")
	}
}

func TestSecretPath_BlindName_IgnoreVersion(t *testing.T) {
	path := api.SecretPath("owner/repo/secret")
	pathWithVersion := api.SecretPath("owner/repo/secret:latest")

	key, err := crypto.GenerateSymmetricKey()
	if err != nil {
		t.Fatal(err)
	}

	expected, err := path.BlindName(key)
	assert.OK(t, err)
	if expected == "" {
		t.Errorf("unexpected blindname for path %s: %s (actual) != <some-base64-encoded-string> (expected)", path, expected)
	}

	actual, err := pathWithVersion.BlindName(key)
	assert.OK(t, err)
	if actual != expected {
		t.Errorf("blindname of versioned path is not equal to unversioned path.")
	}
}

func TestBlindNameCaseSensitivity(t *testing.T) {
	// these paths should all produce the same blindname
	paths := []api.SecretPath{
		"owner/repo/secret",
		"owner/repo/secret:1",
		"owner/repo/Secret",
		"owner/Repo/secret",
		"Owner/repo/secret",
	}

	key, err := crypto.GenerateSymmetricKey()
	if err != nil {
		t.Fatal(err)
	}

	expected, err := paths[0].BlindName(key)
	assert.OK(t, err)
	if expected == "" {
		t.Errorf("unexpected blindname for path %s: %s (actual) != <some-base64-encoded-string> (expected)", paths[0], expected)
	}
	for _, path := range paths {
		actual, err := path.BlindName(key)
		assert.OK(t, err)

		if actual != expected {
			t.Errorf("unexpected blindname for path %s: %s (actual) != %s (expected)", path, actual, expected)
		}
	}
}

func TestBlindName_DifferentKey(t *testing.T) {
	paths := []api.SecretPath{
		"owner/repo/secret",
		"owner/repo/secret:latest",
		"owner/repo/secret:1",
		"owner/repo/Secret",
		"owner/repo/Dir/secret",
		"owner/Repo/secret",
		"Owner/repo/dir/secret",
	}

	key1, err := crypto.GenerateSymmetricKey()
	if err != nil {
		t.Fatal(err)
	}

	key2, err := crypto.GenerateSymmetricKey()
	if err != nil {
		t.Fatal(err)
	}

	for _, path := range paths {
		first, err := path.BlindName(key1)
		assert.OK(t, err)
		second, err := path.BlindName(key2)
		assert.OK(t, err)

		if first == second {
			t.Errorf("unexpected blindname for same path %s with different keys: %s (first) == %s (second)", path, first, second)
		}
	}
}

func TestDirPath_HasParent(t *testing.T) {
	// Arrange
	tests := []struct {
		path     api.DirPath
		expected bool
	}{
		{
			path:     "namespace/repo/dir",
			expected: true,
		},
		{
			path:     "namespace/repo/parent/dir",
			expected: true,
		},
		{
			path:     "namespace/repo/grandparent/parent/dir",
			expected: true,
		},
		{
			path:     "",
			expected: false,
		},
		{
			path:     "namespace",
			expected: false,
		},
		{
			path:     "namespace/repo",
			expected: false,
		},
	}

	for _, test := range tests {
		// Act
		actual := test.path.HasParentDirectory()

		// Assert
		if actual != test.expected {
			t.Errorf(
				"unexpected result for path %s: %v (actual) != %v (expected)",
				test.path,
				actual,
				test.expected,
			)
		}
	}
}

func TestDirPath_GetParentPath(t *testing.T) {
	tests := []struct {
		path     api.DirPath
		expected api.ParentPath
	}{
		{
			path:     "namespace/repo/parent/dir",
			expected: "namespace/repo/parent",
		},
		{
			path:     "namespace/repo/grandparent/parent/dir",
			expected: "namespace/repo/grandparent/parent",
		},
		{
			path:     "namespace/repo/dir",
			expected: "namespace/repo",
		},
	}

	for _, test := range tests {
		actual, err := test.path.GetParentPath()
		if err != nil {
			t.Errorf("unexpected result for path %s: %s", test.path.String(), err)
		}

		if actual != test.expected {
			t.Errorf(
				"unexpected result for path %s:\n\t%v (actual) != %v (expected)",
				test.path,
				actual,
				test.expected,
			)
		}
	}
}

func TestDirPath_GetDirName(t *testing.T) {
	// Arrange
	tests := []struct {
		path     api.DirPath
		expected string
	}{
		{
			path:     "namespace/repo/dir",
			expected: "dir",
		},
		{
			path:     "namespace/repo/parent/dir",
			expected: "dir",
		},
		{
			path:     "namespace/repo/grandparent/parent/dir",
			expected: "dir",
		},
		{
			path:     "",
			expected: "",
		},
	}

	for _, test := range tests {
		// Act
		actual := test.path.GetDirName()

		// Assert
		if actual != test.expected {
			t.Errorf(
				"unexpected result for path %s:\n\t%v (actual) != %v (expected)",
				test.path,
				actual,
				test.expected,
			)
		}
	}
}

func TestDirPath_Validate(t *testing.T) {
	// Arrange
	tests := []struct {
		path     api.DirPath
		expected error
	}{
		{
			path:     "namespace/repo/parent",
			expected: nil,
		},
		{
			path:     "namespace/repo/parent/dir",
			expected: nil,
		},
		{
			path:     "namespace/repo/grandparent/parent/dir",
			expected: nil,
		},
		{
			path:     "namespace/repo/",
			expected: api.ErrInvalidDirName,
		},

		{
			path:     "namespace/repo/+",
			expected: api.ErrInvalidDirName,
		},
		{
			path:     "namespace/repo/parent/+",
			expected: api.ErrInvalidDirName,
		},
		{
			path:     "namespace/repo/dir/",
			expected: api.ErrInvalidDirName,
		},
		{
			path:     "namespace",
			expected: api.ErrInvalidDirPath("namespace"),
		},
		{
			path:     "namespace/",
			expected: api.ErrInvalidDirName,
		},
		{
			path:     "/repo/+",
			expected: api.ErrInvalidDirName,
		},
		{
			path:     "/namespace/repo/dir",
			expected: api.ErrInvalidDirPath("/namespace/repo/dir"),
		},
	}

	for _, test := range tests {
		// Act
		err := api.ValidateDirPath(string(test.path))

		// Assert
		if err != test.expected {
			t.Errorf(
				"unexpected error for path %s:\n\t%v (actual) != %v (expected)",
				test.path,
				err,
				test.expected,
			)
		}
	}
}

func TestDirPath_JoinDir(t *testing.T) {
	path := api.DirPath("namespace/repo/parent")
	dirName := "child"
	expected := api.DirPath("namespace/repo/parent/child")

	actual := path.JoinDir(dirName)
	assert.Equal(t, actual, expected)

}

func TestDirPath_JoinSecret(t *testing.T) {
	path := api.DirPath("namespace/repo/parent")
	secretName := "secret"
	expected := api.SecretPath("namespace/repo/parent/secret")

	actual := path.JoinSecret(secretName)
	assert.Equal(t, actual, expected)

}

func TestParentPath_JoinDir(t *testing.T) {
	path := api.ParentPath("namespace/repo/parent")
	dirName := "child"
	expected := api.DirPath("namespace/repo/parent/child")

	actual := path.JoinDir(dirName)
	assert.Equal(t, actual, expected)
}

func TestRepoPath_GetDirPath(t *testing.T) {
	path := api.RepoPath("namespace/repo")
	expected := api.DirPath("namespace/repo")

	actual := path.GetDirPath()
	assert.Equal(t, actual, expected)

	err := actual.Validate()
	assert.OK(t, err)
}
