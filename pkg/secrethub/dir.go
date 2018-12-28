package secrethub

import (
	"github.com/keylockerbv/secrethub-go/pkg/api"
	"github.com/keylockerbv/secrethub-go/pkg/errio"
)

// DirService handles operations on directories from SecretHub.
type DirService interface {
	// Create a directory at a given path.
	Create(path api.DirPath) (*api.Dir, error)
	// Delete removes the directory at the given path.
	Delete(path api.DirPath) error
	// GetTree retrieves a directory at a given path and all of its descendants up to a given depth.
	// When the depth <= 0, there is no limit.
	// TODO SHDEV-1062: Change this such that 0 returns the Tree without any descendants
	// and -1 returns the Tree with all descendants.
	GetTree(path api.DirPath, depth int) (*api.Tree, error)
}

type dirService struct {
	client *client
}

// GetTree retrieves a directory at a given path.
func (s dirService) GetTree(path api.DirPath, depth int) (*api.Tree, error) {
	return s.client.GetDirByBlindName(path, depth, false)
}

// Create creates a directory at a given path.
func (s dirService) Create(path api.DirPath) (*api.Dir, error) {
	return s.client.CreateDir(path)
}

// Delete removes the directory at the given path.
func (s dirService) Delete(path api.DirPath) error {
	return s.client.DeleteDir(path)
}

// CreateDir creates a directory for a repo and optional parent directory.
func (c *client) CreateDir(dirPath api.DirPath) (*api.Dir, error) {
	var err error

	err = dirPath.Validate()
	if err != nil {
		return nil, errio.Error(err)
	}

	parentPath, err := dirPath.GetParentPath()
	if err != nil {
		return nil, errio.Error(err)
	}

	accounts, err := c.ListDirAccounts(parentPath)
	if err != nil {
		return nil, errio.Error(err)
	}

	encryptedNames, err := encryptNameForAccounts(dirPath.GetDirName(), accounts...)
	if err != nil {
		return nil, errio.Error(err)
	}

	blindName, err := c.convertPathToBlindName(dirPath)
	if err != nil {
		return nil, errio.Error(err)
	}

	parentBlindName, err := c.convertPathToBlindName(parentPath)
	if err != nil {
		return nil, errio.Error(err)
	}

	request := &api.CreateDirRequest{
		BlindName:       blindName,
		ParentBlindName: parentBlindName,

		EncryptedNames: encryptedNames,
	}

	encryptedDir, err := c.httpClient.CreateDir(dirPath.GetNamespace(), dirPath.GetRepo(), request)
	if err != nil {
		return nil, errio.Error(err)
	}

	accountKey, err := c.getAccountKey()
	if err != nil {
		return nil, errio.Error(err)
	}

	dir, err := encryptedDir.Decrypt(accountKey)
	return dir, errio.Error(err)
}

// GetDirByBlindName retrieves a directory from the API.
// This can be RepoPath for a RootDir or a DirPath.
func (c *client) GetDirByBlindName(path api.DirPath, depth int, ancestors bool) (*api.Tree, error) {
	blindName, err := c.convertPathToBlindName(path)
	if err != nil {
		return nil, errio.Error(err)
	}

	encTree, err := c.httpClient.GetTree(blindName, depth, ancestors)
	if err != nil {
		return nil, errio.Error(err)
	}

	accountKey, err := c.getAccountKey()
	if err != nil {
		return nil, errio.Error(err)
	}

	tree, err := encTree.Decrypt(accountKey)
	if err != nil {
		return nil, errio.Error(err)
	}

	if ancestors {
		// When ancestors are retrieved, the root of the filesystem is the directory at repo level.
		// So, the parentPath of the filesystem is then the namespace of the path.
		tree.ParentPath = api.ParentPath(path.GetNamespace())
	} else {
		// When ancestors are not retrieved, the root of the filesystem is the directory at path.
		// So, the parentPath of the filesystem is then the parent of the directory at path.
		tree.ParentPath, err = path.GetParentPath()
		if err != nil {
			return nil, errio.Error(err)
		}
	}

	return tree, errio.Error(err)
}

// DeleteDir deletes a directory by a given path.
func (c *client) DeleteDir(dirPath api.DirPath) error {
	var err error

	err = dirPath.Validate()
	if err != nil {
		return errio.Error(err)
	}

	dirBlindName, err := c.convertPathToBlindName(dirPath)
	if err != nil {
		return errio.Error(err)
	}

	err = c.httpClient.DeleteDir(dirBlindName)
	if err != nil {
		return errio.Error(err)
	}

	return nil
}

// ListDirAccounts list the accounts with read permission.
func (c *client) ListDirAccounts(path api.BlindNamePath) ([]*api.Account, error) {
	blindName, err := c.convertPathToBlindName(path)
	if err != nil {
		return nil, errio.Error(err)
	}

	accounts, err := c.httpClient.ListDirAccounts(blindName)
	return accounts, errio.Error(err)
}
