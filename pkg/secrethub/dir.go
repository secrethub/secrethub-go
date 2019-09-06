package secrethub

import (
	"github.com/secrethub/secrethub-go/internals/api"
	"github.com/secrethub/secrethub-go/internals/api/uuid"
	"github.com/secrethub/secrethub-go/internals/errio"
)

// DirService handles operations on directories from SecretHub.
type DirService interface {
	// Create a directory at a given path.
	Create(path string) (*api.Dir, error)
	// Get returns the directory with the given ID.
	GetByID(id uuid.UUID) (*api.Dir, error)
	// Delete removes the directory at the given path.
	Delete(path string) error
	// GetTree retrieves a directory at a given path and all of its descendants up to a given depth.
	// When the depth <= 0, all descendants are returned. When ancestors is true, the parent directories
	// of the dir at the given path will also be included in the tree.
	GetTree(path string, depth int, ancestors bool) (*api.Tree, error)
}

func newDirService(client *Client) DirService {
	return dirService{
		client: client,
	}
}

type dirService struct {
	client *Client
}

// Get returns the directory with the given ID.
func (s dirService) GetByID(id uuid.UUID) (*api.Dir, error) {
	encDir, err := s.client.httpClient.GetDirByID(id)
	if err != nil {
		return nil, errio.Error(err)
	}

	accountKey, err := s.client.getAccountKey()
	if err != nil {
		return nil, errio.Error(err)
	}

	dir, err := encDir.Decrypt(accountKey)
	if err != nil {
		return nil, errio.Error(err)
	}

	return dir, nil
}

// GetTree retrieves a directory tree at a given path. The contents to the given depth
// are returned. When depth is -1 all contents of the directory are included in the tree.
// When ancestors is true, the parent directories of the dir at the given path will also
// be included in the tree.
func (s dirService) GetTree(path string, depth int, ancestors bool) (*api.Tree, error) {
	p, err := api.NewDirPath(path)
	if err != nil {
		return nil, errio.Error(err)
	}

	blindName, err := s.client.convertPathToBlindName(p)
	if err != nil {
		return nil, errio.Error(err)
	}

	encTree, err := s.client.httpClient.GetTree(blindName, depth, ancestors)
	if err != nil {
		return nil, errio.Error(err)
	}

	accountKey, err := s.client.getAccountKey()
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
		tree.ParentPath = api.ParentPath(p.GetNamespace())
	} else {
		// When ancestors are not retrieved, the root of the filesystem is the directory at path.
		// So, the parentPath of the filesystem is then the parent of the directory at path.
		tree.ParentPath, err = p.GetParentPath()
		if err != nil {
			return nil, errio.Error(err)
		}
	}

	return tree, errio.Error(err)
}

// Create creates a directory at a given path.
func (s dirService) Create(path string) (*api.Dir, error) {
	p, err := api.NewDirPath(path)
	if err != nil {
		return nil, errio.Error(err)
	}

	parentPath, err := p.GetParentPath()
	if err != nil {
		return nil, errio.Error(err)
	}

	accounts, err := s.client.listDirAccounts(parentPath)
	if err != nil {
		return nil, errio.Error(err)
	}

	encryptedNames, err := encryptNameForAccounts(p.GetDirName(), accounts...)
	if err != nil {
		return nil, errio.Error(err)
	}

	blindName, err := s.client.convertPathToBlindName(p)
	if err != nil {
		return nil, errio.Error(err)
	}

	parentBlindName, err := s.client.convertPathToBlindName(parentPath)
	if err != nil {
		return nil, errio.Error(err)
	}

	request := &api.CreateDirRequest{
		BlindName:       blindName,
		ParentBlindName: parentBlindName,

		EncryptedNames: encryptedNames,
	}

	encryptedDir, err := s.client.httpClient.CreateDir(p.GetNamespace(), p.GetRepo(), request)
	if err != nil {
		return nil, errio.Error(err)
	}

	accountKey, err := s.client.getAccountKey()
	if err != nil {
		return nil, errio.Error(err)
	}

	dir, err := encryptedDir.Decrypt(accountKey)
	return dir, errio.Error(err)
}

// Delete removes the directory at the given path.
func (s dirService) Delete(path string) error {
	p, err := api.NewDirPath(path)
	if err != nil {
		return errio.Error(err)
	}

	dirBlindName, err := s.client.convertPathToBlindName(p)
	if err != nil {
		return errio.Error(err)
	}

	err = s.client.httpClient.DeleteDir(dirBlindName)
	if err != nil {
		return errio.Error(err)
	}

	return nil
}

// listDirAccounts list the accounts with read permission.
func (c *Client) listDirAccounts(path api.BlindNamePath) ([]*api.Account, error) {
	blindName, err := c.convertPathToBlindName(path)
	if err != nil {
		return nil, errio.Error(err)
	}

	accounts, err := c.httpClient.ListDirAccounts(blindName)
	return accounts, errio.Error(err)
}
