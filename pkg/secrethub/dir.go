package secrethub

import (
	"fmt"
	"strings"

	"github.com/secrethub/secrethub-go/internals/api"
	"github.com/secrethub/secrethub-go/internals/api/uuid"
	"github.com/secrethub/secrethub-go/internals/errio"
	"github.com/secrethub/secrethub-go/pkg/secretpath"
)

// DirService handles operations on directories from SecretHub.
type DirService interface {
	// Create a directory at a given path.
	Create(path string) (*api.Dir, error)
	// CreateAll creates all directories in the given path that do not exist yet.
	//
	// Contrary to Create, it doesn't return an error when the directories already exist.
	CreateAll(path string) error
	// Exists returns whether a directory where you have access to exists at a given path.
	Exists(path string) (bool, error)
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

	blindName, err := s.client.convertPathToBlindName(p)
	if err != nil {
		return nil, errio.Error(err)
	}

	parentBlindName, err := s.client.convertPathToBlindName(parentPath)
	if err != nil {
		return nil, errio.Error(err)
	}

	dirName := p.GetDirName()

	encryptedNamesMap := make(map[uuid.UUID]api.EncryptedNameRequest)
	tries := 0
	for {
		accounts, err := s.client.listDirAccounts(parentPath)
		if err != nil {
			return nil, errio.Error(err)
		}

		for _, account := range accounts {
			_, ok := encryptedNamesMap[account.AccountID]
			if !ok {
				encryptedName, err := encryptNameForAccount(dirName, account)
				if err != nil {
					return nil, err
				}
				encryptedNamesMap[account.AccountID] = encryptedName
			}
		}

		encryptedNames := make([]api.EncryptedNameRequest, len(encryptedNamesMap))
		i := 0
		for _, encryptedName := range encryptedNamesMap {
			encryptedNames[i] = encryptedName
			i++
		}

		request := &api.CreateDirRequest{
			BlindName:       blindName,
			ParentBlindName: parentBlindName,

			EncryptedNames: encryptedNames,
		}

		encryptedDir, err := s.client.httpClient.CreateDir(p.GetNamespace(), p.GetRepo(), request)
		if err == nil {
			accountKey, err := s.client.getAccountKey()
			if err != nil {
				return nil, errio.Error(err)
			}

			dir, err := encryptedDir.Decrypt(accountKey)
			return dir, errio.Error(err)
		}
		if err != api.ErrNotEncryptedForAccounts {
			return nil, err
		}
		if tries >= missingMemberRetries {
			return nil, fmt.Errorf("cannot create directory: access rules giving access to the directory are simultaneously being created; you may try again")
		}
		tries++
	}
}

// Exists returns whether a directory where you have access to exists at a given path.
func (s dirService) Exists(path string) (bool, error) {
	_, err := s.GetTree(path, 0, false)
	if api.IsErrNotFound(err) {
		return false, nil
	} else if err != nil {
		return false, err
	}
	return true, nil
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

// CreateAll creates all directories in the given path that do not exist yet.
//
// Contrary to Create, it doesn't return an error when the directories already exist.
func (s dirService) CreateAll(path string) error {
	err := api.ValidateDirPath(path)
	if err != nil {
		return err
	}
	return s.createAll(path)
}

func (s dirService) createAll(path string) error {
	if len(strings.Split(path, "/")) < 3 {
		return nil
	}

	exists, err := s.Exists(path)
	if err != nil {
		return err
	}
	if exists {
		return nil
	}

	err = s.createAll(secretpath.Parent(path))
	if err != nil {
		return err
	}

	_, err = s.Create(path)
	if err == api.ErrDirAlreadyExists {
		return nil
	}
	// err might be nil
	return err
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
