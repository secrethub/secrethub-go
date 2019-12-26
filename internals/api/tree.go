package api

import (
	"bytes"
	"net/http"

	"github.com/gofrs/uuid"
	"github.com/secrethub/secrethub-go/internals/crypto"
	"github.com/secrethub/secrethub-go/internals/errio"
)

// Errors
var (
	ErrParentDirNotAvailable = errAPI.Code("parent_dir_not_available").StatusError("the parent directory is not available in EncryptedTree", http.StatusInternalServerError)
	ErrMultipleRootDirs      = errAPI.Code("multiple_root_dirs").StatusError("there are multiple root directories possible", http.StatusInternalServerError)
)

// EncryptedTree can construct a full tree at a certain path.
// It contains all dirs and secrets.
type EncryptedTree struct {
	Directories map[uuid.UUID]*EncryptedDir
	Secrets     []*EncryptedSecret
}

// DecryptContents decrypts every directory and Secret.
func (t EncryptedTree) DecryptContents(accountKey *crypto.RSAPrivateKey) ([]*Dir, []*Secret, error) {
	dirs := make([]*Dir, len(t.Directories))
	i := 0
	for _, encryptedDir := range t.Directories {
		dir, err := encryptedDir.Decrypt(accountKey)
		if err != nil {
			return nil, nil, err
		}

		dirs[i] = dir

		i++
	}

	secrets := make([]*Secret, len(t.Secrets))
	for i, encryptedSecret := range t.Secrets {
		secret, err := encryptedSecret.Decrypt(accountKey)
		if err != nil {
			return nil, nil, err
		}

		secrets[i] = secret
	}

	return dirs, secrets, nil
}

// Decrypt decrypts and constructs a tree of the directories and secrets.
// Decrypt does not set the ParentPath.
func (t EncryptedTree) Decrypt(accountKey *crypto.RSAPrivateKey) (*Tree, error) {
	// This could be done in a single for loop but for maintainability this structure has been adopted.
	var rootDir *Dir
	var err error

	dirs, secrets, err := t.DecryptContents(accountKey)
	if err != nil {
		return nil, err
	}

	// Create a map of all directories.
	// This has to be prepopulated to be able to put childs under parents.
	dirMap := make(map[uuid.UUID]*Dir)
	for _, dir := range dirs {
		dirMap[dir.DirID] = dir
	}

	// All directories are looped and placed below the parent directory as a subdirectory.
	for _, dir := range dirs {
		if dir.ParentID != nil {
			parentDir, ok := dirMap[*dir.ParentID]
			if !ok {
				return nil, ErrParentDirNotAvailable
			}

			parentDir.SubDirs = append(parentDir.SubDirs, dir)
		} else {
			if rootDir != nil {
				return nil, ErrMultipleRootDirs
			}

			rootDir = dir
		}
	}

	secretMap := make(map[uuid.UUID]*Secret)
	// All secrets are placed below every directory.
	for _, secret := range secrets {
		dir, ok := dirMap[secret.DirID]
		if !ok {
			return nil, ErrParentDirNotAvailable
		}

		dir.Secrets = append(dir.Secrets, secret)
		secretMap[secret.SecretID] = secret
	}

	return &Tree{
		RootDir: rootDir,
		Dirs:    dirMap,
		Secrets: secretMap,
	}, nil
}

// Tree  contains a full tree from the RootDir and all dirs and secrets.
// ParentPath is used to construct absolute paths.
// ParentPath is the path to the parent of the root dir, eg:
// For namespace/repo/parent/rootdir => namespace/repo/parent
type Tree struct {
	ParentPath ParentPath
	RootDir    *Dir
	Dirs       map[uuid.UUID]*Dir
	Secrets    map[uuid.UUID]*Secret
}

// SecretCount returns the number of secrets contained in the tree.
func (t Tree) SecretCount() int {
	return len(t.Secrets)
}

// DirCount returns the number of directories inside the tree.
// This does not include the root directory.
func (t Tree) DirCount() int {
	return len(t.Dirs) - 1
}

// AbsSecretPath returns the full path of secret.
// This function makes the assumption that every secret has a ParentDir.
// If not, an error will occur.
func (t Tree) AbsSecretPath(secretID uuid.UUID) (*SecretPath, error) {
	secret, ok := t.Secrets[secretID]
	if !ok {
		return nil, ErrSecretNotFound
	}

	dirPath, err := t.AbsDirPath(secret.DirID)
	if err != nil {
		return nil, errio.Error(err)
	}

	secretPath := dirPath.JoinSecret(secret.Name)

	return &secretPath, nil
}

// AbsDirPath returns the full path of dir
// This function makes the assumption that only the root dir has no parentID.
// If not, an error will occur.
func (t Tree) AbsDirPath(dirID uuid.UUID) (DirPath, error) {
	if bytes.Equal(dirID.Bytes(), t.RootDir.DirID.Bytes()) {
		dirPath := t.ParentPath.JoinDir(t.RootDir.Name)
		return dirPath, nil
	}

	dir, ok := t.Dirs[dirID]
	if !ok {
		return "", ErrDirNotFound
	}

	parentPath, err := t.AbsDirPath(*dir.ParentID)
	if err != nil {
		return "", errio.Error(err)
	}

	return parentPath.JoinDir(dir.Name), nil
}
