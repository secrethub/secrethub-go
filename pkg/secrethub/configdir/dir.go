// Package configdir provides simple functions to manage the SecretHub
// configuration directory.
package configdir

import (
	"errors"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"

	"github.com/secrethub/secrethub-go/pkg/secrethub/credentials"

	"github.com/mitchellh/go-homedir"
)

var (
	// ErrCredentialNotFound is returned when a credential file does not exist but CredentialFile.Read() is called.
	ErrCredentialNotFound = errors.New("credential not found")
)

type ErrDecodingCredential struct {
	Location string
	Err      error
}

func (e ErrDecodingCredential) Error() string {
	return fmt.Sprintf("error decoding credential loaded from '%s': %v", e.Location, e.Err)
}

// Dir represents the configuration directory located at some path
// on the file system.
type Dir struct {
	path string
}

// New a new Dir which represents a configuration directory at the given location.
func New(path string) Dir {
	return Dir{
		path: path,
	}
}

// Default is the default way to get the location of the SecretHub
// configuration directory, sourcing it from the environment variable
// SECRETHUB_CONFIG_DIR or falling back to the ~/.secrethub directory.
func Default() (*Dir, error) {
	envDir := os.Getenv("SECRETHUB_CONFIG_DIR")
	if envDir != "" {
		return &Dir{
			path: envDir,
		}, nil
	}

	homeDir, err := homedir.Dir()
	if err != nil {
		return &Dir{}, fmt.Errorf("cannot get home directory: %v", err)
	}
	return &Dir{
		path: filepath.Join(homeDir, ".secrethub"),
	}, nil
}

// Credential returns the file that contains the SecretHub API credential.
func (c Dir) Credential() *CredentialFile {
	return &CredentialFile{
		path: filepath.Join(c.path, "credential"),
	}
}

// Path returns the path on the filesystem at which the config directory is located.
func (c Dir) Path() string {
	return c.path
}

func (c Dir) String() string {
	return c.path
}

// CredentialFile represents the file that contains the SecretHub API credential.
// By default, it's a file named "credential" in the configuration directory.
type CredentialFile struct {
	path string
}

// Path returns the path on the filesystem at which the credential file is located.
func (f *CredentialFile) Path() string {
	return f.path
}

// Write writes the given bytes to the credential file.
func (f *CredentialFile) Write(data []byte) error {
	err := os.MkdirAll(filepath.Dir(f.path), os.FileMode(0700))
	if err != nil {
		return err
	}
	return ioutil.WriteFile(f.path, data, os.FileMode(0600))
}

// Exists returns true when a file exists at the path this credential points to.
func (f *CredentialFile) Exists() bool {
	if _, err := os.Stat(f.path); os.IsNotExist(err) {
		return false
	}
	return true
}

// Read reads from the filesystem and returns the contents of the credential file.
func (f *CredentialFile) Read(decoder credentials.KeyDecoder) (credentials.Key, error) {
	file, err := os.Open(f.path)
	if os.IsNotExist(err) {
		return credentials.Key{}, ErrCredentialNotFound
	} else if err != nil {
		return credentials.Key{}, err
	}
	bytes, err := ioutil.ReadAll(file)
	if err != nil {
		return credentials.Key{}, err
	}
	key, err := decoder.Decode(bytes)
	if err != nil {
		return credentials.Key{}, ErrDecodingCredential{
			Location: f.path,
			Err:      err,
		}
	}
	return key, nil
}
