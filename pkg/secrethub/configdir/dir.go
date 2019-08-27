// Package configdir provides simple functions to manage the SecretHub
// configuration directory.
package configdir

import (
	"errors"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"

	"github.com/mitchellh/go-homedir"
)

var (
	// ErrCredentialNotFound is returned when a credential file does not exist but CredentialFile.Read() is called.
	ErrCredentialNotFound = errors.New("credential not found")
)

// Dir represents the configuration directory located at some path
// on the file system.
type Dir struct {
	Path string
}

// Default is the default way to get the location of the SecretHub
// configuration directory, sourcing it from the environment variable
// SECRETHUB_CONFIG_DIR or falling back to the ~/.secrethub directory.
func Default() (*Dir, error) {
	envDir := os.Getenv("SECRETHUB_CONFIG_DIR")
	if envDir != "" {
		return &Dir{
			Path: envDir,
		}, nil
	}

	homeDir, err := homedir.Dir()
	if err != nil {
		return &Dir{}, fmt.Errorf("cannot get home directory: %v", err)
	}
	return &Dir{
		Path: filepath.Join(homeDir, ".secrethub"),
	}, nil
}

// Credential returns the file that contains the SecretHub API credential.
func (c Dir) Credential() *CredentialFile {
	return &CredentialFile{
		Path: filepath.Join(c.Path, "credential"),
	}
}

func (c Dir) String() string {
	return c.Path
}

// CredentialFile represents the file that contains the SecretHub API credential.
// By default, it's a file named "credential" in the configuration directory.
type CredentialFile struct {
	Path string
}

// Write writes the given bytes to the credential file.
func (f *CredentialFile) Write(data []byte) error {
	err := os.MkdirAll(filepath.Dir(f.Path), os.FileMode(0700))
	if err != nil {
		return err
	}
	return ioutil.WriteFile(f.Path, data, os.FileMode(0600))
}

// Exists returns true when a file exists at the path this credential points to.
func (f *CredentialFile) Exists() bool {
	if _, err := os.Stat(f.Path); os.IsNotExist(err) {
		return false
	}
	return true
}

// Read reads from the filesystem and returns the contents of the credential file.
func (f *CredentialFile) Read() ([]byte, error) {
	file, err := os.Open(f.Path)
	if os.IsNotExist(err) {
		return nil, ErrCredentialNotFound
	} else if err != nil {
		return nil, err
	}
	return ioutil.ReadAll(file)
}
