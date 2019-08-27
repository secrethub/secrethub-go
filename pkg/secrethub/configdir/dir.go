package configdir

import (
	"errors"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"

	"github.com/mitchellh/go-homedir"
)

type Dir struct {
	Path string
}

func Default() (*Dir, error) {
	// TODO: move to constant?
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

func (c Dir) Credential() *CredentialFile {
	return &CredentialFile{
		Path: filepath.Join(c.Path, "credential"),
	}
}

type CredentialFile struct {
	Path string
}

func (f *CredentialFile) Write(p []byte) error {
	// TOOD: correct permission?
	err := os.MkdirAll(filepath.Dir(f.Path), 0600)
	if err != nil {
		return err
	}
	// TOOD: correct permission?
	return ioutil.WriteFile(f.Path, p, 0600)
}

func (f *CredentialFile) Exists() bool {
	if _, err := os.Stat(f.Path); os.IsNotExist(err) {
		return false
	}
	return true
}

func (f *CredentialFile) Read() ([]byte, error) {
	file, err := os.Open(f.Path)
	if os.IsNotExist(err) {
		// TOOD: return more usable error
		return nil, errors.New("credential not found. Please signup first")
	} else if err != nil {
		return nil, err
	}
	return ioutil.ReadAll(file)
}
