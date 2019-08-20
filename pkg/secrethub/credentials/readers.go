package credentials

import (
	"io"
	"io/ioutil"
	"os"
	"path/filepath"

	"github.com/mitchellh/go-homedir"
)

// Errors
var (
	ErrCannotFindHomeDir = errCredentials.Code("cannot_find_home_dir").ErrorPref(
		"cannot find your home directory: %s",
	)
)

type Reader interface {
	Read() ([]byte, error)
}

type readerFunc func() ([]byte, error)

func (f readerFunc) Read() ([]byte, error) {
	return f()
}

func FromReader(reader io.Reader) Reader {
	return readerFunc(func() ([]byte, error) {
		return ioutil.ReadAll(reader)
	})
}

func FromFile(path string) Reader {
	return readerFunc(func() ([]byte, error) {
		return ioutil.ReadFile(path)
	})
}

func FromEnv(key string) Reader {
	return readerFunc(func() ([]byte, error) {
		return []byte(os.Getenv(key)), nil
	})
}

func FromBytes(raw []byte) Reader {
	return readerFunc(func() ([]byte, error) {
		return raw, nil
	})
}

func FromString(raw string) Reader {
	return readerFunc(func() ([]byte, error) {
		return []byte(raw), nil
	})
}

func fromDefault() Reader {
	return readerFunc(func() ([]byte, error) {
		envCredential := os.Getenv("SECRETHUB_CREDENTIAL")
		if envCredential != "" {
			return []byte(envCredential), nil
		}

		configDir := os.Getenv("SECRETHUB_CONFIG_DIR")
		if configDir == "" {
			home, err := homedir.Dir()
			if err != nil {
				return nil, ErrCannotFindHomeDir(err)
			}
			configDir = filepath.Join(home, ".secrethub")
		}

		return FromFile(filepath.Join(configDir, ".credential")).Read()
	})
}
