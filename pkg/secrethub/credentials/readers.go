package credentials

import (
	"bytes"
	"io"
	"os"
	"path/filepath"
	"strings"

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

type readerFunc func() (io.Reader, error)

func (f readerFunc) Read(p []byte) (n int, err error) {
	reader, err := f()
	if err != nil {
		return 0, err
	}
	return reader.Read(p)
}

func FromFile(path string) io.Reader {
	return readerFunc(func() (io.Reader, error) {
		return os.Open(path)
	})
}

func FromEnv(key string) io.Reader {
	return readerFunc(func() (io.Reader, error) {
		return strings.NewReader(os.Getenv(key)), nil
	})
}

func FromBytes(raw []byte) io.Reader {
	return readerFunc(func() (io.Reader, error) {
		return bytes.NewReader(raw), nil
	})
}

func FromString(raw string) io.Reader {
	return readerFunc(func() (io.Reader, error) {
		return strings.NewReader(raw), nil
	})
}

func credentialFromDefault() io.Reader {
	return readerFunc(func() (io.Reader, error) {
		envCredential := os.Getenv("SECRETHUB_CREDENTIAL")
		if envCredential != "" {
			return strings.NewReader(envCredential), nil
		}

		configDir := os.Getenv("SECRETHUB_CONFIG_DIR")
		if configDir == "" {
			home, err := homedir.Dir()
			if err != nil {
				return nil, ErrCannotFindHomeDir(err)
			}
			configDir = filepath.Join(home, ".secrethub")
		}

		return os.Open(filepath.Join(configDir, ".credential"))
	})
}
