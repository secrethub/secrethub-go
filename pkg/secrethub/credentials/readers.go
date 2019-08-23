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

// FromFile returns an io.Reader that reads the contents from a file.
// This can be used to read a credential or passphrase from a file.
func FromFile(path string) io.Reader {
	return readerFunc(func() (io.Reader, error) {
		return os.Open(path)
	})
}

// FromEnv returns an io.Reader that reads the content of an environment variable.
// This can be used to read a credential or passphrase from a file.
func FromEnv(key string) io.Reader {
	return readerFunc(func() (io.Reader, error) {
		return strings.NewReader(os.Getenv(key)), nil
	})
}

// FromBytes returns an io.Reader that reads the provided bytes.
// This can be used to read a credential or passphrase from a byte slice.
func FromBytes(raw []byte) io.Reader {
	return readerFunc(func() (io.Reader, error) {
		return bytes.NewReader(raw), nil
	})
}

// FromString returns an io.Reader that reads the provided string.
// This can be used to read a credential or passphrase from a string.
func FromString(raw string) io.Reader {
	return readerFunc(func() (io.Reader, error) {
		return strings.NewReader(raw), nil
	})
}

// credentialFromDefault returns an io.Reader that tries to read a credential from any of the default locations.
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

// readerFunc is a helper function to create a io.Reader from any func() (io.Reader, error).
type readerFunc func() (io.Reader, error)

// Read implements Read() on readerFunc to implement the io.Reader interface.
func (f readerFunc) Read(p []byte) (n int, err error) {
	reader, err := f()
	if err != nil {
		return 0, err
	}
	return reader.Read(p)
}
