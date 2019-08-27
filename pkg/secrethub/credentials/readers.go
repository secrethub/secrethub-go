package credentials

import (
	"io/ioutil"
	"os"
)

type Reader interface {
	Read() ([]byte, error)
}

// FromFile returns a Reader that reads the contents from a file.
// This can be used to read a credential or passphrase from a file.
func FromFile(path string) Reader {
	return readerFunc(func() ([]byte, error) {
		return ioutil.ReadFile(path)
	})
}

// FromEnv returns a Reader that reads the content of an environment variable.
// This can be used to read a credential or passphrase from a file.
func FromEnv(key string) Reader {
	return readerFunc(func() ([]byte, error) {
		return []byte(os.Getenv(key)), nil
	})
}

// FromBytes returns a Reader that reads the provided bytes.
// This can be used to read a credential or passphrase from a byte slice.
func FromBytes(raw []byte) Reader {
	return readerFunc(func() ([]byte, error) {
		return raw, nil
	})
}

// FromString returns a Reader that reads the provided string.
// This can be used to read a credential or passphrase from a string.
func FromString(raw string) Reader {
	return readerFunc(func() ([]byte, error) {
		return []byte(raw), nil
	})
}

// readerFunc is a helper function to create a Reader from any func() ([]byte, error).
type readerFunc func() ([]byte, error)

// Read implements Read() on readerFunc to implement the Reader interface.
func (f readerFunc) Read() ([]byte, error) {
	return f()
}
