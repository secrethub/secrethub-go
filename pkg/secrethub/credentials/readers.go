package credentials

import (
	"io/ioutil"
	"os"
)

// Reader helps with reading bytes from a configured source.
type Reader interface {
	// Read reads from the reader and returns the resulting bytes.
	Read() ([]byte, error)
}

// FromFile returns a reader that reads the contents of a file,
// e.g. a credential or a passphrase.
func FromFile(path string) Reader {
	return readerFunc(func() ([]byte, error) {
		return ioutil.ReadFile(path)
	})
}

// FromEnv returns a reader that reads the contents of an
// environment variable, e.g. a credential or a passphrase.
func FromEnv(key string) Reader {
	return readerFunc(func() ([]byte, error) {
		return []byte(os.Getenv(key)), nil
	})
}

// FromBytes returns a reader that simply returns the given bytes
// when Read() is called.
func FromBytes(raw []byte) Reader {
	return readerFunc(func() ([]byte, error) {
		return raw, nil
	})
}

// FromString returns a reader that simply returns the given string as
// a byte slice when Read() is called.
func FromString(raw string) Reader {
	return readerFunc(func() ([]byte, error) {
		return []byte(raw), nil
	})
}

// readerFunc is a helper function to create a reader from any func() ([]byte, error).
type readerFunc func() ([]byte, error)

// Read implements the Reader interface.
func (f readerFunc) Read() ([]byte, error) {
	return f()
}
