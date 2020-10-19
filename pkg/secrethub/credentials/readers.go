package credentials

import (
	"io/ioutil"
	"os"
)

// PassphraseReader helps with reading bytes from a configured source.
type PassphraseReader interface {
	// Read reads from the reader and returns the resulting bytes.
	Read() ([]byte, error)
}

type KeyReader interface {
	Read(decoder KeyDecoder) (Key, error)
}

// FromFile returns a reader that reads the contents of a file,
// e.g. a credential or a passphrase.
func FromFile(path string) KeyReader {
	return keyReaderFunc(func() ([]byte, error) {
		return ioutil.ReadFile(path)
	})
}

// FromEnv returns a reader that reads the contents of an
// environment variable, e.g. a credential or a passphrase.
func FromEnv(key string) KeyReader {
	return keyReaderFunc(func() ([]byte, error) {
		return []byte(os.Getenv(key)), nil
	})
}

// FromBytes returns a reader that simply returns the given bytes
// when Read() is called.
func FromBytes(raw []byte) KeyReader {
	return keyReaderFunc(func() ([]byte, error) {
		return raw, nil
	})
}

// FromString returns a reader that simply returns the given string as
// a byte slice when Read() is called.
func FromString(raw string) KeyReader {
	return keyReaderFunc(func() ([]byte, error) {
		return []byte(raw), nil
	})
}

// keyReaderFunc is a helper function to create a reader from any func() ([]byte, error).
type keyReaderFunc func() ([]byte, error)

// Read implements the Reader interface.
func (f keyReaderFunc) Read(decoder KeyDecoder) (Key, error) {
	keyBytes, err := f()
	if err != nil {
		return Key{}, err
	}
	return decoder.Decode(keyBytes)
}
