package credentials

import (
	"fmt"
	"io/ioutil"
	"os"
)

type ErrDecodingCredential struct {
	Location string
	Err      error
}

func (e ErrDecodingCredential) Error() string {
	return fmt.Sprintf("error decoding credential loaded from '%s': %v", e.Location, e.Err)
}

// PassphraseReader helps with reading bytes from a configured source.
type PassphraseReader interface {
	// Read reads from the reader and returns the resulting bytes.
	Read() ([]byte, error)
}

type passphraseReader func() ([]byte, error)

func (p passphraseReader) Read() ([]byte, error) {
	return p()
}

// PassphraseFromString returns a reader that simply returns the given string as
// a byte slice when Read() is called.
func PassphraseFromString(passphrase string) PassphraseReader {
	return passphraseReader(func() ([]byte, error) {
		return []byte(passphrase), nil
	})
}

type KeyReader interface {
	Read(decoder KeyDecoder) (Key, error)
}

// FromFile returns a reader that reads the contents of a file,
// e.g. a credential or a passphrase.
func FromFile(path string) KeyReader {
	return keyReaderFunc(func(decoder KeyDecoder) (Key, error) {
		keyBytes, err := ioutil.ReadFile(path)
		if err != nil {
			return Key{}, err
		}
		key, err := decoder.Decode(keyBytes)
		if err != nil {
			return Key{}, ErrDecodingCredential{
				Location: path,
				Err:      err,
			}
		}
		return key, nil
	})
}

// FromEnv returns a reader that reads the contents of an
// environment variable, e.g. a credential or a passphrase.
func FromEnv(envVarKey string) KeyReader {
	return keyReaderFunc(func(decoder KeyDecoder) (Key, error) {
		key, err := decoder.Decode([]byte(os.Getenv(envVarKey)))
		if err != nil {
			return Key{}, ErrDecodingCredential{
				Location: "$" + envVarKey,
				Err:      err,
			}
		}
		return key, nil
	})
}

// FromBytes returns a reader that simply returns the given bytes
// when Read() is called.
func FromBytes(raw []byte) KeyReader {
	return keyReaderFunc(func(decoder KeyDecoder) (Key, error) {
		return decoder.Decode(raw)
	})
}

// FromString returns a reader that simply returns the given string as
// a byte slice when Read() is called.
func FromString(raw string) KeyReader {
	return keyReaderFunc(func(decoder KeyDecoder) (Key, error) {
		return decoder.Decode([]byte(raw))
	})
}

// keyReaderFunc is a helper function to create a KeyReader with a custom Read function.
type keyReaderFunc func(decoder KeyDecoder) (Key, error)

// Read implements the Reader interface.
func (f keyReaderFunc) Read(decoder KeyDecoder) (Key, error) {
	return f(decoder)
}
