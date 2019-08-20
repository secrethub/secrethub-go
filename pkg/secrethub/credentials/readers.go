package credentials

import (
	"io"
	"io/ioutil"
	"os"
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
