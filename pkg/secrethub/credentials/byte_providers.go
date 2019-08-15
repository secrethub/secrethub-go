package credentials

import "io/ioutil"

type BytesReader interface {
	Data() ([]byte, error)
}

type byteProviderFunc func() ([]byte, error)

func (f byteProviderFunc) Data() ([]byte, error) {
	return f()
}

func File(path string) BytesReader {
	return byteProviderFunc(func() ([]byte, error) {
		return ioutil.ReadFile(path)
	})
}

func Raw(raw []byte) BytesReader {
	return byteProviderFunc(func() ([]byte, error) {
		return raw, nil
	})
}
