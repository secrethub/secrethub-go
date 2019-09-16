// +build !production

// Package fakes provides mock implementations to be used in testing.
package fakes

// FakeRandomGenerator can be used to mock a RandomGenerator.
type FakeRandomGenerator struct {
	Ret []byte
	Err error
}

// Generate returns the mocked Generate response.
func (generator FakeRandomGenerator) Generate(length int) ([]byte, error) {
	return generator.Ret, generator.Err
}
