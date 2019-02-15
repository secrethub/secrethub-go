package randchar

import (
	"crypto/rand"
	"fmt"
	"math/big"
)

var (
	// Numeric defines a character set containing all numbers.
	Numeric = Charset("0123456789")
	// Lowercase defines a character set containing all lowercase letters.
	Lowercase = Charset("abcdefghijklmnopqrstuvwxyz")
	// Uppercase defines a character set containing all uppercase letters.
	Uppercase = Charset("ABCDEFGHIJKLMNOPQRSTUVWXYZ")
	// Alphanumeric defines a character set containing letters and numbers.
	Alphanumeric = Numeric.Add(Lowercase).Add(Uppercase)
	// Symbols defines a character set containing special characters commonly used for passwords.
	Symbols = Charset("!@#$%^*-_+=.,?")
	// All defines a character set containing both alphanumeric and symbol characters.
	All = Alphanumeric.Add(Symbols)
	// Similar defines a character set containing similar looking characters.
	Similar = Charset("iIlL1oO0")

	// DefaultGenerator defines the default generator to use. You can create
	// your own generators using NewGenerator.
	DefaultGenerator = NewGenerator(Alphanumeric, nil)
)

// Generator generates random byte arrays.
type Generator interface {
	Generate(n int) ([]byte, error)
}

// NewGenerator creates a new random generator.
func NewGenerator(base Charset, filter Charset, reqs ...Requirement) Generator {
	minLen := 0
	for i, req := range reqs {
		reqs[i].Charset = req.Charset.Subtract(filter)
		minLen += req.MinCount
	}

	return &generator{
		requirements: reqs,
		base:         base.Subtract(filter),
		minLen:       minLen,
	}
}

// generator helps generating slices of randomly chosen
// characters from a given character set.
type generator struct {
	requirements []Requirement
	base         Charset
	minLen       int
}

// Requirement defines a minimum number of characters that must be from a given character set.
type Requirement struct {
	Charset  Charset
	MinCount int
}

// Generate returns a byte slice of length n filled with randomly chosen characters from the character set.
func (g generator) Generate(n int) ([]byte, error) {
	if n < g.minLen {
		return nil, fmt.Errorf("n cannot be smaller than the minimum required length of the generator")
	}

	var result []byte
	for _, req := range g.requirements {
		chars, err := req.Charset.Rand(req.MinCount)
		if err != nil {
			return nil, err
		}
		result = append(result, chars...)
	}

	remainder, err := g.base.Rand(n - g.minLen)
	if err != nil {
		return nil, err
	}
	result = append(result, remainder...)

	return shuffle(result)
}

// shuffle randomly shuffles elements of a byte slice, using the Durstenfeld shuffle algorithm.
func shuffle(data []byte) ([]byte, error) {
	for i := len(data) - 1; i > 0; i-- {
		randomIndex, err := rand.Int(rand.Reader, big.NewInt(int64(i)))
		if err != nil {
			return nil, err
		}
		j := randomIndex.Int64()
		data[i], data[j] = data[j], data[i]
	}

	return data, nil
}

// Charset is a byte slice with a set of unique characters.
type Charset []byte

// Rand returns a byte slice of length n filled with randomly chosen characters from the set.
func (cs Charset) Rand(n int) ([]byte, error) {
	data := make([]byte, n)

	size := big.NewInt(int64(len(cs)))
	for i := 0; i < n; i++ {
		randomIndex, err := rand.Int(rand.Reader, size)
		if err != nil {
			return nil, err
		}
		data[i] = cs[randomIndex.Int64()]
	}
	return data, nil
}

// Add merges two character sets into one, removing duplicates.
func (cs Charset) Add(set Charset) Charset {
	uniques := make(map[byte]struct{})
	for _, char := range cs {
		uniques[char] = struct{}{}
	}

	for _, char := range set {
		uniques[char] = struct{}{}
	}

	result := make([]byte, len(uniques))
	i := 0
	for char := range uniques {
		result[i] = char
		i++
	}

	return result
}

// Subtract removes all characters from a set that match a given set of characters.
func (cs Charset) Subtract(set Charset) Charset {
	filter := make(map[byte]struct{})
	for _, char := range set {
		filter[char] = struct{}{}
	}

	result := []byte{}
	for _, char := range cs {
		_, exists := filter[char]
		if !exists {
			result = append(result, char)
		}
	}

	return result
}
