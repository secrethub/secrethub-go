package randchar

import (
	"crypto/rand"
	"fmt"
	"io"
	"math/big"
)

var (
	// Numeric defines a character set containing all numbers.
	Numeric = NewCharset("0123456789")
	// Lowercase defines a character set containing all lowercase letters.
	Lowercase = NewCharset("abcdefghijklmnopqrstuvwxyz")
	// Uppercase defines a character set containing all uppercase letters.
	Uppercase = NewCharset("ABCDEFGHIJKLMNOPQRSTUVWXYZ")
	// Letters defines a character set containing all upper- and lowercase letters of the alphabet.
	Letters = Lowercase.Add(Uppercase)
	// Alphanumeric defines a character set containing letters and numbers.
	Alphanumeric = Letters.Add(Numeric)
	// Symbols defines a character set containing special characters commonly used for passwords.
	Symbols = NewCharset("!@#$%^*-_+=.,?")
	// All defines a character set containing both alphanumeric and symbol characters.
	All = Alphanumeric.Add(Symbols)
	// Similar defines a character set containing similar looking characters.
	Similar = NewCharset("iIlL1oO0")

	// DefaultRand defines the default random generator to use. You can create
	// your own generators using NewRand.
	DefaultRand = NewRand(Alphanumeric)
)

// Generator generates random byte arrays.
type Generator interface {
	Generate(n int) ([]byte, error)
}

// NewGenerator is a shorthand function to create a new random alphanumeric
// generator, optionally configured to use symbols too. For more flexibility
// to configure the random generator, use NewRand instead.
func NewGenerator(useSymbols bool) Generator {
	if useSymbols {
		return NewRand(Alphanumeric.Add(Symbols))
	}
	return NewRand(Alphanumeric)
}

// Rand helps generating slices of randomly chosen
// characters from a given character set.
type Rand struct {
	reader io.Reader
	base   Charset
	minima []minimum
	minLen int
}

// NewRand initializes a new random generator from the given character set
// and configures it with the given options.
func NewRand(base Charset, options ...Option) Rand {
	r := Rand{
		reader: rand.Reader,
		base:   base,
	}

	for _, opt := range options {
		r = opt(r)
	}
	return r
}

// Option defines a configuration option for a random reader.
type Option func(r Rand) Rand

// minimum defines a minimum number of characters that must be from a given character set.
type minimum struct {
	count   int
	charset Charset
}

// Min ensures the generated slice contains at least n characters from the given character set.
func Min(n int, charset Charset) Option {
	return func(r Rand) Rand {
		r.minima = append(r.minima, minimum{
			count:   n,
			charset: charset,
		})
		r.minLen += n
		return r
	}
}

// WithReader allows you to set the reader used as source of randomness.
// Do not use this unless you know what you're doing. By default, the
// jsource of randomness is set to rand.Reader.
func WithReader(reader io.Reader) Option {
	return func(r Rand) Rand {
		r.reader = reader
		return r
	}
}

// Generate returns a randomly generated slice of characters that meets the requirements of the reader.
func (r Rand) Generate(n int) ([]byte, error) {
	if n < r.minLen {
		return nil, fmt.Errorf("n cannot be smaller than the minimum required length of the generator")
	}

	var result []byte
	for _, min := range r.minima {
		chars, err := min.charset.rand(r.reader, min.count)
		if err != nil {
			return nil, err
		}
		result = append(result, chars...)
	}

	remainder, err := r.base.rand(r.reader, n-r.minLen)
	if err != nil {
		return nil, err
	}
	result = append(result, remainder...)

	return shuffle(r.reader, result)
}

// shuffle randomly shuffles elements of a byte slice, using the Durstenfeld shuffle algorithm.
func shuffle(reader io.Reader, data []byte) ([]byte, error) {
	for i := len(data) - 1; i > 0; i-- {
		randomIndex, err := rand.Int(reader, big.NewInt(int64(i)))
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

// NewCharset creates a set of characters from a given byte slice, removing duplicates to ensure the random generators are not biased.
func NewCharset(characters string) Charset {
	uniques := make(map[byte]struct{})
	for _, char := range []byte(characters) {
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

// rand returns a byte slice of length n filled with randomly chosen characters
// from the set, using the given reader as source of randomness.
func (cs Charset) rand(reader io.Reader, n int) ([]byte, error) {
	data := make([]byte, n)

	size := big.NewInt(int64(len(cs)))
	for i := 0; i < n; i++ {
		randomIndex, err := rand.Int(reader, size)
		if err != nil {
			return nil, err
		}
		data[i] = cs[randomIndex.Int64()]
	}
	return data, nil
}
