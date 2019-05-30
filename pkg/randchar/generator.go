package randchar

import (
	"crypto/rand"
	"errors"
	"io"
	"log"
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
	DefaultRand = MustNewRand(Alphanumeric)
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
		return MustNewRand(Alphanumeric.Add(Symbols))
	}
	return MustNewRand(Alphanumeric)
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
func NewRand(base Charset, options ...Option) (Rand, error) {
	r := Rand{
		reader: rand.Reader,
		base:   base,
	}

	var err error
	for _, opt := range options {
		r, err = opt(r)
		if err != nil {
			return r, err
		}
	}
	return r, nil
}

// MustNewRand is a utility function for creating random character generators,
// which panicks upon error so be careful. For more safety, use NewRand instead.
func MustNewRand(base Charset, options ...Option) Rand {
	r, err := NewRand(base, options...)
	if err != nil {
		log.Fatal(err)
	}
	return r
}

// Option defines a configuration option for a random reader.
type Option func(r Rand) (Rand, error)

// minimum defines a minimum number of characters that must be from a given character set.
type minimum struct {
	count   int
	charset Charset
}

// Min ensures the generated slice contains at least n characters from the given character set.
// When multiple Min options are given with the same character set, the biggest minimum takes precedence.
func Min(n int, charset Charset) Option {
	return func(r Rand) (Rand, error) {
		if n < 1 {
			return r, errors.New("minimum must be at least 1")
		}

		if len(charset) == 0 {
			return r, errors.New("minimum character set cannot be empty")
		}

		if !charset.IsSubset((r.base)) {
			return r, errors.New("minimum character set must be a subset of the base character set")
		}

		// Ensure the biggest minimum takes precedence when same charset minimum applies.
		for i, minimum := range r.minima {
			if minimum.charset.Equal(charset) {
				if minimum.count >= n {
					return r, nil
				}

				r.minLen += n - minimum.count
				r.minima[i].count = n
				return r, nil
			}
		}

		r.minima = append(r.minima, minimum{
			count:   n,
			charset: charset,
		})
		r.minLen += n
		return r, nil
	}
}

// WithReader allows you to set the reader used as source of randomness.
// Do not use this unless you know what you're doing. By default, the
// source of randomness is set to crypto/rand.Reader.
func WithReader(reader io.Reader) Option {
	return func(r Rand) (Rand, error) {
		r.reader = reader
		return r, nil
	}
}

// Generate returns a randomly generated slice of characters that meets the requirements of the reader.
func (r Rand) Generate(n int) ([]byte, error) {
	if n < r.minLen {
		return nil, errors.New("n cannot be smaller than the minimum required length of the generator")
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

// IsSubset returns true when the character set is a subset of the given set.
// When both sets are the same it returns true too.
func (cs Charset) IsSubset(of Charset) bool {
	set := map[byte]struct{}{}
	for _, char := range of {
		set[char] = struct{}{}
	}

	for _, char := range cs {
		_, found := set[char]
		if !found {
			return false
		}
	}

	return true
}

// Equal returns true when one character set is equal to another character set.
func (cs Charset) Equal(other Charset) bool {
	if len(cs) != len(other) {
		return false
	}

	return cs.IsSubset(other)
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
