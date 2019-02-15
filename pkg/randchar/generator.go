package randchar

import (
	"crypto/rand"
	"math/big"
)

var (
	// randPatternAlphanumeric is the default pattern of characters used to generate random secrets.
	randPatternAlphanumeric = []byte(`0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ`)
	// randPatternSymbols is added to the randPattern when generator.useSymbols is true.
	randPatternSymbols = []byte(`!@#$%^*-_+=.,?`)

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
	Similar = Charset("ilL1oO0")
)

// Generator generates random byte arrays.
type Generator interface {
	Generate(n int) ([]byte, error)
}

// NewGenerator creates a new random generator.
func NewGenerator(useSymbols bool) Generator {
	charset := Alphanumeric
	if useSymbols {
		charset = All
	}

	return &generator{
		charset: charset,
	}
}

// generator helps generating slices of randomly chosen
// characters from a given character set.
type generator struct {
	charset Charset
}

// Generate returns a byte slice of length n filled with randomly chosen characters from the character set.
func (g generator) Generate(n int) ([]byte, error) {
	return g.charset.Rand(n)
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
