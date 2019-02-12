package randstr

import (
	"crypto/rand"
	"math/big"

	"github.com/keylockerbv/secrethub-go/pkg/errio"
)

var (
	// randPatternAlphanumeric is the default pattern of characters used to generate random secrets.
	randPatternAlphanumeric = []byte(`0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ`)
	// randPatternSymbols is added to the randPattern when generator.useSymbols is true.
	randPatternSymbols = []byte(`!@#$%^*-_+=.,?`)
)

// Generator generates random byte arrays.
type Generator interface {
	Generate(length int) ([]byte, error)
}

// NewGenerator creates a new random generator.
func NewGenerator(useSymbols bool) Generator {
	return &generator{
		useSymbols: useSymbols,
	}
}

type generator struct {
	useSymbols bool
}

// Generate returns a random byte array of given length.
func (generator generator) Generate(length int) ([]byte, error) {
	pattern := randPatternAlphanumeric
	if generator.useSymbols {
		pattern = append(pattern, randPatternSymbols...)
	}
	return randFromPattern(pattern, length)
}

func randFromPattern(pattern []byte, length int) ([]byte, error) {
	data := make([]byte, length)

	lengthPattern := len(pattern)
	for i := 0; i < length; i++ {
		c, err := rand.Int(rand.Reader, big.NewInt(int64(lengthPattern)))
		if err != nil {
			return nil, errio.Error(err)
		}
		data[i] = pattern[c.Int64()]
	}
	return data, nil
}
