package randchar

import (
	"errors"
	"testing"

	"github.com/secrethub/secrethub-go/internals/assert"
)

func TestMin(t *testing.T) {
	cases := map[string]struct {
		base                  Charset
		minima                []minimum
		expectedInitError     error
		n                     int
		expectedGenerateError error
	}{
		"n > min": {
			base:   Alphanumeric,
			minima: []minimum{{2, Numeric}},
			n:      3,
		},
		"n == min": {
			base:   Alphanumeric,
			minima: []minimum{{2, Numeric}},
			n:      2,
		},
		"n < min": {
			base:                  Alphanumeric,
			minima:                []minimum{{3, Numeric}},
			n:                     2,
			expectedGenerateError: errors.New("n cannot be smaller than the minimum required length of the generator"),
		},
		"min not in base set": {
			base:              Alphanumeric,
			minima:            []minimum{{2, Symbols}},
			expectedInitError: errors.New("minimum character set must be a subset of the base character set"),
			n:                 3,
		},
		"empty min set": {
			base:              Alphanumeric,
			minima:            []minimum{{2, nil}},
			expectedInitError: errors.New("minimum character set cannot be empty"),
			n:                 3,
		},
		"zero minimum": {
			base:              Alphanumeric,
			minima:            []minimum{{0, Numeric}},
			expectedInitError: errors.New("minimum must be at least 1"),
			n:                 3,
		},
		"multiple minima": {
			base:   Alphanumeric,
			minima: []minimum{{1, Numeric}, {1, Uppercase}},
			n:      3,
		},
		"multiple minima == n": {
			base:   Alphanumeric,
			minima: []minimum{{2, Numeric}, {1, Uppercase}},
			n:      3,
		},
		"multiple minima > n": {
			base:                  Alphanumeric,
			minima:                []minimum{{2, Numeric}, {2, Uppercase}},
			n:                     3,
			expectedGenerateError: errors.New("n cannot be smaller than the minimum required length of the generator"),
		},
		"multiple minima with same charset small first": {
			base:   Alphanumeric,
			minima: []minimum{{1, Numeric}, {2, Numeric}},
			n:      3,
		},
		"multiple minima with same charset big first": {
			base:   Alphanumeric,
			minima: []minimum{{2, Numeric}, {1, Numeric}},
			n:      3,
		},
	}

	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			options := make([]Option, len(tc.minima))
			for i, min := range tc.minima {
				options[i] = Min(min.count, min.charset)
			}

			rand, err := NewRand(tc.base, options...)
			assert.Equal(t, err, tc.expectedInitError)

			// skip other assertions if error case
			if err != nil {
				return
			}

			actual, err := rand.Generate(tc.n)
			assert.Equal(t, err, tc.expectedGenerateError)

			// skip other assertions if error case
			if err != nil {
				return
			}

			for _, min := range tc.minima {
				count := countFromSet(actual, min.charset)
				if count < min.count {
					t.Errorf("unexpected count for %v: %d (actual) < %d (expected minimum)", min.charset, count, min.count)
				}
			}
		})
	}
}

func TestNewCharset(t *testing.T) {
	cases := map[string]struct {
		in       string
		expected string
	}{
		"empty": {
			in:       "",
			expected: "",
		},
		"duplicates": {
			in:       "aa",
			expected: "a",
		},
		"multiple": {
			in:       "abc",
			expected: "abc",
		},
	}

	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			actual := NewCharset(tc.in)

			if !actual.Equal(Charset(tc.expected)) {
				t.Errorf("unexpected result: %v (actual) != %v (expected)", actual, tc.expected)
			}
		})
	}
}
func TestAdd(t *testing.T) {
	cases := map[string]struct {
		a        string
		b        string
		expected string
	}{
		"equal": {
			a:        "abc",
			b:        "abc",
			expected: "abc",
		},
		"subset": {
			a:        "ab",
			b:        "abc",
			expected: "abc",
		},
		"superset": {
			a:        "abc",
			b:        "ab",
			expected: "abc",
		},
		"empty A": {
			a:        "",
			b:        "abc",
			expected: "abc",
		},
		"empty B": {
			a:        "abc",
			b:        "",
			expected: "abc",
		},
		"both empty": {
			a:        "",
			b:        "",
			expected: "",
		},
		"different": {
			a:        "ab",
			b:        "bc",
			expected: "abc",
		},
		"different with overlap": {
			a:        "ab",
			b:        "c",
			expected: "abc",
		},
	}

	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			actual := Charset(tc.a).Add(Charset(tc.b))

			if !actual.Equal(Charset(tc.expected)) {
				t.Errorf("unexpected result: %v (actual) != %v (expected)", actual, tc.expected)
			}
		})
	}
}

func TestSubtract(t *testing.T) {
	cases := map[string]struct {
		a        string
		b        string
		expected string
	}{
		"equal": {
			a:        "abc",
			b:        "abc",
			expected: "",
		},
		"subset": {
			a:        "ab",
			b:        "abc",
			expected: "",
		},
		"superset": {
			a:        "abc",
			b:        "ab",
			expected: "c",
		},
		"empty A": {
			a:        "",
			b:        "abc",
			expected: "",
		},
		"empty B": {
			a:        "abc",
			b:        "",
			expected: "abc",
		},
		"both empty": {
			a:        "",
			b:        "",
			expected: "",
		},
	}

	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			actual := Charset(tc.a).Subtract(Charset(tc.b))

			if !actual.Equal(Charset(tc.expected)) {
				t.Errorf("unexpected result: %v (actual) != %v (expected)", actual, tc.expected)
			}
		})
	}
}

func TestIsSubset(t *testing.T) {
	cases := map[string]struct {
		a        string
		b        string
		expected bool
	}{
		"equal": {
			a:        "abc",
			b:        "abc",
			expected: true,
		},
		"different order": {
			a:        "abc",
			b:        "cba",
			expected: true,
		},
		"subset": {
			a:        "ab",
			b:        "abc",
			expected: true,
		},
		"superset": {
			a:        "abc",
			b:        "ab",
			expected: false,
		},
		"empty A": {
			a:        "",
			b:        "abc",
			expected: true,
		},
		"empty B": {
			a:        "abc",
			b:        "",
			expected: false,
		},
		"both empty": {
			a:        "",
			b:        "",
			expected: true,
		},
	}

	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			actual := Charset(tc.a).IsSubset(Charset(tc.b))

			assert.Equal(t, actual, tc.expected)
		})
	}
}

func TestEqual(t *testing.T) {
	cases := map[string]struct {
		a        string
		b        string
		expected bool
	}{
		"equal": {
			a:        "abc",
			b:        "abc",
			expected: true,
		},
		"different order": {
			a:        "abc",
			b:        "cba",
			expected: true,
		},
		"subset": {
			a:        "ab",
			b:        "abc",
			expected: false,
		},
		"superset": {
			a:        "abc",
			b:        "ab",
			expected: false,
		},
		"empty A": {
			a:        "",
			b:        "abc",
			expected: false,
		},
		"empty B": {
			a:        "abc",
			b:        "",
			expected: false,
		},
		"both empty": {
			a:        "",
			b:        "",
			expected: true,
		},
	}

	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			actual := Charset(tc.a).Equal(Charset(tc.b))

			assert.Equal(t, actual, tc.expected)
		})
	}
}

func countFromSet(characters []byte, from Charset) int {
	n := 0
	for _, char := range characters {
		for _, in := range from {
			if char == in {
				n++
				break
			}
		}
	}
	return n
}

func BenchmarkGenerate24(b *testing.B) {
	rand := MustNewRand(Alphanumeric)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = rand.Generate(24)
	}
}

func BenchmarkGenerate24WithMinimum(b *testing.B) {
	rand := MustNewRand(Alphanumeric, Min(2, Numeric))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = rand.Generate(24)
	}
}

func BenchmarkGenerate128(b *testing.B) {
	rand := MustNewRand(Alphanumeric)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = rand.Generate(128)
	}
}

func BenchmarkGenerate128WithMinimum(b *testing.B) {
	rand := MustNewRand(Alphanumeric, Min(2, Numeric))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = rand.Generate(128)
	}
}
