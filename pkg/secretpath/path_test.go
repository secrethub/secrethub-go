package secretpath_test

import (
	"testing"

	"github.com/secrethub/secrethub-go/internals/assert"
	"github.com/secrethub/secrethub-go/pkg/secretpath"
)

// TODO: implement these functions:
// func Validate(path string) error {}
// func IsSecret(path string) bool {}
// func IsDir(path string) bool {}
// func IsRepo(path string) bool {}
// func IsNamespace(path string) bool {}

func TestJoin(t *testing.T) {
	cases := map[string]struct {
		elem     []string
		expected string
	}{
		"empty string": {
			elem:     []string{""},
			expected: "",
		},
		"zero": {
			elem:     []string{},
			expected: "",
		},
		"one": {
			elem:     []string{"foo"},
			expected: "foo",
		},
		"two": {
			elem:     []string{"foo", "bar"},
			expected: "foo/bar",
		},
		"empty string in the middle": {
			elem:     []string{"foo", "", "bar"},
			expected: "foo/bar",
		},
		"empty leading string": {
			elem:     []string{"", "foo", "bar"},
			expected: "foo/bar",
		},
		"with separator": {
			elem:     []string{"foo/"},
			expected: "foo",
		},
		"with separator in the middle": {
			elem:     []string{"foo/", "bar"},
			expected: "foo/bar",
		},
		"with separator arg": {
			elem:     []string{"foo", "/", "bar"},
			expected: "foo/bar",
		},
		"with version": {
			elem:     []string{"foo", "bar:latest"},
			expected: "foo/bar:latest",
		},
		"with separate version": {
			elem:     []string{"foo", "bar", ":latest"},
			expected: "foo/bar:latest",
		},
	}

	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			actual := secretpath.Join(tc.elem...)

			assert.Equal(t, actual, tc.expected)
		})
	}
}

func TestBase(t *testing.T) {
	cases := map[string]struct {
		path     string
		expected string
	}{
		"one element": {
			path:     "foo",
			expected: "foo",
		},
		"two elements": {
			path:     "foo/bar",
			expected: "bar",
		},
		"one element trailing separator": {
			path:     "foo/",
			expected: "foo",
		},
		"two elements trailing separator": {
			path:     "foo/bar/",
			expected: "bar",
		},
		"with version": {
			path:     "foo/bar/baz:1",
			expected: "baz",
		},
		"with latest version": {
			path:     "foo/bar/baz:1",
			expected: "baz",
		},
		"illegal": {
			path:     "foo/illegal#$%",
			expected: "illegal#$%",
		},
	}

	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			actual := secretpath.Base(tc.path)

			assert.Equal(t, actual, tc.expected)
		})
	}
}

func TestParent(t *testing.T) {
	cases := map[string]struct {
		path     string
		expected string
	}{
		"empty string": {
			path:     "",
			expected: "",
		},
		"separator only": {
			path:     "/",
			expected: "",
		},
		"one element": {
			path:     "foo",
			expected: "",
		},
		"two elements": {
			path:     "foo/bar",
			expected: "foo",
		},
		"two elements with version": {
			path:     "foo/bar:1",
			expected: "foo",
		},
	}

	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			actual := secretpath.Parent(tc.path)

			assert.Equal(t, actual, tc.expected)
		})
	}
}

func TestHasVersion(t *testing.T) {
	cases := map[string]struct {
		path     string
		expected bool
	}{
		"empty string": {
			path:     "",
			expected: false,
		},
		"one element": {
			path:     "foo",
			expected: false,
		},
		"two elements with version": {
			path:     "foo/bar:1",
			expected: true,
		},
		"numbered version": {
			path:     "foo/bar/baz:1",
			expected: true,
		},
		"latest version": {
			path:     "foo/bar/baz:latest",
			expected: true,
		},
		"empty version": {
			path:     "foo/bar/baz:",
			expected: false,
		},
	}

	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			actual := secretpath.HasVersion(tc.path)

			assert.Equal(t, actual, tc.expected)
		})
	}
}

func TestVersion(t *testing.T) {
	cases := map[string]struct {
		path     string
		expected int
	}{
		"empty string": {
			path:     "",
			expected: 0,
		},
		"one element": {
			path:     "foo",
			expected: 0,
		},
		"numbered version": {
			path:     "foo/bar/baz:1",
			expected: 1,
		},
		"multi-digit version": {
			path:     "foo/bar/baz:12",
			expected: 12,
		},
		"latest version": {
			path:     "foo/bar/baz:latest",
			expected: -1,
		},
		"negative version": {
			path:     "foo/bar/baz:-3",
			expected: -1,
		},
		"illegal text version": {
			path:     "foo/bar/baz:illegal",
			expected: 0,
		},
		"empty version": {
			path:     "foo/bar/baz:",
			expected: 0,
		},
	}

	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			actual := secretpath.Version(tc.path)

			assert.Equal(t, actual, tc.expected)
		})
	}
}

func TestAddVersion(t *testing.T) {
	cases := map[string]struct {
		path     string
		version  int
		expected string
	}{
		"empty string": {
			path:     "",
			version:  1,
			expected: ":1",
		},
		"one element": {
			path:     "foo",
			version:  1,
			expected: "foo:1",
		},
		"two elements": {
			path:     "foo/bar",
			version:  1,
			expected: "foo/bar:1",
		},
		"ends in separator": {
			path:     "foo/bar/",
			version:  1,
			expected: "foo/bar:1",
		},
		"already has numbered version": {
			path:     "foo/bar/baz:1",
			version:  -1,
			expected: "foo/bar/baz:latest",
		},
		"already has latest version": {
			path:     "foo/bar/baz:latest",
			version:  1,
			expected: "foo/bar/baz:1",
		},
		"already has same version": {
			path:     "foo/bar/baz:latest",
			version:  -1,
			expected: "foo/bar/baz:latest",
		},
	}

	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			actual := secretpath.AddVersion(tc.path, tc.version)

			assert.Equal(t, actual, tc.expected)
		})
	}
}

func TestClean(t *testing.T) {
	cases := map[string]struct {
		path     string
		expected string
	}{
		"empty": {
			path:     "",
			expected: "",
		},
		"only sep": {
			path:     "/",
			expected: "",
		},
		"only multiple sep": {
			path:     "///",
			expected: "",
		},
		"cleaned": {
			path:     "foo/bar/baz",
			expected: "foo/bar/baz",
		},
		"prefix": {
			path:     "/foo/bar/baz",
			expected: "foo/bar/baz",
		},
		"suffix": {
			path:     "foo/bar/baz/",
			expected: "foo/bar/baz",
		},
		"middle double": {
			path:     "foo/bar//baz",
			expected: "foo/bar/baz",
		},
		"middle triple": {
			path:     "foo///bar/baz",
			expected: "foo/bar/baz",
		},
		"version suffix": {
			path:     "foo/bar//baz:latest",
			expected: "foo/bar/baz:latest",
		},
		"version suffix with sep": {
			path:     "foo/bar/baz/:latest",
			expected: "foo/bar/baz:latest",
		},
	}

	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			actual := secretpath.Clean(tc.path)

			assert.Equal(t, actual, tc.expected)
		})
	}
}

func TestCount(t *testing.T) {
	cases := map[string]struct {
		path     string
		expected int
	}{
		"sempty string": {
			path:     "",
			expected: 0,
		},
		"separators only": {
			path:     "/",
			expected: 0,
		},
		"one": {
			path:     "foo",
			expected: 1,
		},
		"two": {
			path:     "foo/bar",
			expected: 2,
		},
		"unclean": {
			path:     "foo//bar",
			expected: 2,
		},
	}

	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			actual := secretpath.Count(tc.path)

			assert.Equal(t, actual, tc.expected)
		})
	}
}

func TestRepo(t *testing.T) {
	cases := map[string]struct {
		path     string
		expected string
	}{
		"empty": {
			path:     "",
			expected: "",
		},
		"separator only": {
			path:     "//",
			expected: "",
		},
		"single element": {
			path:     "foo",
			expected: "",
		},
		"two elements": {
			path:     "foo/bar",
			expected: "foo/bar",
		},
		"single element with trailing separator": {
			path:     "foo/",
			expected: "",
		},
		"leading separator": {
			path:     "/foo/bar",
			expected: "foo/bar",
		},
		"leading separator three elements": {
			path:     "/foo/bar/baz",
			expected: "foo/bar",
		},
	}

	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			actual := secretpath.Repo(tc.path)

			assert.Equal(t, actual, tc.expected)
		})
	}
}

func TestNamespace(t *testing.T) {
	cases := map[string]struct {
		path     string
		expected string
	}{
		"empty": {
			path:     "",
			expected: "",
		},
		"separator only": {
			path:     "//",
			expected: "",
		},
		"single element": {
			path:     "foo",
			expected: "foo",
		},
		"multiple elements": {
			path:     "foo/bar",
			expected: "foo",
		},
		"single element with trailing separator": {
			path:     "foo/",
			expected: "foo",
		},
		"leading separator": {
			path:     "/foo",
			expected: "foo",
		},
		"leading separator multiple elements": {
			path:     "/foo/bar",
			expected: "foo",
		},
	}

	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			actual := secretpath.Namespace(tc.path)

			assert.Equal(t, actual, tc.expected)
		})
	}
}
