package api

import (
	"testing"

	"github.com/secrethub/secrethub-go/internals/assert"
)

func TestJoinPaths(t *testing.T) {
	cases := map[string]struct {
		elements []string
		expected string
	}{
		"one path": {
			elements: []string{"namespace/repo"},
			expected: "namespace/repo",
		},
		"empty element": {
			elements: []string{"namespace/repo", ""},
			expected: "namespace/repo",
		},
		"two paths, without separator": {
			elements: []string{"namespace/repo", "dir"},
			expected: "namespace/repo/dir",
		},
		"two paths, with separator": {
			elements: []string{"namespace/repo", "/dir"},
			expected: "namespace/repo/dir",
		},
		"two paths, both with separator": {
			elements: []string{"namespace/repo/", "/dir"},
			expected: "namespace/repo/dir",
		},
		"no paths": {
			elements: []string{},
			expected: "",
		},
	}

	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			actual := JoinPaths(tc.elements...)
			assert.Equal(t, actual, tc.expected)
		})
	}
}
