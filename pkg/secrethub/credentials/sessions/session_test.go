package sessions

import (
	"testing"
	"time"

	"github.com/secrethub/secrethub-go/internals/assert"
)

func TestExpireTimeNeedsRefresh(t *testing.T) {
	cases := map[string]struct {
		in       time.Time
		expected bool
	}{
		"not expired": {
			in:       time.Now().Add(time.Minute),
			expected: false,
		},
		"in margin": {
			in:       time.Now().Add(time.Second * 10),
			expected: true,
		},
		"past": {
			in:       time.Now().Add(-time.Second * 10),
			expected: true,
		},
	}

	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			assert.Equal(t, expireTime(tc.in).NeedsRefresh(), tc.expected)
		})
	}
}
