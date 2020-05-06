package secrethub

import (
	"os"
	"regexp"
	"testing"

	"github.com/secrethub/secrethub-go/internals/assert"
)

func TestClient_userAgent(t *testing.T) {
	cases := map[string]struct {
		appInfo       []*AppInfo
		envAppName    string
		envAppVersion string
		expected      string
		err           error
	}{
		"default": {},
		"multiple app info layers": {
			appInfo: []*AppInfo{
				{Name: "secrethub-xgo", Version: "0.1.0"},
				{Name: "secrethub-java", Version: "0.2.0"},
			},
			expected: "secrethub-xgo/0.1.0 secrethub-java/0.2.0",
		},
		"no version number": {
			appInfo: []*AppInfo{
				{Name: "terraform-provider-secrethub"},
			},
			expected: "terraform-provider-secrethub",
		},
		"top level app info from environment": {
			appInfo: []*AppInfo{
				{Name: "secrethub-cli", Version: "0.37.0"},
			},
			envAppName:    "secrethub-circleci-orb",
			envAppVersion: "1.0.0",
			expected:      "secrethub-cli/0.37.0 secrethub-circleci-orb/1.0.0",
		},
		"invalid app name": {
			appInfo: []*AppInfo{
				{Name: "illegal-name*%!@", Version: "0.1.0"},
			},
			err: ErrInvalidAppInfoName,
		},
		"ignore faulty environment variable": {
			appInfo: []*AppInfo{
				{Name: "secrethub-cli", Version: "0.37.0"},
			},
			envAppName: "illegal-name*%!@",
			expected:   "secrethub-cli/0.37.0",
		},
	}

	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			os.Setenv("SECRETHUB_APP_INFO_NAME", tc.envAppName)
			os.Setenv("SECRETHUB_APP_INFO_VERSION", tc.envAppVersion)

			var opts []ClientOption
			for _, info := range tc.appInfo {
				opts = append(opts, WithAppInfo(info))
			}
			client, err := NewClient(opts...)
			assert.Equal(t, err, tc.err)
			if err != nil {
				return
			}

			userAgent := client.userAgent()
			pattern := tc.expected + " \\(.*\\)"
			matched, err := regexp.MatchString(pattern, userAgent)
			assert.OK(t, err)
			if !matched {
				t.Errorf("user agent '%s' doesn't match pattern '%s'", userAgent, pattern)
			}
		})
	}
}
