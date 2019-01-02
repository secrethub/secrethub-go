package api_test

import (
	"testing"

	"github.com/keylockerbv/secrethub-go/pkg/api"
)

func TestAccountName(t *testing.T) {

	tests := []struct {
		input     string
		isService bool
	}{
		{
			input:     "user1",
			isService: false,
		},
		{
			input:     "USER1",
			isService: false,
		},
		{
			input:     "user-s-1",
			isService: false,
		},
		{
			input:     "s-service1",
			isService: true,
		},
		{
			input:     "S-SERVICE1",
			isService: true,
		},
		{
			input:     "s--service1",
			isService: true,
		},
	}

	for _, test := range tests {
		an := api.AccountName(test.input)

		if an.IsService() != test.isService {
			t.Errorf("unexpected output AccountName(\"%s\").Service(): %v (actual) != %v (expected)", test.input, an.IsService(), test.isService)
		}
		if an.IsUser() != !test.isService {
			t.Errorf("unexpected output AccountName(\"%s\").User(): %v (actual) != %v (expected)", test.input, an.IsUser(), !test.isService)
		}
	}

}
