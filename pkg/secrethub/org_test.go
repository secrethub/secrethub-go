package secrethub

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/go-chi/chi"
	"github.com/secrethub/secrethub-go/internals/api"
	"github.com/secrethub/secrethub-go/internals/api/uuid"
	"github.com/secrethub/secrethub-go/internals/assert"
)

func TestCreateOrg(t *testing.T) {
	// Arrange
	router, opts, cleanup := setup()
	defer cleanup()

	client := Must(NewClient(opts...))

	name := "myorg"
	descr := "My very own organization"

	expectedRequest := &api.CreateOrgRequest{
		Name:        name,
		Description: descr,
	}

	orgID := uuid.New()
	accountID := uuid.New()

	now := time.Now().UTC()
	expectedResponse := &api.Org{
		OrgID:       uuid.New(),
		Name:        name,
		Description: descr,
		CreatedAt:   now,
		Members: []*api.OrgMember{
			{
				OrgID:         orgID,
				AccountID:     accountID,
				Role:          "admin",
				CreatedAt:     now,
				LastChangedAt: now,
			},
		},
	}

	router.Post("/orgs", func(w http.ResponseWriter, r *http.Request) {
		// Assert
		req := new(api.CreateOrgRequest)
		err := json.NewDecoder(r.Body).Decode(&req)
		assert.OK(t, err)

		assert.OK(t, req.Validate())

		assert.Equal(t, req, expectedRequest)

		// Respond
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(expectedResponse)
	})

	// Act
	resp, err := client.Orgs().Create(name, descr)

	// Assert
	assert.OK(t, err)
	assert.Equal(t, resp, expectedResponse)
}

func TestCreateOrg_InvalidArgs(t *testing.T) {

	cases := map[string]struct {
		name  string
		descr string
		err   error
	}{
		"invalid org name": {
			name:  "invalid org name",
			descr: "some description",
			err:   api.ErrInvalidOrgName,
		},
		"invalid descr": {
			name:  "myorg",
			descr: strings.Repeat("a", 300),
			err:   api.ErrInvalidDescription,
		},
	}

	_, opts, cleanup := setup()
	defer cleanup()

	client := Must(NewClient(opts...))

	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			_, err := client.Orgs().Create(tc.name, tc.descr)

			assert.Equal(t, err, tc.err)
		})
	}
}

func TestGetOrg(t *testing.T) {
	org := &api.Org{
		OrgID:       uuid.New(),
		Name:        "myorg",
		Description: "My very own organization",
		CreatedAt:   time.Now().UTC(),
		Members:     []*api.OrgMember{},
	}

	cases := map[string]struct {
		name       string
		response   interface{}
		statusCode int
		err        error
		expected   *api.Org
	}{
		"invalid org name": {
			name:       "invalid org name",
			response:   nil,
			statusCode: http.StatusBadRequest,
			err:        api.ErrInvalidOrgName,
			expected:   nil,
		},
		"not found": {
			name:       "myorg",
			response:   api.ErrOrgNotFound,
			statusCode: api.ErrOrgNotFound.StatusCode,
			err:        api.ErrOrgNotFound,
			expected:   nil,
		},
		"success": {
			name:       "myorg",
			response:   org,
			statusCode: http.StatusOK,
			err:        nil,
			expected:   org,
		},
	}

	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			router, opts, cleanup := setup()
			defer cleanup()

			client := Must(NewClient(opts...))

			router.Get("/orgs/{org_name}", func(w http.ResponseWriter, r *http.Request) {
				// Assert
				orgName := chi.URLParam(r, "org_name")

				assert.Equal(t, orgName, tc.name)

				// Respond
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(tc.statusCode)
				_ = json.NewEncoder(w).Encode(tc.response)
			})

			actual, err := client.Orgs().Get(tc.name)

			assert.Equal(t, err, tc.err)
			if tc.err == nil {
				assert.Equal(t, actual, tc.expected)
			}
		})
	}
}

func TestListMyOrgs(t *testing.T) {
	orgs := []*api.Org{
		{
			OrgID:       uuid.New(),
			Name:        "myorg1",
			Description: "My first organization",
			CreatedAt:   time.Now().UTC(),
			Members:     []*api.OrgMember{},
		},
		{
			OrgID:       uuid.New(),
			Name:        "myorg2",
			Description: "My second organization",
			CreatedAt:   time.Now().UTC(),
			Members:     []*api.OrgMember{},
		},
	}

	cases := map[string]struct {
		response   interface{}
		statusCode int
		err        error
		expected   []*api.Org
	}{
		"zero": {
			response:   []*api.Org{},
			statusCode: http.StatusOK,
			err:        nil,
			expected:   []*api.Org{},
		},
		"one": {
			response:   orgs[:0],
			statusCode: http.StatusOK,
			err:        nil,
			expected:   orgs[:0],
		},
		"two": {
			response:   orgs,
			statusCode: http.StatusOK,
			err:        nil,
			expected:   orgs,
		},
		"forbidden": {
			response:   api.ErrForbidden,
			statusCode: api.ErrForbidden.StatusCode,
			err:        api.ErrForbidden,
			expected:   nil,
		},
	}

	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			router, opts, cleanup := setup()
			defer cleanup()

			client := Must(NewClient(opts...))

			router.Get("/orgs", func(w http.ResponseWriter, r *http.Request) {
				// Respond
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(tc.statusCode)
				_ = json.NewEncoder(w).Encode(tc.response)
			})

			actual, err := client.Orgs().ListMine()

			assert.Equal(t, err, tc.err)
			if tc.err == nil {
				assert.Equal(t, actual, tc.expected)
			}
		})
	}
}

func TestDeleteOrg(t *testing.T) {
	cases := map[string]struct {
		name       string
		response   interface{}
		statusCode int
		err        error
	}{
		"invalid org name": {
			name:       "invalid org name",
			response:   nil,
			statusCode: http.StatusBadRequest,
			err:        api.ErrInvalidOrgName,
		},
		"not found": {
			name:       "myorg",
			response:   api.ErrOrgNotFound,
			statusCode: api.ErrOrgNotFound.StatusCode,
			err:        api.ErrOrgNotFound,
		},
		"forbidden": {
			name:       "myorg",
			response:   api.ErrForbidden,
			statusCode: api.ErrForbidden.StatusCode,
			err:        api.ErrForbidden,
		},
		"success": {
			name:       "myorg",
			response:   nil,
			statusCode: http.StatusOK,
			err:        nil,
		},
	}

	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			router, opts, cleanup := setup()
			defer cleanup()

			client := Must(NewClient(opts...))

			router.Delete("/orgs/{org_name}", func(w http.ResponseWriter, r *http.Request) {
				// Assert
				orgName := chi.URLParam(r, "org_name")

				assert.Equal(t, orgName, tc.name)

				// Respond
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(tc.statusCode)
				_ = json.NewEncoder(w).Encode(tc.response)
			})

			err := client.Orgs().Delete(tc.name)
			assert.Equal(t, err, tc.err)
		})
	}
}
