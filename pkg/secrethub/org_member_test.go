package secrethub

import (
	"encoding/json"
	"net/http"
	"testing"
	"time"

	"github.com/go-chi/chi"
	"github.com/keylockerbv/secrethub-go/pkg/api"
	"github.com/keylockerbv/secrethub-go/pkg/api/uuid"
	"github.com/keylockerbv/secrethub-go/pkg/testutil"
)

func TestGetOrgMember(t *testing.T) {
	accountID := uuid.New()
	member := &api.OrgMember{
		OrgID:         uuid.New(),
		AccountID:     accountID,
		Role:          "admin",
		CreatedAt:     time.Now().UTC(),
		LastChangedAt: time.Now().UTC(),
		User: &api.User{
			AccountID: accountID,
			Username:  "user1",
			FullName:  "User Uno",
		},
	}

	cases := map[string]struct {
		name       string
		username   string
		response   interface{}
		statusCode int
		err        error
		expected   *api.OrgMember
	}{
		"invalid username": {
			name:       "myorg",
			username:   "invalid user",
			response:   nil,
			statusCode: 0,
			err:        api.ErrInvalidUsername,
			expected:   nil,
		},
		"org not found": {
			name:       "myorg",
			username:   "user1",
			response:   api.ErrOrgNotFound,
			statusCode: api.ErrOrgNotFound.StatusCode,
			err:        api.ErrOrgNotFound,
			expected:   nil,
		},
		"member not found": {
			name:       "myorg",
			username:   "user1",
			response:   api.ErrOrgMemberNotFound,
			statusCode: api.ErrOrgMemberNotFound.StatusCode,
			err:        api.ErrOrgMemberNotFound,
			expected:   nil,
		},
		"success": {
			name:       "myorg",
			username:   "user1",
			response:   member,
			statusCode: http.StatusOK,
			err:        nil,
			expected:   member,
		},
	}

	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			router, opts, cleanup := setup()
			defer cleanup()

			client := NewClient(cred1, opts)

			router.Get("/orgs/{org_name}/members/{username}", func(w http.ResponseWriter, r *http.Request) {
				// Assert
				orgName := chi.URLParam(r, "org_name")
				username := chi.URLParam(r, "username")

				testutil.Compare(t, orgName, tc.name)
				testutil.Compare(t, username, tc.username)

				// Respond
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(tc.statusCode)
				_ = json.NewEncoder(w).Encode(tc.response)
			})

			actual, err := client.Orgs().Members().Get(tc.name, tc.username)

			testutil.Compare(t, err, tc.err)
			if tc.err == nil {
				testutil.Compare(t, actual, tc.expected)
			}
		})
	}
}

func TestListOrgMembers(t *testing.T) {
	accountID1 := uuid.New()
	accountID2 := uuid.New()
	orgID := uuid.New()

	members := []*api.OrgMember{
		{
			OrgID:         orgID,
			AccountID:     accountID1,
			Role:          "admin",
			CreatedAt:     time.Now().UTC(),
			LastChangedAt: time.Now().UTC(),
			User: &api.User{
				AccountID: accountID1,
				Username:  "user1",
				FullName:  "User Uno",
			},
		},
		{
			OrgID:         orgID,
			AccountID:     accountID2,
			Role:          "member",
			CreatedAt:     time.Now().UTC(),
			LastChangedAt: time.Now().UTC(),
			User: &api.User{
				AccountID: accountID2,
				Username:  "user2",
				FullName:  "User Duo",
			},
		},
	}

	cases := map[string]struct {
		name       string
		response   interface{}
		statusCode int
		err        error
		expected   []*api.OrgMember
	}{
		"zero": {
			name:       "myorg",
			response:   []*api.OrgMember{},
			statusCode: http.StatusOK,
			err:        nil,
			expected:   []*api.OrgMember{},
		},
		"one": {
			name:       "myorg",
			response:   members[:0],
			statusCode: http.StatusOK,
			err:        nil,
			expected:   members[:0],
		},
		"two": {
			name:       "myorg",
			response:   members,
			statusCode: http.StatusOK,
			err:        nil,
			expected:   members,
		},
		"not found": {
			name:       "myorg",
			response:   api.ErrOrgNotFound,
			statusCode: api.ErrOrgNotFound.StatusCode,
			err:        api.ErrOrgNotFound,
			expected:   nil,
		},
	}

	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			router, opts, cleanup := setup()
			defer cleanup()

			client := NewClient(cred1, opts)

			router.Get("/orgs/{org_name}/members", func(w http.ResponseWriter, r *http.Request) {
				orgName := chi.URLParam(r, "org_name")

				testutil.Compare(t, orgName, tc.name)

				// Respond
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(tc.statusCode)
				_ = json.NewEncoder(w).Encode(tc.response)
			})

			actual, err := client.Orgs().Members().List(tc.name)

			testutil.Compare(t, err, tc.err)
			if tc.err == nil {
				testutil.Compare(t, actual, tc.expected)
			}
		})
	}
}

func TestInviteOrg(t *testing.T) {
	expectedRequest := &api.CreateOrgMemberRequest{
		Username: "user1",
		Role:     "admin",
	}

	accountID := uuid.New()
	member := &api.OrgMember{
		OrgID:         uuid.New(),
		AccountID:     accountID,
		Role:          "admin",
		CreatedAt:     time.Now().UTC(),
		LastChangedAt: time.Now().UTC(),
		User: &api.User{
			AccountID: accountID,
			Username:  "user1",
			FullName:  "User Uno",
		},
	}

	cases := map[string]struct {
		name            string
		username        string
		role            string
		expectedRequest *api.CreateOrgMemberRequest
		response        interface{}
		statusCode      int
		err             error
		expected        *api.OrgMember
	}{
		"invalid username": {
			name:            "myorg",
			username:        "invalid user",
			role:            "admin",
			expectedRequest: nil,
			response:        nil,
			statusCode:      0,
			err:             api.ErrInvalidUsername,
			expected:        nil,
		},
		"invalid role": {
			name:            "myorg",
			username:        "user1",
			role:            "invalid role",
			expectedRequest: nil,
			response:        nil,
			statusCode:      0,
			err:             api.ErrInvalidOrgRole,
			expected:        nil,
		},
		"org not found": {
			name:            "myorg",
			username:        "user1",
			role:            "admin",
			expectedRequest: expectedRequest,
			response:        api.ErrOrgNotFound,
			statusCode:      api.ErrOrgNotFound.StatusCode,
			err:             api.ErrOrgNotFound,
			expected:        nil,
		},
		"user not found": {
			name:            "myorg",
			username:        "user1",
			role:            "admin",
			expectedRequest: expectedRequest,
			response:        api.ErrUserNotFound,
			statusCode:      api.ErrUserNotFound.StatusCode,
			err:             api.ErrUserNotFound,
			expected:        nil,
		},
		"member already exists": {
			name:            "myorg",
			username:        "user1",
			role:            "admin",
			expectedRequest: expectedRequest,
			response:        api.ErrOrgMemberAlreadyExists,
			statusCode:      api.ErrOrgMemberAlreadyExists.StatusCode,
			err:             api.ErrOrgMemberAlreadyExists,
			expected:        nil,
		},
		"success": {
			name:            "myorg",
			username:        "user1",
			role:            "admin",
			expectedRequest: expectedRequest,
			response:        member,
			statusCode:      http.StatusCreated,
			err:             nil,
			expected:        member,
		},
	}

	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			router, opts, cleanup := setup()
			defer cleanup()

			client := NewClient(cred1, opts)

			router.Post("/orgs/{org_name}/members", func(w http.ResponseWriter, r *http.Request) {
				// Assert
				orgName := chi.URLParam(r, "org_name")
				testutil.Compare(t, orgName, tc.name)

				req := new(api.CreateOrgMemberRequest)
				err := json.NewDecoder(r.Body).Decode(&req)
				testutil.OK(t, err)

				testutil.OK(t, req.Validate())

				testutil.Compare(t, req, tc.expectedRequest)

				// Respond
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(tc.statusCode)
				_ = json.NewEncoder(w).Encode(tc.response)
			})

			actual, err := client.Orgs().Members().Invite(tc.name, tc.username, tc.role)

			testutil.Compare(t, err, tc.err)
			if tc.err == nil {
				testutil.Compare(t, actual, tc.expected)
			}
		})
	}
}

func TestUpdateOrgMember(t *testing.T) {
	expectedRequest := &api.UpdateOrgMemberRequest{
		Role: "admin",
	}

	accountID := uuid.New()
	member := &api.OrgMember{
		OrgID:         uuid.New(),
		AccountID:     accountID,
		Role:          "admin",
		CreatedAt:     time.Now().UTC(),
		LastChangedAt: time.Now().UTC(),
		User: &api.User{
			AccountID: accountID,
			Username:  "user1",
			FullName:  "User Uno",
		},
	}

	cases := map[string]struct {
		name            string
		username        string
		role            string
		expectedRequest *api.UpdateOrgMemberRequest
		response        interface{}
		statusCode      int
		err             error
		expected        *api.OrgMember
	}{
		"invalid username": {
			name:            "myorg",
			username:        "invalid user",
			role:            "admin",
			expectedRequest: nil,
			response:        nil,
			statusCode:      0,
			err:             api.ErrInvalidUsername,
			expected:        nil,
		},
		"invalid role": {
			name:            "myorg",
			username:        "user1",
			role:            "invalid role",
			expectedRequest: nil,
			response:        nil,
			statusCode:      0,
			err:             api.ErrInvalidOrgRole,
			expected:        nil,
		},
		"org not found": {
			name:            "myorg",
			username:        "user1",
			role:            "admin",
			expectedRequest: expectedRequest,
			response:        api.ErrOrgNotFound,
			statusCode:      api.ErrOrgNotFound.StatusCode,
			err:             api.ErrOrgNotFound,
			expected:        nil,
		},
		"user not found": {
			name:            "myorg",
			username:        "user1",
			role:            "admin",
			expectedRequest: expectedRequest,
			response:        api.ErrUserNotFound,
			statusCode:      api.ErrUserNotFound.StatusCode,
			err:             api.ErrUserNotFound,
			expected:        nil,
		},
		"member already exists": {
			name:            "myorg",
			username:        "user1",
			role:            "admin",
			expectedRequest: expectedRequest,
			response:        api.ErrOrgMemberAlreadyExists,
			statusCode:      api.ErrOrgMemberAlreadyExists.StatusCode,
			err:             api.ErrOrgMemberAlreadyExists,
			expected:        nil,
		},
		"success": {
			name:            "myorg",
			username:        "user1",
			role:            "admin",
			expectedRequest: expectedRequest,
			response:        member,
			statusCode:      http.StatusOK,
			err:             nil,
			expected:        member,
		},
	}

	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			router, opts, cleanup := setup()
			defer cleanup()

			client := NewClient(cred1, opts)

			router.Post("/orgs/{org_name}/members/{username}", func(w http.ResponseWriter, r *http.Request) {
				// Assert
				orgName := chi.URLParam(r, "org_name")
				testutil.Compare(t, orgName, tc.name)

				username := chi.URLParam(r, "username")
				testutil.Compare(t, username, tc.username)

				req := new(api.UpdateOrgMemberRequest)
				err := json.NewDecoder(r.Body).Decode(&req)
				testutil.OK(t, err)

				testutil.OK(t, req.Validate())

				testutil.Compare(t, req, tc.expectedRequest)

				// Respond
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(tc.statusCode)
				_ = json.NewEncoder(w).Encode(tc.response)
			})

			actual, err := client.Orgs().Members().Update(tc.name, tc.username, tc.role)

			testutil.Compare(t, err, tc.err)
			if tc.err == nil {
				testutil.Compare(t, actual, tc.expected)
			}
		})
	}
}
