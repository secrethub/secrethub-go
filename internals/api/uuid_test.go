package api_test

import (
	"github.com/secrethub/secrethub-go/internals/api/uuid"
)

// UUID returns the pointer to the given uuid.UUID value.
func UUID(id uuid.UUID) *uuid.UUID {
	return &id
}
