// Package uuid is a utility package to standardize and abstract away how UUIDs are generated and used.
package uuid

import gid "github.com/satori/go.uuid"

// UUID is a wrapper around go.uuid.UUID
type UUID struct {
	gid.UUID
}

// New generates a new UUID.
func New() *UUID {
	id := gid.NewV4()
	return &UUID{id}
}

// FromString reads a UUID from a string
func FromString(str string) (*UUID, error) {
	id, err := gid.FromString(str)
	if err != nil {
		return nil, err
	}
	return &UUID{id}, nil
}

// ToString converts UUID into string
func (u *UUID) ToString() string {
	return u.UUID.String()
}

// Equal returns true if both argument uuids contain the same value.
func Equal(a *UUID, b *UUID) bool {
	return gid.Equal(a.UUID, b.UUID)
}

// IsUUID returns true if argument is uuid.
func IsUUID(str string) bool {
	_, err := FromString(str)
	if err != nil {
		return false
	}

	return true
}
