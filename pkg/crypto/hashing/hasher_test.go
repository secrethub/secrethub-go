package hashing_test

import (
	"testing"

	"github.com/keylockerbv/secrethub-go/pkg/crypto/hashing"
)

func TestEqual_Same(t *testing.T) {
	// Arrange
	data := []byte("test_data_string")
	a := hashing.Sum(data)
	b := hashing.Sum(data)

	// Act & Assert
	if !hashing.Equal(a, b) {
		t.Errorf("unexpected sum: %v != %v", a, b)
	}

	if !a.Equal(b) {
		t.Errorf("unexpected sum: %v != %v", a, b)
	}
}

func TestEqual_Diff(t *testing.T) {
	// Arrange
	data1 := []byte("ẗest_data_string")
	data2 := []byte("ẗest_data_string_2")

	// Act & Assert
	hash1 := hashing.Sum(data1)
	hash2 := hashing.Sum(data2)
	if hashing.Equal(hash1, hash2) {
		t.Errorf("unexpected sum: %v == %v", hash1, hash2)
	}
}

func TestEqual_EmptySame(t *testing.T) {
	// Arrange
	data1 := []byte{}

	// Act & Assert
	hash1 := hashing.Sum(data1)
	hash2 := hashing.EmptyHash
	if !hashing.Equal(hash1, hash2) {
		t.Errorf("unexpected sum: %v != %v", hash1, hash2)
	}
}

func TestEqual_EmptyDiff(t *testing.T) {
	// Arrange
	data1 := []byte("test_data_string")

	// Assert & Act
	hash1 := hashing.Sum(data1)
	hash2 := hashing.EmptyHash

	if hashing.Equal(hash1, hash2) {
		t.Errorf("unexpected sum: %v == %v", hash1, hash2)
	}
}
