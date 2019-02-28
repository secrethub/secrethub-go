// Package secretpath implements utility functions for manipulating paths
// compatible with SecretHub, e.g. namespaces, repositories, directories,
// secrets and versions.
package secretpath

import (
	"strconv"
	"strings"

	"bitbucket.org/zombiezen/cardcpx/natsort"
)

const (
	elemSepByte    = '/'
	elemSep        = string(elemSepByte)
	versionSepByte = ':'
	versionSep     = string(versionSepByte)
	latestSuffix   = ":latest"
)

// Join joins any number of elements into a path, adding a separator
// if necessary. Empty string elements are ignored.
func Join(elements ...string) string {
	switch len(elements) {
	case 0:
		return ""
	case 1:
		return strings.Trim(elements[0], elemSep)
	}

	result := ""
	for _, e := range elements {
		e = strings.Trim(e, elemSep)
		if len(e) != 0 && len(result) == 0 {
			result += e
		} else if len(e) != 0 {
			result += elemSep + e
		}
	}

	return result
}

// HasVersion returns true when a version suffix is specified in the path.
func HasVersion(path string) bool {
	return hasVersion(path)
}

// hasVersion returns true when a version suffix is specified in the path.
func hasVersion(path string) bool {
	i := strings.LastIndex(path, versionSep)
	return i >= 0 && i < len(path)-1
}

// Version returns the version number suffix of a path, returning -1
// when :latest or negative version numbers are given. If no version
// suffix is set or it cannot be parsed to an integer, 0 is returned.
func Version(path string) int {
	if !hasVersion(path) {
		return 0
	}

	if strings.HasSuffix(path, latestSuffix) {
		return -1
	}

	i := strings.LastIndex(path, versionSep)
	version, err := strconv.Atoi(path[i+1:])
	if err != nil {
		return 0
	}

	if version < 0 {
		return -1
	}

	return version
}

// AddVersion adds a version suffix to a given path, removing trailing
// separators if necessary. If the path already contains a version suffix,
// it is replaced by the given version number. Negative version numbers
// are converted to ":latest".
func AddVersion(path string, version int) string {
	path = strings.Trim(path, elemSep)

	suffix := latestSuffix
	if version > 0 {
		suffix = versionSep + strconv.Itoa(version)
	}

	i := strings.LastIndex(path, versionSep)
	if i < 0 {
		return path + suffix
	}

	return path[:i] + suffix
}

// Base returns the last element of a path. Trailing separators and version
// numbers are removed.
func Base(path string) string {
	path = strings.Trim(path, elemSep)

	for i := len(path) - 1; i >= 0; i-- {
		if path[i] == elemSepByte {
			return path[i+1:]
		}

		if path[i] == versionSepByte {
			path = path[:i]
		}
	}
	return path
}

// Parent returns all but the last element of a path, removing trailing separators.
// If a path contains only one element, it returns an empty string.
func Parent(path string) string {
	path = Clean(path)

	for i := len(path) - 1; i >= 0; i-- {
		if path[i] == elemSepByte {
			return path[:i]
		}
	}

	return ""
}

// Repo returns the first two elements of a path, removing trailing separators.
// If a path contains less than two elements, it returns the empty string.
func Repo(path string) string {
	path = Clean(path)

	count := 0
	for i := 0; i < len(path); i++ {
		if path[i] == elemSepByte {
			count++
		}

		if count == 2 {
			return path[:i]
		}
	}

	if count == 1 {
		return path
	}
	return ""
}

// Namespace returns the first element of a path, removing trailing separators.
func Namespace(path string) string {
	path = strings.Trim(path, elemSep)
	if len(path) == 0 {
		return ""
	}

	for i := 0; i < len(path); i++ {
		if path[i] == elemSepByte {
			return path[:i]
		}
	}

	return path
}

// Clean returns the shortest path name equivalent to the given path
// by lexical processing. It removes trailing and multiple separator
// elements. Version suffixes are not removed.
func Clean(path string) string {
	if len(path) == 0 {
		return ""
	}

	out := []byte{}
	previous := false
	n := len(path)
	for i := 0; i < n; i++ {
		if path[i] == elemSepByte {
			// Skip consecutive separators
			if previous {
				continue
			}

			previous = true

			// Skip leading and trailing separators
			if i == 0 || i == n-1 {
				continue
			}
		} else {
			previous = false
		}
		out = append(out, path[i])
	}

	return string(out)
}

// Count returns the number of elements in a path, excluding the version suffix.
func Count(path string) int {
	path = Clean(path)

	if len(path) == 0 {
		return 0
	}

	return 1 + strings.Count(path, elemSep)
}

// NaturalSort implements the sort.Interface by natural sorting.
type NaturalSort []string

func (s NaturalSort) Len() int {
	return len(s)
}

func (s NaturalSort) Swap(i, j int) {
	s[i], s[j] = s[j], s[i]
}

func (s NaturalSort) Less(i, j int) bool {
	return natsort.Less(s[i], s[j])
}
