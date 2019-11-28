// Package assert is a utility package that provides simple
// assertions to help with writing tests.
package assert

import (
	"testing"

	"github.com/kylelemons/godebug/pretty"
)

// Equal errors when actual and expected are not the same, printing out the diff.
func Equal(tb testing.TB, actual, expected interface{}) {
	tb.Helper()
	diff := diff(actual, expected)
	if diff != "" {
		tb.Errorf("unexpected diff (-actual +expected):\n%s", diff)
	}
}

// OK fails a test if the provided error is not nil.
func OK(tb testing.TB, err error) {
	tb.Helper()
	if err != nil {
		tb.Fatal(err)
	}
}

func diff(actual, expected interface{}) string {
	c := pretty.Config{
		Compact:           true,
		IncludeUnexported: true,
		Formatter:         pretty.DefaultFormatter,
	}
	return c.Compare(actual, expected)
}
