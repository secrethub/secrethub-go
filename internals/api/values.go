package api

// String converts a string into a *string.
func String(val string) *string {
	return &val
}

// StringValue safely converts a *string into a string.
func StringValue(val *string) string {
	if val != nil {
		return *val
	}
	return ""
}

// Int converts an int into a *int.
func Int(val int) *int {
	return &val
}

// IntValue safely converts a *int into an int.
func IntValue(val *int) int {
	if val != nil {
		return *val
	}
	return 0
}
