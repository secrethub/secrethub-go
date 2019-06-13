package api

func String(val string) *string {
	return &val
}

func StringValue(val *string) string {
	if val != nil {
		return *val
	}
	return ""
}

func Int(val int) *int {
	return &val
}

func IntValue(val *int) int {
	if val != nil {
		return *val
	}
	return 0
}
