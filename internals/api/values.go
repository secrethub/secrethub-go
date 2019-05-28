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
