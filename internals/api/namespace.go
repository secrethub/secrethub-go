package api

// NamespaceDetails defines a user or organization namespace.
// TODO: rename this to Namespace currently claimed in paths.go
type NamespaceDetails struct {
	Name        string `json:"name"`
	MemberCount int    `json:"member_count"`
	RepoCount   int    `json:"repo_count"`
	SecretCount int    `json:"secret_count"`
}
