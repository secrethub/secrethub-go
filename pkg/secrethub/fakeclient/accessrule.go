// +build !production

package fakeclient

import "github.com/keylockerbv/secrethub-go/internals/api"

// AccessRuleService is a mock of the AccessRuleService interface.
type AccessRuleService struct {
	Deleter     *AccessRuleDeleter
	Getter      *AccessRuleGetter
	Lister      *AccessRuleLister
	LevelLister *AccessLevelLister
	Setter      AccessRuleSetter
}

// Delete implements the AccessRuleService interface Delete function.
func (s *AccessRuleService) Delete(path string, accountName string) error {
	return s.Deleter.Delete(path, accountName)
}

// Get implements the AccessRuleService interface Get function.
func (s *AccessRuleService) Get(path string, accountName string) (*api.AccessRule, error) {
	return s.Getter.Get(path, accountName)
}

// ListLevels implements the AccessRuleService interface ListLevels function.
func (s *AccessRuleService) ListLevels(path string) ([]*api.AccessLevel, error) {
	return s.LevelLister.ListLevels(path)
}

// List implements the AccessRuleService interface List function.
func (s *AccessRuleService) List(path string, depth int, ancestors bool) ([]*api.AccessRule, error) {
	return s.Lister.List(path, depth, ancestors)
}

// Set implements the AccessRuleService interface Set function.
func (s *AccessRuleService) Set(path string, permission api.Permission, accountName string) (*api.AccessRule, error) {
	return s.Setter.Set(path, permission, accountName)
}

// AccessRuleDeleter mocks the Delete function.
type AccessRuleDeleter struct {
	ArgPath        string
	ArgAccountName string
	Err            error
}

// Delete saves the arguments it was called with and returns the mocked response.
func (d *AccessRuleDeleter) Delete(path string, accountName string) error {
	d.ArgPath = path
	d.ArgAccountName = accountName
	return d.Err
}

// AccessRuleGetter mocks the Get function.
type AccessRuleGetter struct {
	ArgPath           string
	ArgAccountName    string
	ReturnsAccessRule *api.AccessRule
	Err               error
}

// Get saves the arguments it was called with and returns the mocked response.
func (g *AccessRuleGetter) Get(path string, accountName string) (*api.AccessRule, error) {
	g.ArgPath = path
	g.ArgAccountName = accountName
	return g.ReturnsAccessRule, g.Err
}

// AccessLevelLister mocks the ListLevels function.
type AccessLevelLister struct {
	ArgPath             string
	ReturnsAccessLevels []*api.AccessLevel
	Err                 error
}

// ListLevels saves the arguments it was called with and returns the mocked response.
func (l *AccessLevelLister) ListLevels(path string) ([]*api.AccessLevel, error) {
	l.ArgPath = path
	return l.ReturnsAccessLevels, l.Err
}

// AccessRuleSetter mocks the Set function.
type AccessRuleSetter struct {
	ArgPath           string
	ArgPermission     api.Permission
	ArgName           string
	ReturnsAccessRule *api.AccessRule
	Err               error
}

// Set saves the arguments it was called with and returns the mocked response.
func (s *AccessRuleSetter) Set(path string, permission api.Permission, name string) (*api.AccessRule, error) {
	s.ArgPath = path
	s.ArgPermission = permission
	s.ArgName = name
	return s.ReturnsAccessRule, s.Err
}

// AccessRuleLister mocks the List function.
type AccessRuleLister struct {
	ArgPath            string
	ArgDepth           int
	ArgAncestors       bool
	ReturnsAccessRules []*api.AccessRule
	Err                error
}

// List saves the arguments it was called with and returns the mocked response.
func (s *AccessRuleLister) List(path string, depth int, ancestors bool) ([]*api.AccessRule, error) {
	s.ArgPath = path
	s.ArgDepth = depth
	s.ArgAncestors = ancestors
	return s.ReturnsAccessRules, s.Err
}
