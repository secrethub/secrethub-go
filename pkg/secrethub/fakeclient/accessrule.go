// +build !production

package fakeclient

import "github.com/keylockerbv/secrethub-go/pkg/api"

// AccessRuleService is a mock of the AccessRuleService interface.
type AccessRuleService struct {
	Deleter        *AccessRuleDeleter
	Getter         *AccessRuleGetter
	Lister         *AccessRuleLister
	LevelLister    *AccessLevelLister
	WithPathLister AccessRuleWithPathLister
	Setter         AccessRuleSetter
}

// Delete implements the AccessRuleService interface Delete function.
func (s *AccessRuleService) Delete(path api.DirPath, accountName api.AccountName) error {
	return s.Deleter.Delete(path, accountName)
}

// Get implements the AccessRuleService interface Get function.
func (s *AccessRuleService) Get(path api.DirPath, accountName api.AccountName) (*api.AccessRule, error) {
	return s.Getter.Get(path, accountName)
}

// ListLevels implements the AccessRuleService interface ListLevels function.
func (s *AccessRuleService) ListLevels(path api.DirPath) ([]*api.AccessLevel, error) {
	return s.LevelLister.ListLevels(path)
}

// List implements the AccessRuleService interface List function.
func (s *AccessRuleService) List(path api.DirPath, depth int, ancestors bool) ([]*api.AccessRule, error) {
	return s.Lister.List(path, depth, ancestors)
}

// ListWithPaths implements the AccessRuleService interface ListWithPaths function.
func (s *AccessRuleService) ListWithPaths(path api.DirPath, depth int, ancestors bool) (map[api.DirPath][]*api.AccessRule, error) {
	return s.WithPathLister.ListWithPaths(path, depth, ancestors)
}

// Set implements the AccessRuleService interface Set function.
func (s *AccessRuleService) Set(path api.BlindNamePath, permission api.Permission, name api.AccountName) (*api.AccessRule, error) {
	return s.Setter.Set(path, permission, name)
}

// AccessRuleDeleter mocks the Delete function.
type AccessRuleDeleter struct {
	ArgPath        api.DirPath
	ArgAccountName api.AccountName
	Err            error
}

// Delete saves the arguments it was called with and returns the mocked response.
func (d *AccessRuleDeleter) Delete(path api.DirPath, accountName api.AccountName) error {
	d.ArgPath = path
	d.ArgAccountName = accountName
	return d.Err
}

// AccessRuleGetter mocks the Get function.
type AccessRuleGetter struct {
	ArgPath           api.DirPath
	ArgAccountName    api.AccountName
	ReturnsAccessRule *api.AccessRule
	Err               error
}

// Get saves the arguments it was called with and returns the mocked response.
func (g *AccessRuleGetter) Get(path api.DirPath, accountName api.AccountName) (*api.AccessRule, error) {
	g.ArgPath = path
	g.ArgAccountName = accountName
	return g.ReturnsAccessRule, g.Err
}

// AccessLevelLister mocks the ListLevels function.
type AccessLevelLister struct {
	ArgPath             api.DirPath
	ReturnsAccessLevels []*api.AccessLevel
	Err                 error
}

// ListLevels saves the arguments it was called with and returns the mocked response.
func (l *AccessLevelLister) ListLevels(path api.DirPath) ([]*api.AccessLevel, error) {
	l.ArgPath = path
	return l.ReturnsAccessLevels, l.Err
}

// AccessRuleSetter mocks the Set function.
type AccessRuleSetter struct {
	ArgPath           api.BlindNamePath
	ArgPermission     api.Permission
	ArgName           api.AccountName
	ReturnsAccessRule *api.AccessRule
	Err               error
}

// Set saves the arguments it was called with and returns the mocked response.
func (s *AccessRuleSetter) Set(path api.BlindNamePath, permission api.Permission, name api.AccountName) (*api.AccessRule, error) {
	s.ArgPath = path
	s.ArgPermission = permission
	s.ArgName = name
	return s.ReturnsAccessRule, s.Err
}

// AccessRuleLister mocks the List function.
type AccessRuleLister struct {
	ArgPath            api.DirPath
	ArgDepth           int
	ArgAncestors       bool
	ReturnsAccessRules []*api.AccessRule
	Err                error
}

// List saves the arguments it was called with and returns the mocked response.
func (s *AccessRuleLister) List(path api.DirPath, depth int, ancestors bool) ([]*api.AccessRule, error) {
	s.ArgPath = path
	s.ArgDepth = depth
	s.ArgAncestors = ancestors
	return s.ReturnsAccessRules, s.Err
}

// AccessRuleWithPathLister mocks the ListWithPaths function.
type AccessRuleWithPathLister struct {
	ArgPath              api.DirPath
	ArgDepth             int
	ArgAncestors         bool
	ReturnsAccessRuleMap map[api.DirPath][]*api.AccessRule
	Err                  error
}

// ListWithPaths saves the arguments it was called with and returns the mocked response.
func (s *AccessRuleWithPathLister) ListWithPaths(path api.DirPath, depth int, ancestors bool) (map[api.DirPath][]*api.AccessRule, error) {
	s.ArgPath = path
	s.ArgDepth = depth
	s.ArgAncestors = ancestors
	return s.ReturnsAccessRuleMap, s.Err
}
