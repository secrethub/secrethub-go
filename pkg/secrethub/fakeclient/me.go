package fakeclient

import (
	"github.com/secrethub/secrethub-go/internals/api"
	"github.com/secrethub/secrethub-go/pkg/secrethub"
)

type MeService struct {
	GetUserFunc func() (*api.User, error)
	SendVerificationEmailFunc func() error
	ListReposFunc func() ([]*api.Repo, error)
	RepoIteratorFunc func(_ *secrethub.RepoIteratorParams) secrethub.RepoIterator
	secrethub.MeService
}

func (m *MeService) GetUser() (*api.User, error) {
	return m.GetUserFunc()
}

func (m *MeService) SendVerificationEmail() error {
	return m.SendVerificationEmailFunc()
}

func (m *MeService) ListRepos() ([]*api.Repo, error) {
	return m.ListReposFunc()
}

func (m *MeService) RepoIterator(repoIteratorParams *secrethub.RepoIteratorParams) secrethub.RepoIterator {
	return m.RepoIteratorFunc(repoIteratorParams)
}
