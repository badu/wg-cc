package login

import (
	"errors"
)

var NotFoundError = errors.New("client not found")

type RepoImpl struct {
}

func NewRepository() RepoImpl {
	return RepoImpl{}
}

func (r *RepoImpl) Verify(clientID, clientSecret string) (bool, error) {
	return false, nil
}
