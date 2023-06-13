package login

import (
	"golang.org/x/crypto/bcrypt"
)

type RepoMock struct {
	clientFound string
}

func NewMock(clientFound string) RepoMock {
	return RepoMock{clientFound: clientFound}
}

func (r *RepoMock) Verify(clientID string) (string, error) {
	hashedSecret, _ := bcrypt.GenerateFromPassword([]byte(r.clientFound), bcrypt.DefaultCost)
	return string(hashedSecret), nil
}

func (r *RepoMock) Insert(clientID, accessToken, tokenType string, expiresIn int64) error {
	return nil
}
