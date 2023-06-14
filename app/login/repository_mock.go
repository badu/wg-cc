package login

import (
	"golang.org/x/crypto/bcrypt"
)

type internalData struct {
	accessToken, tokenType string
	expiresIn              int64
}

type RepoMock struct {
	clientFound string
	keysMap     map[string]internalData
}

func NewMock(clientFound string) RepoMock {
	return RepoMock{clientFound: clientFound, keysMap: make(map[string]internalData)}
}

func (r *RepoMock) Verify(clientID string) (string, error) {
	hashedSecret, _ := bcrypt.GenerateFromPassword([]byte(r.clientFound), bcrypt.DefaultCost)
	return string(hashedSecret), nil
}

func (r *RepoMock) Insert(clientID, accessToken, tokenType string, expiresIn int64) error {
	r.keysMap[clientID] = internalData{
		accessToken: accessToken,
		tokenType:   tokenType,
		expiresIn:   expiresIn,
	}
	return nil
}
