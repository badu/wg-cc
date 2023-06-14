package login

import (
	"database/sql"

	"golang.org/x/crypto/bcrypt"
)

type internalData struct {
	accessToken, tokenType string
	expiresIn              int64
}

type RepoMock struct {
	clientID string
	jwtsMap  map[string]internalData
	keysMap  map[string][]byte
}

func NewMock(clientID string) RepoMock {
	return RepoMock{clientID: clientID, jwtsMap: make(map[string]internalData), keysMap: make(map[string][]byte)}
}

func (r *RepoMock) GetClientSecretAndPrivateKeyByClientID(clientID string) (string, []byte, error) {
	hashedSecret, _ := bcrypt.GenerateFromPassword([]byte(r.clientID), bcrypt.DefaultCost)
	key, has := r.keysMap[clientID]
	if !has {
		return string(hashedSecret), nil, sql.ErrNoRows
	}
	return string(hashedSecret), key, nil
}

func (r *RepoMock) InsertAudit(clientID, accessToken, tokenType string, expiresIn int64) error {
	r.jwtsMap[clientID] = internalData{
		accessToken: accessToken,
		tokenType:   tokenType,
		expiresIn:   expiresIn,
	}
	return nil
}

func (r *RepoMock) SavePrivateKey(keyName string, keyData []byte) error {
	r.keysMap[keyName] = keyData
	return nil
}

func (r *RepoMock) InsertClient(clientID string, clientSecret []byte, keyName string) error {
	return nil
}

func (r *RepoMock) GetSigningKeyFromAuditedToken(tokenString string) ([]byte, error) {
	return nil, nil
}

func (r *RepoMock) ListAllSigningKeys() ([]string, [][]byte, error) {
	return nil, nil, nil
}
