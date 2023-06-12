package login

import (
	"time"

	"github.com/golang-jwt/jwt/v5"
)

type Repository interface {
}

type SvcImpl struct {
	repo            Repository
	secretKey       []byte
	tokenExpiration time.Duration
}

func NewService(repo Repository, secret []byte, expiration time.Duration) SvcImpl {
	return SvcImpl{repo: repo, secretKey: secret, tokenExpiration: expiration}
}

func (s *SvcImpl) Sign(clientID, clientSecret string) (*TokenResponse, error) {
	// TODO : validate client credentials here (sqlite database would do)

	// generate the access token
	token := jwt.New(jwt.SigningMethodHS256)
	claims := token.Claims.(jwt.MapClaims)
	claims["client_id"] = clientID
	claims["exp"] = time.Now().Add(s.tokenExpiration).Unix()

	// sign the token with the secret key
	tokenString, err := token.SignedString(s.secretKey)
	if err != nil {
		return nil, err
	}

	// the token response
	return &TokenResponse{
		AccessToken: tokenString,
		TokenType:   "Bearer",
		ExpiresIn:   int64(s.tokenExpiration),
	}, nil
}
