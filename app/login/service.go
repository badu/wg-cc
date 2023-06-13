package login

import (
	"errors"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

const (
	HS384 = "HS384"
	HS512 = "HS512"
	HS256 = "HS256"
)

type Repository interface {
	Verify(clientID, clientSecret string) (bool, error)
}

type SvcImpl struct {
	repo            Repository
	secretKey       []byte
	tokenExpiration time.Duration
	signingMethod   *jwt.SigningMethodHMAC
}

func NewService(
	repo Repository,
	secret []byte,
	expiration time.Duration,
	signMethod string,
) (*SvcImpl, error) {
	result := SvcImpl{
		repo:            repo,
		secretKey:       secret,
		tokenExpiration: expiration,
	}

	switch signMethod {
	case HS384:
		result.signingMethod = jwt.SigningMethodHS384
	case HS512:
		result.signingMethod = jwt.SigningMethodHS512
	case HS256:
		result.signingMethod = jwt.SigningMethodHS256
	default:
		return nil, errors.New("unknown signing method")
	}

	return &result, nil
}

func (s *SvcImpl) Sign(clientID, clientSecret string) (*TokenResponse, error) {
	has, err := s.repo.Verify(clientID, clientSecret)
	if err != nil {
		return nil, err
	}

	if !has {
		return nil, NotFoundError
	}

	// generate the access token
	token := jwt.New(s.signingMethod)
	claims := token.Claims.(jwt.MapClaims)
	claims["sub"] = clientID
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
