package login

import (
	"crypto/rsa"
	"errors"
	"log"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/crypto/bcrypt"
)

const (
	RS384 = "RS384"
	RS512 = "RS512"
	RS256 = "RS256"
)

type Repository interface {
	Verify(clientID, clientSecret string) (string, error)
	Insert(clientID, accessToken, tokenType string, expiresIn int64) error
}

type SvcImpl struct {
	repo            Repository
	secretKey       *rsa.PrivateKey
	tokenExpiration time.Duration
	signingMethod   *jwt.SigningMethodRSA
}

func NewService(
	repo Repository,
	secret *rsa.PrivateKey,
	expiration time.Duration,
	signMethod string,
) (*SvcImpl, error) {
	result := SvcImpl{
		repo:            repo,
		secretKey:       secret,
		tokenExpiration: expiration,
	}

	switch signMethod {
	case RS384:
		result.signingMethod = jwt.SigningMethodRS384
	case RS512:
		result.signingMethod = jwt.SigningMethodRS512
	case RS256:
		result.signingMethod = jwt.SigningMethodRS256
	default:
		return nil, errors.New("unknown signing method")
	}

	return &result, nil
}

func (s *SvcImpl) Sign(clientID, clientSecret string) (*TokenResponse, error) {
	hashedSecret, err := s.repo.Verify(clientID, clientSecret)
	if err != nil {
		return nil, err
	}

	err = bcrypt.CompareHashAndPassword([]byte(hashedSecret), []byte(clientSecret))
	if err != nil {
		return nil, err
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

	result := TokenResponse{
		AccessToken: tokenString,
		TokenType:   "Bearer",
		ExpiresIn:   int64(s.tokenExpiration.Seconds()),
	}

	if err := s.repo.Insert(clientID, result.AccessToken, result.TokenType, result.ExpiresIn); err != nil {
		log.Printf("non fatal error inserting key into database : %#v", err)
	}

	// the token response
	return &result, nil
}
