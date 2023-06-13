package login

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
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
	Verify(clientID string) (string, error)
	Insert(clientID, accessToken, tokenType string, expiresIn int64) error
}

type SvcImpl struct {
	repo              Repository
	secretKey         *rsa.PrivateKey
	tokenExpiration   time.Duration
	signingMethod     *jwt.SigningMethodRSA
	signingMethodName string
}

func NewService(
	repo Repository,
	secret *rsa.PrivateKey,
	expiration time.Duration,
	signMethod string,
) SvcImpl {
	result := SvcImpl{
		repo:              repo,
		secretKey:         secret,
		tokenExpiration:   expiration,
		signingMethodName: signMethod,
	}

	// validation happens in the main file of the server, so we don't get surprises here
	switch signMethod {
	case RS384:
		result.signingMethod = jwt.SigningMethodRS384
	case RS512:
		result.signingMethod = jwt.SigningMethodRS512
	case RS256:
		result.signingMethod = jwt.SigningMethodRS256
	}

	return result
}

func (s *SvcImpl) Sign(clientID, clientSecret string) (*TokenResponse, error) {
	hashedSecret, err := s.repo.Verify(clientID)
	if err != nil {
		return nil, err
	}

	err = bcrypt.CompareHashAndPassword([]byte(hashedSecret), []byte(clientSecret))
	if err != nil {
		return nil, err
	}
	now := time.Now()

	// generate the access token
	token := jwt.New(s.signingMethod)
	claims := token.Claims.(jwt.MapClaims)
	claims["sub"] = clientID
	claims["exp"] = now.Add(s.tokenExpiration).Unix() // The expiration time after which the token must be disregarded.
	claims["iat"] = now.Unix()                        // The time at which the token was issued.
	claims["nbf"] = now.Unix()                        // The time before which the token must be disregarded.

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

func (s *SvcImpl) DecodeJWTToken(tokenString string) (*jwt.Token, error) {
	token, err := jwt.Parse(tokenString, func(jwtToken *jwt.Token) (interface{}, error) {
		if _, ok := jwtToken.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, fmt.Errorf("unexpected method: %s", jwtToken.Header["alg"])
		}
		return s.secretKey.Public(), nil
	})
	return token, err
}

func (s *SvcImpl) ListKeys() KeysResponse {
	result := KeysResponse{Keys: make([]SignKey, 0, 1)}

	// Marshal the public key to PKIX format
	publicKeyBytes, err := x509.MarshalPKIXPublicKey(s.secretKey.Public())
	if err != nil {
		log.Fatal(err)
	}

	// Create a PEM block for the public key
	publicKeyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: publicKeyBytes,
	})

	result.Keys = append(result.Keys, SignKey{
		Key:       string(publicKeyPEM),
		KeyID:     "key1",
		Algorithm: s.signingMethodName,
	})
	return result
}
