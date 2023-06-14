package login

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"log"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"
)

const (
	RS384 = "RS384"
	RS512 = "RS512"
	RS256 = "RS256"
)

type Repository interface {
	GetClientSecretAndPrivateKeyByClientID(clientID string) (string, []byte, error)
	InsertAudit(clientID, accessToken, tokenType string, expiresIn int64) error
	SavePrivateKey(keyName string, keyData []byte) error
	InsertClient(clientID string, clientSecret []byte, keyName string) error
	GetSigningKeyFromAuditedToken(tokenString string) ([]byte, error)
	ListAllSigningKeys() ([]string, [][]byte, error)
}

type SvcImpl struct {
	repo              Repository
	tokenExpiration   time.Duration
	signingMethod     *jwt.SigningMethodRSA
	signingMethodName string
	totpKey           string
}

func NewService(
	repo Repository,
	expiration time.Duration,
	signMethod string,
	totpKey string,
) SvcImpl {
	result := SvcImpl{
		repo:              repo,
		tokenExpiration:   expiration,
		signingMethodName: signMethod,
		totpKey:           totpKey,
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
	hashedSecret, privateKeyPEM, err := s.repo.GetClientSecretAndPrivateKeyByClientID(clientID)
	if err != nil {
		return nil, err
	}

	// Decode the PEM block to obtain the private key
	privateKeyBlock, _ := pem.Decode(privateKeyPEM)
	if privateKeyBlock == nil {
		return nil, errors.New("failed to decode PEM block containing private key")
	}

	// Parse the DER encoded private key
	privateKey, err := x509.ParsePKCS1PrivateKey(privateKeyBlock.Bytes)
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
	// from 7519, the following claims
	claims := token.Claims.(jwt.MapClaims)
	// "sub" (Subject): Identifies the subject of the token, typically the user or entity associated with it.
	claims["sub"] = clientID
	// "iss" (Issuer): Identifies the issuer of the token.
	claims["iss"] = "http://localhost:8080"
	// "aud" (Audience): Specifies the intended audience for the token.
	claims["aud"] = "https://api.example.com"
	// "exp" (Expiration Time): Indicates the expiration time of the token.
	claims["exp"] = now.Add(s.tokenExpiration).Unix() // The expiration time after which the token must be disregarded.
	// "iat" (Issued At): Specifies the time at which the token was issued.
	claims["iat"] = now.Unix() // The time at which the token was issued.
	// "nbf" (Not Before): Defines the time before which the token should not be accepted.
	claims["nbf"] = now.Unix() // The time before which the token must be disregarded.
	// "jti" (JWT ID): Provides a unique identifier for the token.
	claims["jti"] = uuid.New().String()
	// extra something, let's say scope
	claims["scope"] = "read" // test scope, just to have something

	tokenString, err := token.SignedString(privateKey)
	if err != nil {
		return nil, err
	}

	result := TokenResponse{
		AccessToken: tokenString,
		TokenType:   "Bearer",
		ExpiresIn:   int64(s.tokenExpiration.Seconds()),
	}

	if err := s.repo.InsertAudit(clientID, result.AccessToken, result.TokenType, result.ExpiresIn); err != nil {
		log.Printf("non fatal error inserting key into database : %#v", err)
	}

	// the token response
	return &result, nil
}

func (s *SvcImpl) DecodeJWTToken(tokenString string) (*jwt.Token, error) {
	privateKeyPEM, err := s.repo.GetSigningKeyFromAuditedToken(tokenString)
	if err != nil {
		return nil, err
	}

	// Decode the PEM block to obtain the private key
	privateKeyBlock, _ := pem.Decode(privateKeyPEM)
	if privateKeyBlock == nil {
		return nil, errors.New("failed to decode PEM block containing private key")
	}

	// Parse the DER encoded private key
	privateKey, err := x509.ParsePKCS1PrivateKey(privateKeyBlock.Bytes)
	if err != nil {
		return nil, err
	}

	token, err := jwt.Parse(tokenString, func(jwtToken *jwt.Token) (interface{}, error) {
		if _, ok := jwtToken.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, fmt.Errorf("unexpected method: %s", jwtToken.Header["alg"])
		}
		return privateKey.Public(), nil
	})
	return token, err
}

func (s *SvcImpl) ListKnownSigningKeys() (*KeysResponse, error) {
	result := KeysResponse{Keys: make([]SignKey, 0, 1)}

	keys, keysData, err := s.repo.ListAllSigningKeys()
	if err != nil {
		return nil, err
	}

	for i := range keys {
		privateKeyPEM := keysData[i]

		// Decode the PEM block to obtain the private key
		privateKeyBlock, _ := pem.Decode(privateKeyPEM)
		if privateKeyBlock == nil {
			return nil, errors.New("failed to decode PEM block containing private key")
		}

		// Parse the DER encoded private key
		privateKey, err := x509.ParsePKCS1PrivateKey(privateKeyBlock.Bytes)
		if err != nil {
			log.Printf("error parsing private key : %#v", err)
			return nil, err
		}

		// Marshal the public key to PKIX format
		publicKeyBytes, err := x509.MarshalPKIXPublicKey(privateKey.Public())
		if err != nil {
			return nil, fmt.Errorf("failed to marshal public key for key named %q : %#v", keys[i], err)
		}

		// Create a PEM block for the public key
		publicKeyPEM := pem.EncodeToMemory(&pem.Block{
			Type:  "PUBLIC KEY",
			Bytes: publicKeyBytes,
		})

		result.Keys = append(result.Keys, SignKey{
			Key:       string(publicKeyPEM),
			KeyID:     keys[i],
			Algorithm: s.signingMethodName,
		})
	}

	return &result, nil
}

func (s *SvcImpl) GenerateAndSavePrivateKey(totpKey, keyName string) error {
	if s.totpKey != totpKey {
		return fmt.Errorf("TOTP secrets not equal %s != %s", s.totpKey, totpKey)
	}

	if len(keyName) == 0 {
		return errors.New("must have a valid key name")
	}

	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return err
	}

	// Convert private key to PKCS1 ASN.1 DER format
	privateKeyBytes := x509.MarshalPKCS1PrivateKey(privateKey)
	privateKeyBlock := pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: privateKeyBytes,
	}

	return s.repo.SavePrivateKey(keyName, pem.EncodeToMemory(&privateKeyBlock))
}

func (s *SvcImpl) OnboardNewClient(totpKey, clientID, clientSecret, keyName string) error {
	if s.totpKey != totpKey {
		return fmt.Errorf("TOTP secrets not equal %s != %s", s.totpKey, totpKey)
	}

	hashedSecret, err := bcrypt.GenerateFromPassword([]byte(clientSecret), bcrypt.DefaultCost)
	if err != nil {
		return err
	}

	return s.repo.InsertClient(clientID, hashedSecret, keyName)
}
