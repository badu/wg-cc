package login_test

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"log"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/badu/wg-cc/app/login"
)

func TestGenerateToken(t *testing.T) {
	payload := url.Values{
		"grant_type":    {"client_credentials"},
		"client_id":     {"test"},
		"client_secret": {"test"},
	}
	req, err := http.NewRequest(http.MethodPost, login.TokenRoute, strings.NewReader(payload.Encode()))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	req.Form = payload

	recorder := httptest.NewRecorder()

	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		log.Fatalf("Error generating private key: %v", err)
	}

	privateKeyBytes := x509.MarshalPKCS1PrivateKey(privateKey)
	privateKeyBlock := pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: privateKeyBytes,
	}

	mockedRepo := login.NewMock("test") // mock the password
	mockedRepo.SavePrivateKey("test", pem.EncodeToMemory(&privateKeyBlock))
	service := login.NewService(&mockedRepo, time.Duration(8)*time.Hour, login.RS256, "123456")

	handler := login.IssueToken(&service)
	handler.ServeHTTP(recorder, req)

	if recorder.Code != http.StatusOK {
		t.Fatalf("Expected status %d, but got %d => %s", http.StatusOK, recorder.Code, recorder.Body.String())
	}

	var response login.TokenResponse
	if err := json.Unmarshal(recorder.Body.Bytes(), &response); err != nil {
		t.Fatalf("error decoding response : %#v", err)
	}

	if len(response.AccessToken) == 0 {
		t.Error("Access token is empty")
	}

	if response.TokenType != "Bearer" {
		t.Errorf("Expected `Bearer`, but got %q", response.TokenType)
	}

	if response.ExpiresIn != 28800 {
		t.Errorf("Expected expires in 8 hours (28800 seconds), but got %d seconds", response.ExpiresIn)
	}

	t.Logf("token : %q", response.AccessToken)
	t.Logf("expires in : %d", response.ExpiresIn)
}

func TestFailGenerateToken(t *testing.T) {
	payload := url.Values{
		"grant_type":    {"client_credentials"},
		"client_id":     {"test"},
		"client_secret": {"test"},
	}
	req, err := http.NewRequest(http.MethodPost, login.TokenRoute, strings.NewReader(payload.Encode()))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	req.Form = payload

	recorder := httptest.NewRecorder()

	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		log.Fatalf("Error generating private key: %v", err)
	}

	privateKeyBytes := x509.MarshalPKCS1PrivateKey(privateKey)
	privateKeyBlock := pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: privateKeyBytes,
	}

	mockedRepo := login.NewMock("should-fail") // mock the password
	mockedRepo.SavePrivateKey("should-fail", pem.EncodeToMemory(&privateKeyBlock))

	service := login.NewService(&mockedRepo, time.Duration(8)*time.Hour, login.RS256, "123456")

	handler := login.IssueToken(&service)
	handler.ServeHTTP(recorder, req)

	if recorder.Code != http.StatusUnauthorized {
		t.Errorf("Expected status %d, but got %d", http.StatusUnauthorized, recorder.Code)
	}
}
