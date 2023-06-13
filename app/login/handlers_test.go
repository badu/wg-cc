package login_test

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"golang.org/x/crypto/bcrypt"

	"github.com/badu/wg-cc/app/login"
)

func TestGenerateToken(t *testing.T) {
	hashedSecret, err := bcrypt.GenerateFromPassword([]byte("test"), bcrypt.DefaultCost)
	if err != nil {
		t.Fatalf("error hashing secret: %#v", err)
	}

	payload := url.Values{
		"grant_type":    {"client_credentials"},
		"client_id":     {"test"},
		"client_secret": {string(hashedSecret)},
	}
	req, err := http.NewRequest(http.MethodPost, login.TokenRoute, nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Form = payload

	recorder := httptest.NewRecorder()
	mockedRepo := login.NewMock("valid-client-id")
	privateKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	service := login.NewService(&mockedRepo, privateKey, time.Duration(8)*time.Hour, login.RS256)

	handler := login.IssueToken(&service)
	handler.ServeHTTP(recorder, req)

	if recorder.Code != http.StatusOK {
		t.Errorf("Expected status %d, but got %d", http.StatusOK, recorder.Code)
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
	req, err := http.NewRequest(http.MethodPost, login.TokenRoute, nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Form = payload

	recorder := httptest.NewRecorder()
	mockedRepo := login.NewMock("")
	privateKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	service := login.NewService(&mockedRepo, privateKey, time.Duration(8)*time.Hour, login.RS256)

	handler := login.IssueToken(&service)
	handler.ServeHTTP(recorder, req)

	if recorder.Code != http.StatusUnauthorized {
		t.Errorf("Expected status %d, but got %d", http.StatusUnauthorized, recorder.Code)
	}
}
