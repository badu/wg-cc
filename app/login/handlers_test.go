package login_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
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
	req, err := http.NewRequest(http.MethodPost, login.TokenRoute, nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Form = payload

	recorder := httptest.NewRecorder()
	mockedRepo := login.NewMock(true)
	service, err := login.NewService(&mockedRepo, []byte(`test`), time.Duration(8)*time.Hour, login.HS256)
	if err != nil {
		t.Fatalf("service creation error : %#v", err)
	}

	handler := login.IssueToken(service)
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

	if response.ExpiresIn != int64(time.Duration(8)*time.Hour) {
		t.Errorf("Expected expires in 8 hours, but got %d", response.ExpiresIn)
	}
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
	mockedRepo := login.NewMock(false)
	service, err := login.NewService(&mockedRepo, []byte(`test`), time.Duration(8)*time.Hour, login.HS256)
	if err != nil {
		t.Fatalf("service creation error : %#v", err)
	}

	handler := login.IssueToken(service)
	handler.ServeHTTP(recorder, req)

	if recorder.Code != http.StatusUnauthorized {
		t.Errorf("Expected status %d, but got %d", http.StatusUnauthorized, recorder.Code)
	}
}
