//go:build integration
// +build integration

package login_test

import (
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/badu/wg-cc/app/login"
)

/*
*
These tests should run agains a running instance of the server
*/
func getTokenResponse(t *testing.T) *login.TokenResponse {
	serverURL := "http://127.0.0.1:8080" + login.TokenRoute

	formData := url.Values{
		"grant_type":    {"client_credentials"},
		"client_id":     {"test"},
		"client_secret": {"test"},
	}

	req, err := http.NewRequest(http.MethodPost, serverURL, strings.NewReader(formData.Encode()))
	if err != nil {
		t.Fatalf("Error creating request: %#v", err)
	}

	// Set the Content-Type header
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("Error sending request: %#v", err)
	}
	defer resp.Body.Close()

	// Read response body
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("Error reading response: %#v", err)
	}

	var response login.TokenResponse
	err = json.Unmarshal(body, &response)
	if err != nil {
		t.Fatalf("Error decoding JSON: %#v\nBody was : %s", err, body)
	}
	return &response
}

func TestGenerateJWTToken(t *testing.T) {
	response := getTokenResponse(t)
	t.Logf("Response: %#v", response)
}

func TestListKeys(t *testing.T) {
	response := getTokenResponse(t)

	serverURL := "http://127.0.0.1:8080" + login.ListRoute

	req, err := http.NewRequest(http.MethodGet, serverURL, nil)
	if err != nil {
		t.Fatalf("Error creating request: %#v", err)
	}

	req.Header.Set("Accept", "application/json")
	req.Header.Set("Authorization", "Bearer "+response.AccessToken)

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("Error sending request: %#v", err)
	}
	defer resp.Body.Close()

	// Read response body
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("Error reading response: %#v", err)
	}

	t.Logf("Response: %s", string(body))
}

func TestIntrospect(t *testing.T) {
	response := getTokenResponse(t)

	serverURL := "http://127.0.0.1:8080" + login.IntrospectRoute

	req, err := http.NewRequest(http.MethodGet, serverURL, nil)
	if err != nil {
		t.Fatalf("Error creating request: %#v", err)
	}

	req.Header.Set("Accept", "application/json")
	req.Header.Set("Authorization", "Bearer "+response.AccessToken)

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("Error sending request: %#v", err)
	}
	defer resp.Body.Close()

	// Read response body
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("Error reading response: %#v", err)
	}

	t.Logf("Response: %s", string(body))
}
