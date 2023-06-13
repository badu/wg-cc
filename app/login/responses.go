package login

type TokenResponse struct {
	AccessToken string `json:"access_token"`
	TokenType   string `json:"token_type"`
	ExpiresIn   int64  `json:"expires_in"`
}

type IntrospectionResponse struct {
	Scope     string `json:"scope"`
	ClientID  string `json:"client_id"`
	TokenType string `json:"token_type"`
	ExpiresIn int64  `json:"expires_in"`
	Active    bool   `json:"active"`
}

type SignKey struct {
	KeyID     string `json:"key_id"`
	Key       string `json:"public_key"`
	Algorithm string `json:"algorithm"`
	Use       string `json:"use"`
}

type KeysResponse struct {
	Keys []SignKey `json:"keys"`
}
