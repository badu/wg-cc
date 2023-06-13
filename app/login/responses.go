package login

type TokenResponse struct {
	AccessToken string `json:"access_token"`
	TokenType   string `json:"token_type"`
	ExpiresIn   int64  `json:"expires_in"`
}

type IntrospectionResponse struct {
	Active    bool   `json:"active"`
	Scope     string `json:"scope"`
	ClientID  string `json:"client_id"`
	ExpiresAt int64  `json:"exp"`
	TokenType string `json:"token_type"`
}

type Key struct {
	Kid string `json:"kid"`
}

type KeysResponse struct {
	Keys []Key `json:"keys"`
}
