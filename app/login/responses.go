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

type Key struct {
	Kid string `json:"kid"`
}

type KeysResponse struct {
	Keys []Key `json:"keys"`
}
