package login

type TokenResponse struct {
	AccessToken string `json:"token"`
	TokenType   string `json:"type"`
	ExpiresIn   int64  `json:"expires"`
}

type IntrospectionResponse struct {
	Active    bool   `json:"active"`
	ClientID  string `json:"client_id"`
	ExpiresAt int64  `json:"exp"`
}

type Key struct {
	Kid string `json:"kid"`
}

type KeysResponse struct {
	Keys []Key `json:"keys"`
}
