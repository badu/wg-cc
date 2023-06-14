package login

type ErrorResponse struct {
	Code    int    `json:"code"`
	Message string `json:"error"`
}

type TokenResponse struct {
	AccessToken string `json:"access_token"`
	TokenType   string `json:"token_type"`
	ExpiresIn   int64  `json:"expires_in"`
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

type IntrospectionResponse struct {
	Scope     string `json:"scope"`
	ExpiresAt int64  `json:"exp"`
	Active    bool   `json:"active"`
}
