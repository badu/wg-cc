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
	ClientID  string `json:"client_id"`
	Subject   string `json:"sub"`
	Scope     string `json:"scope"`
	Audience  string `json:"aud"`
	Type      string `json:"token_type"`
	UUID      string `json:"jti"`
	ExpiresAt int64  `json:"exp"`
	NotBefore int64  `json:"nbf"`
	IssuedAt  int64  `json:"iat"`
	Active    bool   `json:"active"`
}
