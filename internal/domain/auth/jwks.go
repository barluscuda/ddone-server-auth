package auth

type JWK struct {
	KeyType   string `json:"kty"`
	Use       string `json:"use"`
	Curve     string `json:"crv"`
	Algorithm string `json:"alg"`
	KeyID     string `json:"kid"`
	X         string `json:"x"`
	Y         string `json:"y"`
}

type JWKSet struct {
	Keys []JWK `json:"keys"`
}
