package auth

type JWK struct {
	KeyType   string
	Use       string
	Curve     string
	Algorithm string
	KeyID     string
	X         string
	Y         string
}

type JWKSet struct {
	Keys []JWK
}
