# JWT Integration Guide

This guide is for other services that need to verify `ddone-server-auth` access tokens.

## Summary

- Token type: JWT access token
- Transport: `Authorization: Bearer <accessToken>`
- Signing algorithm: `ES256`
- Curve: `P-256`
- Public keys endpoint: `GET /.well-known/jwks.json`
- Default issuer: `ddone-server-auth`
- Default audience: `ddone-clients`
- Default access-token TTL: `5m`

Do not call this auth service for every request just to validate access tokens. Verify JWTs locally with cached JWKS keys.

## Token Header

Access tokens use a JOSE header like:

```json
{
  "alg": "ES256",
  "kid": "key_123",
  "typ": "JWT"
}
```

Downstream services must reject tokens when:

- `alg` is not `ES256`
- `kid` is missing or does not match a published JWKS key
- `typ` is present and is not `JWT`
- the ECDSA signature is invalid

## Token Claims

Payload example:

```json
{
  "iss": "ddone-server-auth",
  "sub": "9f9d4c17-7f0d-47cf-96af-0de257391111",
  "aud": "ddone-clients",
  "jti": "tok_123",
  "iat": 1779703260,
  "nbf": 1779703260,
  "exp": 1779703560,
  "userId": "9f9d4c17-7f0d-47cf-96af-0de257391111",
  "phone_number": "+8562012345678"
}
```

Required validation:

- `iss` equals the configured issuer.
- `aud` equals the configured audience expected by your service.
- `sub` is present.
- `jti` is present.
- `iat`, `nbf`, and `exp` are positive Unix timestamps.
- current time is on or after `nbf`.
- current time is before `exp`.
- `exp` is not before `iat`.

Identity fields:

- Prefer `userId` as the authenticated user id.
- If `userId` is absent, use `sub`.
- `phone_number` is optional and should not be treated as an authorization boundary.
- `jti` identifies this access token and can be useful in logs.

## JWKS

Fetch public keys from:

```http
GET https://auth.example.com/.well-known/jwks.json
```

Response:

```json
{
  "keys": [
    {
      "kty": "EC",
      "use": "sig",
      "crv": "P-256",
      "alg": "ES256",
      "kid": "key_123",
      "x": "base64url-x-coordinate",
      "y": "base64url-y-coordinate"
    }
  ]
}
```

The endpoint returns:

```http
Cache-Control: public, max-age=300
ETag: "..."
```

Integration behavior:

- Cache JWKS for up to 5 minutes.
- Re-fetch JWKS when a token's `kid` is unknown.
- Use `If-None-Match` with the cached `ETag` when refreshing keys.
- Keep the previous key set briefly during refresh failures so valid in-flight tokens are not rejected only because JWKS refresh failed.

## Key Rotation

Signing keys rotate according to the auth service config:

- `security.auth.signing_key_rotation`
- `security.auth.signing_key_retention`

Published JWKS includes keys that have not reached retirement. Since access tokens are short lived, downstream services should normally only need a small JWKS cache and a retry-on-unknown-`kid` path.

## Go Verification Example

This example uses `github.com/golang-jwt/jwt/v5`.

```go
package authverify

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"net/http"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

type Claims struct {
	UserID      string `json:"userId"`
	PhoneNumber string `json:"phone_number"`
	jwt.RegisteredClaims
}

type JWKSet struct {
	Keys []JWK `json:"keys"`
}

type JWK struct {
	KeyType   string `json:"kty"`
	Use       string `json:"use"`
	Curve     string `json:"crv"`
	Algorithm string `json:"alg"`
	KeyID     string `json:"kid"`
	X         string `json:"x"`
	Y         string `json:"y"`
}

func Verify(ctx context.Context, rawToken string, jwksURL string, issuer string, audience string) (*Claims, error) {
	set, err := fetchJWKS(ctx, jwksURL)
	if err != nil {
		return nil, err
	}

	claims := &Claims{}
	token, err := jwt.ParseWithClaims(rawToken, claims, func(token *jwt.Token) (any, error) {
		if token.Method.Alg() != jwt.SigningMethodES256.Alg() {
			return nil, fmt.Errorf("unexpected alg: %s", token.Method.Alg())
		}

		kid, _ := token.Header["kid"].(string)
		if strings.TrimSpace(kid) == "" {
			return nil, errors.New("missing kid")
		}

		return publicKeyForKID(set, kid)
	}, jwt.WithIssuer(issuer), jwt.WithAudience(audience), jwt.WithExpirationRequired(), jwt.WithIssuedAt())
	if err != nil {
		return nil, err
	}
	if !token.Valid {
		return nil, errors.New("invalid token")
	}
	if claims.Subject == "" || claims.ID == "" || claims.IssuedAt == nil || claims.NotBefore == nil || claims.ExpiresAt == nil {
		return nil, errors.New("missing required claims")
	}
	if claims.ExpiresAt.Time.Before(claims.IssuedAt.Time) {
		return nil, errors.New("invalid token time range")
	}
	if claims.UserID == "" {
		claims.UserID = claims.Subject
	}
	if claims.UserID == "" {
		return nil, errors.New("missing user id")
	}

	return claims, nil
}

func fetchJWKS(ctx context.Context, jwksURL string) (*JWKSet, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, jwksURL, nil)
	if err != nil {
		return nil, err
	}

	client := &http.Client{Timeout: 5 * time.Second}
	res, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()

	if res.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("jwks status: %d", res.StatusCode)
	}

	var set JWKSet
	if err := json.NewDecoder(res.Body).Decode(&set); err != nil {
		return nil, err
	}
	return &set, nil
}

func publicKeyForKID(set *JWKSet, kid string) (*ecdsa.PublicKey, error) {
	for _, key := range set.Keys {
		if key.KeyID != kid {
			continue
		}
		if key.KeyType != "EC" || key.Use != "sig" || key.Curve != "P-256" || key.Algorithm != "ES256" {
			return nil, errors.New("unsupported jwk")
		}

		xBytes, err := base64.RawURLEncoding.DecodeString(key.X)
		if err != nil {
			return nil, err
		}
		yBytes, err := base64.RawURLEncoding.DecodeString(key.Y)
		if err != nil {
			return nil, err
		}

		x := new(big.Int).SetBytes(xBytes)
		y := new(big.Int).SetBytes(yBytes)
		curve := elliptic.P256()
		if !curve.IsOnCurve(x, y) {
			return nil, errors.New("invalid jwk coordinates")
		}

		return &ecdsa.PublicKey{
			Curve: curve,
			X:     x,
			Y:     y,
		}, nil
	}

	return nil, errors.New("kid not found")
}
```

Production services should wrap the JWKS fetch with an in-memory cache and only refresh on cache expiry or unknown `kid`.

## Authorization Pattern

JWT verification proves the caller has a valid DDONE auth token. It does not decide business permissions.

Recommended downstream request context:

```text
userId: claims.userId or claims.sub
tokenId: claims.jti
phoneNumber: claims.phone_number, optional
```

Use service-local authorization checks for ownership, roles, resource access, and tenant boundaries.

## Failure Handling

Return `401 Unauthorized` when:

- the `Authorization` header is missing
- the header is not `Bearer <token>`
- signature verification fails
- issuer or audience does not match
- the token is expired or not yet valid
- no matching JWKS key can be found after refresh

Return `403 Forbidden` when:

- the token is valid, but the user does not have permission for the requested resource

Do not expose raw JWT parser errors in public responses.
