package cache

import (
	"testing"

	"ddone-server-auth/internal/domain/auth"
)

func TestPublicSigningKeysDropsPrivateKeyMaterial(t *testing.T) {
	keys := []auth.SigningKey{{
		KeyID:         "kid-1",
		PublicX:       "x",
		PublicY:       "y",
		PrivateKeyPEM: "private-key",
	}}

	publicKeys := publicSigningKeys(keys)
	if len(publicKeys) != 1 {
		t.Fatalf("expected one public key, got %d", len(publicKeys))
	}
	if publicKeys[0].PrivateKeyPEM != "" {
		t.Fatal("expected private key material to be removed")
	}
	if keys[0].PrivateKeyPEM == "" {
		t.Fatal("expected source key to remain unchanged")
	}
}
