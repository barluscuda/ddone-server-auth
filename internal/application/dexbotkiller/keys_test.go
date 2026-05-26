package dexbotkiller

import (
	"strings"
	"testing"
	"time"
)

func TestKeyBuilderHashesRawValues(t *testing.T) {
	hasher, err := NewHasher("test-pepper")
	if err != nil {
		t.Fatalf("new hasher: %v", err)
	}
	keys := NewKeyBuilder("dbk:v1", hasher)

	key := keys.Counter(FlowRegister, FlowActionStart, "phone", "+8562012345678", time.Minute)
	if strings.Contains(key, "+8562012345678") {
		t.Fatalf("expected key to omit raw phone number, got %q", key)
	}
	if !strings.HasPrefix(key, "dbk:v1:counter:register:start:phone:") {
		t.Fatalf("unexpected key prefix: %q", key)
	}
}

func TestHasherRejectsEmptyPepper(t *testing.T) {
	if _, err := NewHasher(""); err == nil {
		t.Fatal("expected empty pepper to be rejected")
	}
}
