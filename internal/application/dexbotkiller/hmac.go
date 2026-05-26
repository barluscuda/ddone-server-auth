package dexbotkiller

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
)

var ErrPepperRequired = errors.New("dexbotkiller pepper is required")

type Hasher struct {
	pepper []byte
}

func NewHasher(pepper string) (Hasher, error) {
	if pepper == "" {
		return Hasher{}, ErrPepperRequired
	}

	return Hasher{pepper: []byte(pepper)}, nil
}

func (h Hasher) Hash(value string) string {
	if value == "" {
		return ""
	}

	mac := hmac.New(sha256.New, h.pepper)
	_, _ = mac.Write([]byte(value))

	return hex.EncodeToString(mac.Sum(nil))
}

func (h Hasher) Sign(value string) string {
	return h.Hash(value)
}

func (h Hasher) ValidSignature(value string, signature string) bool {
	expected := h.Sign(value)
	return hmac.Equal([]byte(expected), []byte(signature))
}
