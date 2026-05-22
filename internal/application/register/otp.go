package register

import (
	"crypto/rand"
	"errors"
	"fmt"
	"math/big"
	"time"
)

func GenerateOTP(length int) (string, error) {
	if length <= 0 {
		return "", errors.New("otp length must be greater than zero")
	}

	code := make([]byte, length)
	for i := range code {
		n, err := rand.Int(rand.Reader, big.NewInt(10))
		if err != nil {
			return "", err
		}

		code[i] = byte('0') + byte(n.Int64())
	}

	return string(code), nil
}

func RegisterOTPMessage(code string, expiresIn time.Duration) string {
	minutes := int(expiresIn.Minutes())
	if minutes <= 0 {
		minutes = 1
	}

	suffix := ""
	if minutes > 1 {
		suffix = "s"
	}

	return fmt.Sprintf(
		"DDONE Verification Code\n\nCode: %s\nValid for: %d minute%s\n\nFor your security, do not share this code with anyone. If you did not request this code, please ignore this message.",
		code,
		minutes,
		suffix,
	)
}
