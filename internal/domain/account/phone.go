package account

import "strings"

var ErrInvalidPhoneNumber = errInvalidPhoneNumber("phone number format is invalid")

type errInvalidPhoneNumber string

func (e errInvalidPhoneNumber) Error() string {
	return string(e)
}

func NormalizePhoneNumber(raw string) (string, error) {
	value := strings.TrimSpace(raw)
	if value == "" {
		return "", nil
	}

	var builder strings.Builder
	builder.Grow(len(value))

	for i, r := range value {
		switch {
		case r >= '0' && r <= '9':
			builder.WriteRune(r)
		case r == '+' && i == 0:
			continue
		case r == ' ' || r == '-' || r == '(' || r == ')':
			continue
		default:
			return "", ErrInvalidPhoneNumber
		}
	}

	digits := builder.String()
	if digits == "" {
		return "", ErrInvalidPhoneNumber
	}

	switch {
	case strings.HasPrefix(digits, "00856"):
		digits = digits[5:]
	case strings.HasPrefix(digits, "856"):
		digits = digits[3:]
	}

	if strings.HasPrefix(digits, "020") {
		digits = digits[1:]
	}

	if len(digits) != 10 || !strings.HasPrefix(digits, "20") {
		return "", ErrInvalidPhoneNumber
	}

	return digits, nil
}
