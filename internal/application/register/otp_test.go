package register

import (
	"testing"
	"time"
)

func TestRegisterOTPMessageUsesShortFormat(t *testing.T) {
	message := RegisterOTPMessage("123456", 5*time.Minute)

	expected := "DDONE code: 123456. Valid for 5 minutes. Do not share it."
	if message != expected {
		t.Fatalf("expected %q, got %q", expected, message)
	}
}

func TestRegisterOTPMessageUsesSingularMinute(t *testing.T) {
	message := RegisterOTPMessage("123456", 30*time.Second)

	expected := "DDONE code: 123456. Valid for 1 minute. Do not share it."
	if message != expected {
		t.Fatalf("expected %q, got %q", expected, message)
	}
}
