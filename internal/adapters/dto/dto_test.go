package dto

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func TestResLoginMarshalsCamelCaseFields(t *testing.T) {
	payload, err := json.Marshal(ResLogin{
		Success: true,
		Code:    "login_succeeded",
		Message: "login completed successfully",
		Data: ResLoginData{
			AccessToken:      "access-token",
			TokenType:        "Bearer",
			ExpiresAt:        time.Date(2026, 5, 23, 10, 15, 0, 0, time.UTC),
			ExpiresIn:        900,
			RefreshToken:     "refresh-token",
			RefreshExpiresAt: time.Date(2026, 6, 22, 10, 0, 0, 0, time.UTC),
		},
	})
	if err != nil {
		t.Fatalf("marshal login dto: %v", err)
	}

	body := string(payload)
	for _, expected := range []string{"accessToken", "tokenType", "expiresAt", "expiresIn", "refreshToken", "refreshExpiresAt"} {
		if !strings.Contains(body, `"`+expected+`"`) {
			t.Fatalf("expected response body to contain %q, got %s", expected, body)
		}
	}
	for _, rejected := range []string{"access_token", "token_type", "expires_at", "expires_in", "refresh_token", "refresh_expires_at"} {
		if strings.Contains(body, `"`+rejected+`"`) {
			t.Fatalf("expected response body to avoid %q, got %s", rejected, body)
		}
	}
}

func TestResRegisterMarshalsCamelCaseFields(t *testing.T) {
	payload, err := json.Marshal(ResRegister{
		Success: true,
		Code:    "register_otp_sent",
		Message: "otp sent successfully",
		Data: ResRegisterTicketData{
			TicketID:              "reg_fixed123",
			ExpiresAt:             time.Date(2026, 5, 23, 10, 5, 0, 0, time.UTC),
			OTPLength:             6,
			ResendCooldownSeconds: 60,
			RemainingResendCount:  3,
		},
	})
	if err != nil {
		t.Fatalf("marshal register dto: %v", err)
	}

	body := string(payload)
	for _, expected := range []string{"ticketId", "expiresAt", "otpLength", "resendCooldownSeconds", "remainingResendCount"} {
		if !strings.Contains(body, `"`+expected+`"`) {
			t.Fatalf("expected response body to contain %q, got %s", expected, body)
		}
	}
	for _, rejected := range []string{"ticket_id", "expires_at", "otp_length", "resend_cooldown_seconds", "remaining_resend_count"} {
		if strings.Contains(body, `"`+rejected+`"`) {
			t.Fatalf("expected response body to avoid %q, got %s", rejected, body)
		}
	}
}

func TestResSettingsMeMarshalsCamelCaseFields(t *testing.T) {
	payload, err := json.Marshal(ResSettingsMe{
		Success: true,
		Code:    "settings_fetched",
		Message: "settings fetched successfully",
		Data: ResSettingsMeData{
			ID:              "account-1",
			PhoneNumber:     "2012345678",
			PhoneVerifiedAt: time.Date(2026, 5, 24, 0, 0, 0, 0, time.UTC),
			CreatedAt:       time.Date(2026, 5, 23, 0, 0, 0, 0, time.UTC),
		},
	})
	if err != nil {
		t.Fatalf("marshal settings me dto: %v", err)
	}

	body := string(payload)
	for _, expected := range []string{"phoneNumber", "phoneVerifiedAt", "createdAt"} {
		if !strings.Contains(body, `"`+expected+`"`) {
			t.Fatalf("expected response body to contain %q, got %s", expected, body)
		}
	}
	for _, rejected := range []string{"phone_number", "phone_verified_at", "created_at"} {
		if strings.Contains(body, `"`+rejected+`"`) {
			t.Fatalf("expected response body to avoid %q, got %s", rejected, body)
		}
	}
}
