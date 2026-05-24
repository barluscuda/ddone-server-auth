package sms

import (
	"context"
	appregister "ddone-server-auth/internal/application/register"
	"ddone-server-auth/internal/domain/user"
	"errors"

	"github.com/barluscuda/dextools/wenova"
)

var _ appregister.OTPSender = (*SMS)(nil)

func (s SMS) SendOTP(ctx context.Context, telCode string, number string, msg string) error {
	switch telCode {
	case "856":
	default:
		return user.ErrUnsupportedTelCode
	}

	if s.wnv == nil {
		return errors.New("wenova client is nil")
	}

	req := wenova.SendSMSRequest{
		Header:      "WNV-OTP",
		PhoneNumber: number,
		Message:     msg,
	}

	_, err := s.wnv.SendSMS(ctx, req)
	return err
}
