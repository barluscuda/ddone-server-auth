package sms

import (
	"context"
	appregister "ddone-server-auth/internal/application/register"
	"errors"

	"github.com/barluscuda/dextools/wenova"
)

var _ appregister.OTPSender = (*SMS)(nil)

func (s SMS) SendOTP(ctx context.Context, phoneNumber string, msg string) error {
	if s.wnv == nil {
		return errors.New("wenova client is nil")
	}

	req := wenova.SendSMSRequest{
		Header:      "WNV-OTP",
		PhoneNumber: phoneNumber,
		Message:     msg,
	}

	_, err := s.wnv.SendSMS(ctx, req)
	return err
}
