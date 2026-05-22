package sms

import (
	"context"
	"errors"

	"github.com/barluscuda/dextools/wenova"
)

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
