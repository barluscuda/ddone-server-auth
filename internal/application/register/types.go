package register

import (
	"context"
	"ddone-server-auth/internal/application/dexbotkiller"
	"ddone-server-auth/internal/application/otp"
	"errors"
	"time"

	"ddone-server-auth/internal/domain/user"
)

type UseCase interface {
	Register(ctx context.Context, input RegisterInput) (*RegisterResult, error)
	VerifyRegister(ctx context.Context, input VerifyRegisterInput) (*user.User, error)
	ResendRegisterOTP(ctx context.Context, input ResendRegisterOTPInput) (*RegisterResult, error)
}

type RegisterInput struct {
	PhoneNumber    string
	Password       string
	ChallengeToken string
}

type RegisterResult struct {
	TicketID             string
	ExpiresAt            time.Time
	ResendCooldown       time.Duration
	RemainingResendCount int
}

type Challenge struct {
	Provider string
	SiteKey  string
}

type ChallengeRequiredError struct {
	Challenge dexbotkiller.Challenge
}

func (e *ChallengeRequiredError) Error() string {
	return ErrChallengeRequired.Error()
}

func (e *ChallengeRequiredError) Unwrap() error {
	return ErrChallengeRequired
}

func ChallengeFromError(err error) (Challenge, bool) {
	var challengeErr *ChallengeRequiredError
	if !errors.As(err, &challengeErr) {
		return Challenge{}, false
	}

	return Challenge{
		Provider: string(challengeErr.Challenge.Provider),
		SiteKey:  challengeErr.Challenge.SiteKey,
	}, true
}

type Settings struct {
	OTPPolicy             otp.Policy
	SystemRateLimitPolicy *SystemRateLimitPolicy
	DexBotKiller          *dexbotkiller.Engine
	ChallengeVerifier     dexbotkiller.ChallengeVerifier
}

type SystemRateLimitPolicy struct {
	Window      time.Duration
	MaxRequests int
}

type ResendRegisterOTPInput struct {
	TicketID       string
	ChallengeToken string
}

type VerifyRegisterInput struct {
	TicketID string
	OTPCode  string
}
