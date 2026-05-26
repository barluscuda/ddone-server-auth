package dexbotkiller

import (
	"context"
	"time"
)

type contextKey string

const clientContextKey contextKey = "dexbotkiller_client_context"

type Mode string

const (
	ModePassive   Mode = "passive"
	ModeDelay     Mode = "delay"
	ModeChallenge Mode = "challenge"
	ModeEnforce   Mode = "enforce"
)

type Action string

const (
	ActionAllow     Action = "allow"
	ActionDelay     Action = "delay"
	ActionChallenge Action = "challenge"
	ActionBlock     Action = "block"
)

type Flow string

const (
	FlowRegister      Flow = "register"
	FlowPasswordReset Flow = "password_reset"
	FlowLogin         Flow = "login"
	FlowRefreshToken  Flow = "refresh_token"
)

type FlowAction string

const (
	FlowActionStart   FlowAction = "start"
	FlowActionResend  FlowAction = "resend"
	FlowActionVerify  FlowAction = "verify"
	FlowActionSubmit  FlowAction = "submit"
	FlowActionRefresh FlowAction = "refresh"
)

type Outcome string

const (
	OutcomeAllowed        Outcome = "allowed"
	OutcomeDelayed        Outcome = "delayed"
	OutcomeChallenge      Outcome = "challenge_required"
	OutcomeBlocked        Outcome = "blocked"
	OutcomeSMSSent        Outcome = "sms_sent"
	OutcomeSMSSendFailed  Outcome = "sms_send_failed"
	OutcomeOTPInvalid     Outcome = "otp_invalid"
	OutcomeOTPSuccess     Outcome = "otp_success"
	OutcomeLoginFailed    Outcome = "login_failed"
	OutcomeLoginSuccess   Outcome = "login_success"
	OutcomeRefreshSuccess Outcome = "refresh_success"
	OutcomeRefreshReplay  Outcome = "refresh_replay_detected"
)

type ClientContext struct {
	IP              string
	Subnet          string
	UserAgent       string
	DeviceID        string
	HasDeviceCookie bool
	AcceptLanguage  string
	ContentType     string
	Timestamp       time.Time
}

type ChallengeProvider string

const (
	ChallengeProviderCloudflareTurnstile ChallengeProvider = "cloudflare_turnstile"
)

type Challenge struct {
	Provider ChallengeProvider
	SiteKey  string
}

type Request struct {
	Flow        Flow
	Action      FlowAction
	Client      ClientContext
	PhoneNumber string
	UserID      string
	TicketID    string
	Timestamp   time.Time
}

type Event struct {
	Request
	Outcome Outcome
}

type Decision struct {
	Action     Action
	RiskScore  float64
	RetryAfter time.Duration
	Reasons    []string
	Challenge  Challenge
}

type ChallengeVerification struct {
	Provider       ChallengeProvider
	Token          string
	RemoteIP       string
	IdempotencyKey string
}

type ChallengeVerifier interface {
	Verify(ctx context.Context, verification ChallengeVerification) error
}

func ContextWithClientContext(ctx context.Context, clientContext ClientContext) context.Context {
	return context.WithValue(ctx, clientContextKey, clientContext)
}

func ClientContextFromContext(ctx context.Context) (ClientContext, bool) {
	clientContext, ok := ctx.Value(clientContextKey).(ClientContext)
	return clientContext, ok
}
