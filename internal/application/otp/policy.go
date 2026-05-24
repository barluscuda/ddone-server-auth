package otp

import "time"

type Policy struct {
	TTL                 time.Duration
	PhoneWindow         time.Duration
	ResendCooldown      time.Duration
	VerifyAttemptWindow time.Duration
	MaxPhoneRequests    int
	MaxResends          int
	MaxVerifyAttempts   int
}

func (p Policy) WithDefaults(defaults Policy) Policy {
	if p.TTL <= 0 {
		p.TTL = defaults.TTL
	}
	if p.PhoneWindow <= 0 {
		p.PhoneWindow = defaults.PhoneWindow
	}
	if p.ResendCooldown <= 0 {
		p.ResendCooldown = defaults.ResendCooldown
	}
	if p.VerifyAttemptWindow <= 0 {
		p.VerifyAttemptWindow = defaults.VerifyAttemptWindow
	}
	if p.MaxPhoneRequests <= 0 {
		p.MaxPhoneRequests = defaults.MaxPhoneRequests
	}
	if p.MaxResends <= 0 {
		p.MaxResends = defaults.MaxResends
	}
	if p.MaxVerifyAttempts <= 0 {
		p.MaxVerifyAttempts = defaults.MaxVerifyAttempts
	}

	return p
}
