package dexbotkiller

import "time"

type Thresholds struct {
	DelayScore     float64
	ChallengeScore float64
	BlockScore     float64
}

type Policy struct {
	Mode                    Mode
	Prefix                  string
	Thresholds              Thresholds
	Challenge               Challenge
	CounterWindow           time.Duration
	UniqueWindow            time.Duration
	ScoreTTL                time.Duration
	Delay                   time.Duration
	MissingUserAgentScore   float64
	MissingDeviceScore      float64
	SuspiciousAgentScore    float64
	InvalidContentTypeScore float64
	IPVelocityScore         float64
	PhoneVelocityScore      float64
	UniquePhoneScore        float64
	SMSFailedScore          float64
	OTPInvalidScore         float64
	OTPSuccessScore         float64
}

func (p Policy) WithDefaults() Policy {
	if p.Mode == "" {
		p.Mode = ModePassive
	}
	if p.Prefix == "" {
		p.Prefix = "dbk:v1"
	}
	if p.Thresholds.DelayScore <= 0 {
		p.Thresholds.DelayScore = 3
	}
	if p.Thresholds.ChallengeScore <= 0 {
		p.Thresholds.ChallengeScore = 6
	}
	if p.Thresholds.BlockScore <= 0 {
		p.Thresholds.BlockScore = 10
	}
	if p.CounterWindow <= 0 {
		p.CounterWindow = time.Minute
	}
	if p.UniqueWindow <= 0 {
		p.UniqueWindow = 15 * time.Minute
	}
	if p.ScoreTTL <= 0 {
		p.ScoreTTL = 24 * time.Hour
	}
	if p.Delay <= 0 {
		p.Delay = 500 * time.Millisecond
	}
	if p.MissingUserAgentScore == 0 {
		p.MissingUserAgentScore = 1
	}
	if p.MissingDeviceScore == 0 {
		p.MissingDeviceScore = 1
	}
	if p.SuspiciousAgentScore == 0 {
		p.SuspiciousAgentScore = 2
	}
	if p.InvalidContentTypeScore == 0 {
		p.InvalidContentTypeScore = 0.5
	}
	if p.IPVelocityScore == 0 {
		p.IPVelocityScore = 1
	}
	if p.PhoneVelocityScore == 0 {
		p.PhoneVelocityScore = 1
	}
	if p.UniquePhoneScore == 0 {
		p.UniquePhoneScore = 1.5
	}
	if p.SMSFailedScore == 0 {
		p.SMSFailedScore = 1
	}
	if p.OTPInvalidScore == 0 {
		p.OTPInvalidScore = 1
	}
	if p.OTPSuccessScore == 0 {
		p.OTPSuccessScore = -1.5
	}

	return p
}
