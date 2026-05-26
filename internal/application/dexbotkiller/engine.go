package dexbotkiller

import (
	"context"
	"time"
)

type Engine struct {
	store  Store
	policy Policy
	keys   KeyBuilder
	now    func() time.Time
}

func NewEngine(store Store, policy Policy, hasher Hasher) *Engine {
	if store == nil {
		store = NoopStore{}
	}
	policy = policy.WithDefaults()

	return &Engine{
		store:  store,
		policy: policy,
		keys:   NewKeyBuilder(policy.Prefix, hasher),
		now:    func() time.Time { return time.Now().UTC() },
	}
}

func (e *Engine) Evaluate(ctx context.Context, req Request) (*Decision, error) {
	req = e.requestWithDefaults(req)

	decision := &Decision{Action: ActionAllow}
	for _, signal := range clientQualitySignals(req, e.policy) {
		decision.RiskScore += signal.score
		decision.Reasons = append(decision.Reasons, signal.reason)
	}

	if req.Client.IP != "" {
		count, err := e.store.IncrementCounter(
			ctx,
			e.keys.Counter(req.Flow, req.Action, "ip", req.Client.IP, e.policy.CounterWindow),
			e.policy.CounterWindow,
		)
		if err != nil {
			return nil, err
		}
		if count > 5 {
			decision.RiskScore += e.policy.IPVelocityScore
			decision.Reasons = append(decision.Reasons, "ip_high_velocity")
		}
		ipScore, err := e.store.GetScore(ctx, e.keys.Score("ip", req.Client.IP))
		if err != nil {
			return nil, err
		}
		decision.RiskScore += ipScore
	}

	if req.PhoneNumber != "" {
		count, err := e.store.IncrementCounter(
			ctx,
			e.keys.Counter(req.Flow, req.Action, "phone", req.PhoneNumber, e.policy.CounterWindow),
			e.policy.CounterWindow,
		)
		if err != nil {
			return nil, err
		}
		if count > 2 {
			decision.RiskScore += e.policy.PhoneVelocityScore
			decision.Reasons = append(decision.Reasons, "phone_high_velocity")
		}
		phoneScore, err := e.store.GetScore(ctx, e.keys.Score("phone", req.PhoneNumber))
		if err != nil {
			return nil, err
		}
		decision.RiskScore += phoneScore
	}

	if req.Client.IP != "" && req.PhoneNumber != "" {
		key := e.keys.Unique(req.Flow, req.Action, "ip", req.Client.IP, "phone", e.policy.UniqueWindow)
		if err := e.store.AddUnique(ctx, key, e.keys.Member(req.PhoneNumber), e.policy.UniqueWindow); err != nil {
			return nil, err
		}
		uniquePhoneCount, err := e.store.UniqueCount(ctx, key)
		if err != nil {
			return nil, err
		}
		if uniquePhoneCount > 3 {
			decision.RiskScore += e.policy.UniquePhoneScore
			decision.Reasons = append(decision.Reasons, "ip_many_phone_targets")
		}
	}

	decision.Action = e.actionForScore(decision.RiskScore)
	if decision.Action == ActionDelay {
		decision.RetryAfter = e.policy.Delay
	}
	if decision.Action == ActionChallenge {
		decision.Challenge = e.policy.Challenge
	}
	if e.policy.Mode == ModePassive {
		decision.Action = ActionAllow
		decision.RetryAfter = 0
		decision.Challenge = Challenge{}
	}

	return decision, nil
}

func (e *Engine) Record(ctx context.Context, event Event) error {
	req := e.requestWithDefaults(event.Request)
	switch event.Outcome {
	case OutcomeSMSSendFailed:
		return e.incrementScores(ctx, req, e.policy.SMSFailedScore)
	case OutcomeOTPInvalid:
		return e.incrementScores(ctx, req, e.policy.OTPInvalidScore)
	case OutcomeOTPSuccess:
		return e.incrementScores(ctx, req, e.policy.OTPSuccessScore)
	default:
		return nil
	}
}

func (e *Engine) requestWithDefaults(req Request) Request {
	if req.Timestamp.IsZero() {
		req.Timestamp = e.now()
	}
	if req.Client.Timestamp.IsZero() {
		req.Client.Timestamp = req.Timestamp
	}

	return req
}

func (e *Engine) actionForScore(score float64) Action {
	switch {
	case score >= e.policy.Thresholds.BlockScore:
		if e.policy.Mode == ModeEnforce {
			return ActionBlock
		}
		if e.policy.Mode == ModeChallenge {
			return ActionChallenge
		}
		if e.policy.Mode == ModeDelay {
			return ActionDelay
		}
	case score >= e.policy.Thresholds.ChallengeScore:
		if e.policy.Mode == ModeChallenge || e.policy.Mode == ModeEnforce {
			return ActionChallenge
		}
		if e.policy.Mode == ModeDelay {
			return ActionDelay
		}
	case score >= e.policy.Thresholds.DelayScore:
		if e.policy.Mode == ModeDelay || e.policy.Mode == ModeChallenge || e.policy.Mode == ModeEnforce {
			return ActionDelay
		}
	}

	return ActionAllow
}

func (e *Engine) incrementScores(ctx context.Context, req Request, delta float64) error {
	if req.Client.IP != "" {
		if _, err := e.store.IncrementScore(ctx, e.keys.Score("ip", req.Client.IP), delta, e.policy.ScoreTTL); err != nil {
			return err
		}
	}
	if req.Client.DeviceID != "" {
		if _, err := e.store.IncrementScore(ctx, e.keys.Score("device", req.Client.DeviceID), delta, e.policy.ScoreTTL); err != nil {
			return err
		}
	}
	if req.PhoneNumber != "" {
		if _, err := e.store.IncrementScore(ctx, e.keys.Score("phone", req.PhoneNumber), delta, e.policy.ScoreTTL); err != nil {
			return err
		}
	}

	return nil
}
