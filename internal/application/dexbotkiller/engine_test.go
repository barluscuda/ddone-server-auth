package dexbotkiller

import (
	"context"
	"testing"
	"time"
)

func TestEvaluatePassiveModeOnlyObservesRisk(t *testing.T) {
	store := newMemoryStore()
	hasher, err := NewHasher("test-pepper")
	if err != nil {
		t.Fatalf("new hasher: %v", err)
	}
	engine := NewEngine(store, Policy{
		Mode: ModePassive,
		Thresholds: Thresholds{
			DelayScore:     1,
			ChallengeScore: 2,
			BlockScore:     3,
		},
	}, hasher)

	decision, err := engine.Evaluate(context.Background(), Request{
		Flow:   FlowRegister,
		Action: FlowActionStart,
		Client: ClientContext{},
	})
	if err != nil {
		t.Fatalf("evaluate: %v", err)
	}

	if decision.RiskScore == 0 {
		t.Fatal("expected missing client signals to add risk")
	}
	if decision.Action != ActionAllow {
		t.Fatalf("expected passive mode to allow, got %q", decision.Action)
	}
}

func TestRecordUpdatesOutcomeRisk(t *testing.T) {
	store := newMemoryStore()
	hasher, err := NewHasher("test-pepper")
	if err != nil {
		t.Fatalf("new hasher: %v", err)
	}
	engine := NewEngine(store, Policy{Mode: ModePassive}, hasher)

	req := Request{
		Flow:        FlowRegister,
		Action:      FlowActionVerify,
		PhoneNumber: "+8562012345678",
		Client: ClientContext{
			IP:       "192.0.2.10",
			DeviceID: "device-id",
		},
	}
	if err := engine.Record(context.Background(), Event{Request: req, Outcome: OutcomeOTPInvalid}); err != nil {
		t.Fatalf("record: %v", err)
	}

	ipScore, err := store.GetScore(context.Background(), engine.keys.Score("ip", req.Client.IP))
	if err != nil {
		t.Fatalf("get ip score: %v", err)
	}
	if ipScore <= 0 {
		t.Fatalf("expected positive ip score, got %v", ipScore)
	}
}

func TestEvaluateChallengeModeReturnsChallengeMetadata(t *testing.T) {
	store := newMemoryStore()
	hasher, err := NewHasher("test-pepper")
	if err != nil {
		t.Fatalf("new hasher: %v", err)
	}
	engine := NewEngine(store, Policy{
		Mode: ModeChallenge,
		Thresholds: Thresholds{
			DelayScore:     1,
			ChallengeScore: 2,
			BlockScore:     3,
		},
		Challenge: Challenge{
			Provider: ChallengeProviderCloudflareTurnstile,
			SiteKey:  "site-key",
		},
	}, hasher)

	decision, err := engine.Evaluate(context.Background(), Request{
		Flow:   FlowRegister,
		Action: FlowActionStart,
		Client: ClientContext{},
	})
	if err != nil {
		t.Fatalf("evaluate: %v", err)
	}

	if decision.Action != ActionChallenge {
		t.Fatalf("expected challenge action, got %q", decision.Action)
	}
	if decision.Challenge.Provider != ChallengeProviderCloudflareTurnstile {
		t.Fatalf("expected cloudflare turnstile provider, got %q", decision.Challenge.Provider)
	}
	if decision.Challenge.SiteKey != "site-key" {
		t.Fatalf("expected site key, got %q", decision.Challenge.SiteKey)
	}
}

func TestEvaluateDelayModeDoesNotEscalateToChallenge(t *testing.T) {
	store := newMemoryStore()
	hasher, err := NewHasher("test-pepper")
	if err != nil {
		t.Fatalf("new hasher: %v", err)
	}
	engine := NewEngine(store, Policy{
		Mode: ModeDelay,
		Thresholds: Thresholds{
			DelayScore:     1,
			ChallengeScore: 2,
			BlockScore:     3,
		},
	}, hasher)

	decision, err := engine.Evaluate(context.Background(), Request{
		Flow:   FlowRegister,
		Action: FlowActionStart,
		Client: ClientContext{},
	})
	if err != nil {
		t.Fatalf("evaluate: %v", err)
	}

	if decision.Action != ActionDelay {
		t.Fatalf("expected delay action, got %q", decision.Action)
	}
	if decision.Challenge.Provider != "" {
		t.Fatalf("expected no challenge metadata, got %#v", decision.Challenge)
	}
}

type memoryStore struct {
	counters map[string]int64
	sets     map[string]map[string]struct{}
	scores   map[string]float64
}

func newMemoryStore() *memoryStore {
	return &memoryStore{
		counters: map[string]int64{},
		sets:     map[string]map[string]struct{}{},
		scores:   map[string]float64{},
	}
}

func (s *memoryStore) IncrementCounter(_ context.Context, key string, _ time.Duration) (int64, error) {
	s.counters[key]++
	return s.counters[key], nil
}

func (s *memoryStore) GetCounter(_ context.Context, key string) (int64, error) {
	return s.counters[key], nil
}

func (s *memoryStore) AddUnique(_ context.Context, key string, member string, _ time.Duration) error {
	if s.sets[key] == nil {
		s.sets[key] = map[string]struct{}{}
	}
	s.sets[key][member] = struct{}{}
	return nil
}

func (s *memoryStore) UniqueCount(_ context.Context, key string) (int64, error) {
	return int64(len(s.sets[key])), nil
}

func (s *memoryStore) IncrementScore(_ context.Context, key string, delta float64, _ time.Duration) (float64, error) {
	s.scores[key] += delta
	return s.scores[key], nil
}

func (s *memoryStore) GetScore(_ context.Context, key string) (float64, error) {
	return s.scores[key], nil
}
