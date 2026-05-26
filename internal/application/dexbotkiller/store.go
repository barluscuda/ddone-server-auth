package dexbotkiller

import (
	"context"
	"time"
)

type Store interface {
	IncrementCounter(ctx context.Context, key string, ttl time.Duration) (int64, error)
	GetCounter(ctx context.Context, key string) (int64, error)
	AddUnique(ctx context.Context, key string, member string, ttl time.Duration) error
	UniqueCount(ctx context.Context, key string) (int64, error)
	IncrementScore(ctx context.Context, key string, delta float64, ttl time.Duration) (float64, error)
	GetScore(ctx context.Context, key string) (float64, error)
}

type NoopStore struct{}

func (NoopStore) IncrementCounter(context.Context, string, time.Duration) (int64, error) {
	return 0, nil
}
func (NoopStore) GetCounter(context.Context, string) (int64, error)              { return 0, nil }
func (NoopStore) AddUnique(context.Context, string, string, time.Duration) error { return nil }
func (NoopStore) UniqueCount(context.Context, string) (int64, error)             { return 0, nil }
func (NoopStore) IncrementScore(context.Context, string, float64, time.Duration) (float64, error) {
	return 0, nil
}
func (NoopStore) GetScore(context.Context, string) (float64, error) { return 0, nil }
