package cache

import (
	"context"
	appjwks "ddone-server-auth/internal/application/jwks"
	"ddone-server-auth/internal/domain/auth"
	"time"

	"github.com/redis/go-redis/v9"
)

type signingKeyCacheBypassKey struct{}

type CachedSigningKeyStore struct {
	next  appjwks.SigningKeyStore
	cache jsonCache
	ttl   time.Duration
}

var _ appjwks.SigningKeyStore = (*CachedSigningKeyStore)(nil)

func NewCachedSigningKeyStore(
	client *redis.Client,
	next appjwks.SigningKeyStore,
	ttl time.Duration,
) *CachedSigningKeyStore {
	return &CachedSigningKeyStore{
		next:  next,
		cache: newJSONCache(client),
		ttl:   ttl,
	}
}

func (s *CachedSigningKeyStore) Create(ctx context.Context, key *auth.SigningKey) error {
	if err := s.next.Create(ctx, key); err != nil {
		return err
	}

	s.invalidate(ctx)
	return nil
}

func (s *CachedSigningKeyStore) ListPublicKeys(
	ctx context.Context,
	now time.Time,
) ([]auth.SigningKey, error) {
	if s.shouldBypass(ctx) || s.ttl <= 0 {
		return s.next.ListPublicKeys(ctx, now)
	}

	var cached []auth.SigningKey
	if s.cache.get(ctx, signingKeysCacheKey(), &cached) {
		return cached, nil
	}

	keys, err := s.next.ListPublicKeys(ctx, now)
	if err != nil {
		return nil, err
	}

	s.cache.set(ctx, signingKeysCacheKey(), keys, s.ttl)
	return keys, nil
}

func (s *CachedSigningKeyStore) DeleteExpired(ctx context.Context, now time.Time) error {
	if err := s.next.DeleteExpired(ctx, now); err != nil {
		return err
	}

	s.invalidate(ctx)
	return nil
}

func (s *CachedSigningKeyStore) WithRotationLock(
	ctx context.Context,
	fn func(context.Context) error,
) error {
	err := s.next.WithRotationLock(ctx, func(lockCtx context.Context) error {
		return fn(context.WithValue(lockCtx, signingKeyCacheBypassKey{}, true))
	})
	if err != nil {
		return err
	}

	s.invalidate(ctx)
	return nil
}

func (s *CachedSigningKeyStore) shouldBypass(ctx context.Context) bool {
	bypass, _ := ctx.Value(signingKeyCacheBypassKey{}).(bool)
	return bypass
}

func (s *CachedSigningKeyStore) invalidate(ctx context.Context) {
	s.cache.delete(ctx, signingKeysCacheKey())
}

func signingKeysCacheKey() string {
	return "cache:signing_keys:all"
}
