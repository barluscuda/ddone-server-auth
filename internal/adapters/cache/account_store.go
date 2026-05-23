package cache

import (
	"context"
	applogin "ddone-server-auth/internal/application/login"
	apppassword "ddone-server-auth/internal/application/password"
	appregister "ddone-server-auth/internal/application/register"
	appsettings "ddone-server-auth/internal/application/settings"
	"ddone-server-auth/internal/domain/account"
	"time"

	"github.com/redis/go-redis/v9"
)

type accountStoreBackend interface {
	appregister.AccountStore
	applogin.AccountLookup
	appsettings.AccountReader
	Update(ctx context.Context, accountModel *account.AccountModel) error
	Delete(ctx context.Context, id string) error
}

type CachedAccountStore struct {
	next  accountStoreBackend
	cache jsonCache
	ttl   time.Duration
}

var _ appregister.AccountStore = (*CachedAccountStore)(nil)
var _ applogin.AccountLookup = (*CachedAccountStore)(nil)
var _ appsettings.AccountReader = (*CachedAccountStore)(nil)
var _ apppassword.AccountStore = (*CachedAccountStore)(nil)

func NewCachedAccountStore(
	client *redis.Client,
	next accountStoreBackend,
	ttl time.Duration,
) *CachedAccountStore {
	return &CachedAccountStore{
		next:  next,
		cache: newJSONCache(client),
		ttl:   ttl,
	}
}

func (s *CachedAccountStore) Create(ctx context.Context, accountModel *account.AccountModel) error {
	if err := s.next.Create(ctx, accountModel); err != nil {
		return err
	}

	s.cacheAccount(ctx, accountModel)
	return nil
}

func (s *CachedAccountStore) GetByID(ctx context.Context, id string) (*account.AccountModel, error) {
	if s.ttl > 0 {
		var cached account.AccountModel
		if s.cache.get(ctx, accountByIDKey(id), &cached) {
			return &cached, nil
		}
	}

	accountModel, err := s.next.GetByID(ctx, id)
	if err != nil {
		return nil, err
	}

	s.cacheAccount(ctx, accountModel)
	return accountModel, nil
}

func (s *CachedAccountStore) GetByPhoneNumber(
	ctx context.Context,
	phoneNumber string,
) (*account.AccountModel, error) {
	if s.ttl > 0 {
		var cached account.AccountModel
		if s.cache.get(ctx, accountByPhoneKey(phoneNumber), &cached) {
			return &cached, nil
		}
	}

	accountModel, err := s.next.GetByPhoneNumber(ctx, phoneNumber)
	if err != nil {
		return nil, err
	}

	s.cacheAccount(ctx, accountModel)
	return accountModel, nil
}

func (s *CachedAccountStore) GetByUsername(ctx context.Context, username string) (*account.AccountModel, error) {
	if s.ttl > 0 {
		var cached account.AccountModel
		if s.cache.get(ctx, accountByUsernameKey(username), &cached) {
			return &cached, nil
		}
	}

	accountModel, err := s.next.GetByUsername(ctx, username)
	if err != nil {
		return nil, err
	}

	s.cacheAccount(ctx, accountModel)
	return accountModel, nil
}

func (s *CachedAccountStore) Update(ctx context.Context, accountModel *account.AccountModel) error {
	existing, _ := s.next.GetByID(ctx, accountModel.ID)

	if err := s.next.Update(ctx, accountModel); err != nil {
		return err
	}

	s.invalidateAccount(ctx, existing)
	s.cacheAccount(ctx, accountModel)
	return nil
}

func (s *CachedAccountStore) Delete(ctx context.Context, id string) error {
	existing, _ := s.next.GetByID(ctx, id)

	if err := s.next.Delete(ctx, id); err != nil {
		return err
	}

	s.invalidateAccount(ctx, existing)
	s.cache.delete(ctx, accountByIDKey(id))
	return nil
}

func (s *CachedAccountStore) cacheAccount(ctx context.Context, accountModel *account.AccountModel) {
	if accountModel == nil || s.ttl <= 0 {
		return
	}

	s.cache.set(ctx, accountByIDKey(accountModel.ID), accountModel, s.ttl)
	s.cache.set(ctx, accountByPhoneKey(accountModel.PhoneNumber), accountModel, s.ttl)
	if accountModel.Username != nil {
		s.cache.set(ctx, accountByUsernameKey(*accountModel.Username), accountModel, s.ttl)
	}
}

func (s *CachedAccountStore) invalidateAccount(ctx context.Context, accountModel *account.AccountModel) {
	if accountModel == nil {
		return
	}

	keys := []string{
		accountByIDKey(accountModel.ID),
		accountByPhoneKey(accountModel.PhoneNumber),
	}
	if accountModel.Username != nil {
		keys = append(keys, accountByUsernameKey(*accountModel.Username))
	}

	s.cache.delete(ctx, keys...)
}

func accountByIDKey(id string) string {
	return "cache:account:id:" + id
}

func accountByPhoneKey(phoneNumber string) string {
	return "cache:account:phone:" + phoneNumber
}

func accountByUsernameKey(username string) string {
	return "cache:account:username:" + username
}
