package cache

import (
	"context"
	applogin "ddone-server-auth/internal/application/login"
	apppassword "ddone-server-auth/internal/application/password"
	appregister "ddone-server-auth/internal/application/register"
	appsettings "ddone-server-auth/internal/application/settings"
	"ddone-server-auth/internal/domain/user"
	"time"

	"github.com/redis/go-redis/v9"
)

type userStoreBackend interface {
	appregister.UserStore
	applogin.UserLookup
	appsettings.UserReader
	Update(ctx context.Context, userModel *user.UserModel) error
	Delete(ctx context.Context, id string) error
}

type CachedUserStore struct {
	next  userStoreBackend
	cache jsonCache
	ttl   time.Duration
}

var _ appregister.UserStore = (*CachedUserStore)(nil)
var _ applogin.UserLookup = (*CachedUserStore)(nil)
var _ appsettings.UserReader = (*CachedUserStore)(nil)
var _ apppassword.UserStore = (*CachedUserStore)(nil)

func NewCachedUserStore(
	client *redis.Client,
	next userStoreBackend,
	ttl time.Duration,
) *CachedUserStore {
	return &CachedUserStore{
		next:  next,
		cache: newJSONCache(client),
		ttl:   ttl,
	}
}

func (s *CachedUserStore) Create(ctx context.Context, userModel *user.UserModel) error {
	if err := s.next.Create(ctx, userModel); err != nil {
		return err
	}

	s.cacheUser(ctx, userModel)
	return nil
}

func (s *CachedUserStore) GetByID(ctx context.Context, id string) (*user.UserModel, error) {
	if s.ttl > 0 {
		var cached user.UserModel
		if s.cache.get(ctx, userByIDKey(id), &cached) {
			return &cached, nil
		}
	}

	userModel, err := s.next.GetByID(ctx, id)
	if err != nil {
		return nil, err
	}

	s.cacheUser(ctx, userModel)
	return userModel, nil
}

func (s *CachedUserStore) GetByPhoneNumber(
	ctx context.Context,
	phoneNumber string,
) (*user.UserModel, error) {
	if s.ttl > 0 {
		var cached user.UserModel
		if s.cache.get(ctx, userByPhoneKey(phoneNumber), &cached) {
			return &cached, nil
		}
	}

	userModel, err := s.next.GetByPhoneNumber(ctx, phoneNumber)
	if err != nil {
		return nil, err
	}

	s.cacheUser(ctx, userModel)
	return userModel, nil
}

func (s *CachedUserStore) GetByUsername(ctx context.Context, username string) (*user.UserModel, error) {
	if s.ttl > 0 {
		var cached user.UserModel
		if s.cache.get(ctx, userByUsernameKey(username), &cached) {
			return &cached, nil
		}
	}

	userModel, err := s.next.GetByUsername(ctx, username)
	if err != nil {
		return nil, err
	}

	s.cacheUser(ctx, userModel)
	return userModel, nil
}

func (s *CachedUserStore) Update(ctx context.Context, userModel *user.UserModel) error {
	existing, _ := s.next.GetByID(ctx, userModel.ID)

	if err := s.next.Update(ctx, userModel); err != nil {
		return err
	}

	s.invalidateUser(ctx, existing)
	s.cacheUser(ctx, userModel)
	return nil
}

func (s *CachedUserStore) Delete(ctx context.Context, id string) error {
	existing, _ := s.next.GetByID(ctx, id)

	if err := s.next.Delete(ctx, id); err != nil {
		return err
	}

	s.invalidateUser(ctx, existing)
	s.cache.delete(ctx, userByIDKey(id))
	return nil
}

func (s *CachedUserStore) cacheUser(ctx context.Context, userModel *user.UserModel) {
	if userModel == nil || s.ttl <= 0 {
		return
	}

	s.cache.set(ctx, userByIDKey(userModel.ID), userModel, s.ttl)
	s.cache.set(ctx, userByPhoneKey(userModel.PhoneNumber), userModel, s.ttl)
	if userModel.Username != nil {
		s.cache.set(ctx, userByUsernameKey(*userModel.Username), userModel, s.ttl)
	}
}

func (s *CachedUserStore) invalidateUser(ctx context.Context, userModel *user.UserModel) {
	if userModel == nil {
		return
	}

	keys := []string{
		userByIDKey(userModel.ID),
		userByPhoneKey(userModel.PhoneNumber),
	}
	if userModel.Username != nil {
		keys = append(keys, userByUsernameKey(*userModel.Username))
	}

	s.cache.delete(ctx, keys...)
}

func userByIDKey(id string) string {
	return "cache:user:id:" + id
}

func userByPhoneKey(phoneNumber string) string {
	return "cache:user:phone:" + phoneNumber
}

func userByUsernameKey(username string) string {
	return "cache:user:username:" + username
}
