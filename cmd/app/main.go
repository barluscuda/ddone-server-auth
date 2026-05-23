package main

import (
	"context"
	"ddone-server-auth/config"
	"ddone-server-auth/internal/adapters/cache"
	"ddone-server-auth/internal/adapters/database"
	"ddone-server-auth/internal/adapters/handler"
	"ddone-server-auth/internal/adapters/repository"
	"ddone-server-auth/internal/adapters/sms"
	"ddone-server-auth/internal/adapters/token"
	appjwks "ddone-server-auth/internal/application/jwks"
	applogin "ddone-server-auth/internal/application/login"
	appregister "ddone-server-auth/internal/application/register"
	"ddone-server-auth/internal/bootstrap/logging"
	"ddone-server-auth/internal/domain/account"
	"net/http"
	"strings"

	"github.com/barluscuda/dextools"
	"go.uber.org/zap"
)

func main() {
	cfg, err := config.Load()
	if err != nil {
		panic(err)
	}

	logger, err := logging.New(cfg.App.Debug)
	if err != nil {
		panic(err)
	}
	defer syncLogger(logger)

	httpServer, cleanup := bootstrapApplication(cfg, logger)
	defer cleanup()

	run(httpServer, logger)
}

func bootstrapApplication(cfg *config.Config, logger *zap.Logger) (*http.Server, func()) {
	db, err := database.New(cfg.Database)
	if err != nil {
		logger.Fatal("failed to connect database", zap.Error(err))
	}
	logger.Info("connected to database")

	redisClient, err := cache.New(cfg.Redis, cfg.App.Debug)
	if err != nil {
		logger.Fatal("failed to connect redis", zap.Error(err))
	}
	logger.Info("connected to redis")

	if err := account.Migrate(db); err != nil {
		logger.Fatal("failed to migrate account tables", zap.Error(err))
	}
	logger.Info("account tables migrated")
	if err := repository.MigrateAuth(db); err != nil {
		logger.Fatal("failed to migrate auth tables", zap.Error(err))
	}
	logger.Info("auth tables migrated")

	wnvClient := dextools.WenovaAPI(cfg.WenovaAPI.Token)
	smsClient := sms.NewSMS(&wnvClient)
	accountRepository := repository.NewAccountRepository(db)
	registerStore := cache.NewRegisterStore(redisClient)
	registerService := appregister.NewRegisterService(accountRepository, registerStore, smsClient)
	signingKeyRepository := repository.NewSigningKeyRepository(db)
	refreshSessionRepository := repository.NewRefreshSessionRepository(db)
	tokenCodec := token.NewES256Codec()
	jwksService := appjwks.NewService(signingKeyRepository, tokenCodec, appjwks.Settings{
		Issuer:              cfg.Auth.Issuer,
		Audience:            cfg.Auth.Audience,
		AccessTokenTTL:      cfg.Auth.AccessTokenTTL,
		SigningKeyRotation:  cfg.Auth.SigningKeyRotation,
		SigningKeyRetention: cfg.Auth.SigningKeyRetention,
	})
	if _, err := jwksService.EnsureActiveSigningKey(context.Background()); err != nil {
		logger.Fatal("failed to ensure active signing key", zap.Error(err))
	}
	loginService := applogin.NewService(accountRepository, refreshSessionRepository, jwksService, applogin.Settings{
		RefreshTokenTTL: cfg.Auth.RefreshTokenTTL,
	})
	loginHandler := handler.NewLoginHandler(loginService, handler.RefreshCookieConfig{
		Name:     cfg.Auth.RefreshCookieName,
		MaxAge:   cfg.Auth.RefreshTokenTTL,
		Secure:   cfg.Auth.RefreshCookieSecure,
		SameSite: sameSiteMode(cfg.Auth.RefreshCookieSameSite),
	})
	jwksHandler := handler.NewJWKSHandler(jwksService)

	return newHTTPServer(cfg, logger, registerService, loginHandler, jwksHandler), func() {
		if err := redisClient.Close(); err != nil {
			logger.Warn("failed to close redis client", zap.Error(err))
		}
	}
}

func syncLogger(logger *zap.Logger) {
	_ = logger.Sync()
}

func sameSiteMode(raw string) http.SameSite {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "strict":
		return http.SameSiteStrictMode
	case "none":
		return http.SameSiteNoneMode
	default:
		return http.SameSiteLaxMode
	}
}
