package main

import (
	"context"
	"ddone-server-auth/config"
	"ddone-server-auth/internal/adapters/cache"
	"ddone-server-auth/internal/adapters/database"
	"ddone-server-auth/internal/adapters/handler"
	"ddone-server-auth/internal/adapters/middleware"
	"ddone-server-auth/internal/adapters/repository"
	"ddone-server-auth/internal/adapters/sms"
	"ddone-server-auth/internal/adapters/token"
	appjwks "ddone-server-auth/internal/application/jwks"
	applogin "ddone-server-auth/internal/application/login"
	appotp "ddone-server-auth/internal/application/otp"
	apppassword "ddone-server-auth/internal/application/password"
	appregister "ddone-server-auth/internal/application/register"
	appsession "ddone-server-auth/internal/application/session"
	appsettings "ddone-server-auth/internal/application/settings"
	apptokenmanager "ddone-server-auth/internal/application/tokenmanager"
	"ddone-server-auth/internal/bootstrap/logging"
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

	if err := repository.Migrate(db); err != nil {
		logger.Fatal("failed to migrate database tables", zap.Error(err))
	}
	logger.Info("database tables migrated")

	wnvClient := dextools.WenovaAPI(cfg.WenovaAPI.Token)
	smsClient := sms.NewSMS(&wnvClient)
	userRepository := cache.NewCachedUserStore(
		redisClient,
		repository.NewUserRepository(db),
		cfg.Cache.UserTTL,
	)
	registerStore := cache.NewRegisterStore(redisClient)
	registerService := appregister.NewServiceWithSettings(userRepository, registerStore, smsClient, appregister.Settings{
		OTPPolicy: otpPolicyFromConfig(cfg.OTP.Register),
	})
	passwordResetStore := cache.NewPasswordResetStore(redisClient)
	signingKeyRepository := cache.NewCachedSigningKeyStore(
		redisClient,
		repository.NewSigningKeyRepository(db),
		cfg.Cache.SigningKeysTTL,
	)
	tokenRepository := cache.NewCachedTokenStore(
		redisClient,
		repository.NewTokenRepository(db),
	)
	loginSessionRepository := cache.NewCachedLoginSessionStore(
		redisClient,
		repository.NewLoginSessionRepository(db),
		cfg.Cache.UserSessionListTTL,
	)
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
	loginService := applogin.NewService(userRepository, tokenRepository, loginSessionRepository, jwksService, applogin.Settings{
		RefreshTokenTTL: cfg.Auth.RefreshTokenTTL,
		LoginSessionTTL: cfg.Auth.LoginSessionTTL,
	})
	passwordService := apppassword.NewServiceWithSettings(
		userRepository,
		passwordResetStore,
		smsClient,
		tokenRepository,
		loginSessionRepository,
		apppassword.Settings{
			OTPPolicy: otpPolicyFromConfig(cfg.OTP.PasswordReset),
		},
	)
	settingsService := appsettings.NewService(userRepository)
	sessionService := appsession.NewService(loginSessionRepository, userRepository, jwksService, appsession.Settings{
		LoginSessionTTL: cfg.Auth.LoginSessionTTL,
	})
	tokenManagerService := apptokenmanager.NewService(tokenRepository)
	loginHandler := handler.NewLoginHandler(loginService, handler.SessionCookieConfig{
		Name:     cfg.Auth.SessionCookieName,
		MaxAge:   cfg.Auth.EffectiveSessionCookieMaxAge(),
		Secure:   cfg.Auth.SessionCookieSecure,
		SameSite: sameSiteMode(cfg.Auth.SessionCookieSameSite),
	})
	sessionCookie := handler.SessionCookieConfig{
		Name:     cfg.Auth.SessionCookieName,
		MaxAge:   cfg.Auth.EffectiveSessionCookieMaxAge(),
		Secure:   cfg.Auth.SessionCookieSecure,
		SameSite: sameSiteMode(cfg.Auth.SessionCookieSameSite),
	}
	settingsHandler := handler.NewSettingsHandler(settingsService)
	sessionHandler := handler.NewSessionHandler(sessionService, sessionCookie)
	tokenManagerHandler := handler.NewTokenManagerHandler(tokenManagerService)
	passwordHandler := handler.NewPasswordHandler(passwordService)
	jwksHandler := handler.NewJWKSHandler(jwksService)

	httpServer := newHTTPServer(
		cfg,
		logger,
		registerService,
		loginHandler,
		settingsHandler,
		sessionHandler,
		tokenManagerHandler,
		passwordHandler,
		middleware.RequireAccessToken(jwksService),
		middleware.RequireSession(cfg.Auth.SessionCookieName, loginSessionRepository),
		jwksHandler,
	)

	return httpServer, func() {
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

func otpPolicyFromConfig(cfg config.OTPPolicyConfig) appotp.Policy {
	return appotp.Policy{
		TTL:                 cfg.TTL,
		PhoneWindow:         cfg.PhoneWindow,
		ResendCooldown:      cfg.ResendCooldown,
		VerifyAttemptWindow: cfg.VerifyAttemptWindow,
		MaxPhoneRequests:    cfg.MaxPhoneRequests,
		MaxResends:          cfg.MaxResends,
		MaxVerifyAttempts:   cfg.MaxVerifyAttempts,
	}
}
