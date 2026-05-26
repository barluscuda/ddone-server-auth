package main

import (
	"context"
	"ddone-server-auth/config"
	"ddone-server-auth/internal/adapters/handler"
	"ddone-server-auth/internal/adapters/middleware"
	appdexbotkiller "ddone-server-auth/internal/application/dexbotkiller"
	appregister "ddone-server-auth/internal/application/register"
	"errors"
	"fmt"
	"net/http"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"
)

func newHTTPServer(
	cfg *config.Config,
	logger *zap.Logger,
	registerService appregister.UseCase,
	loginHandler *handler.LoginHandler,
	settingsHandler *handler.SettingsHandler,
	sessionHandler *handler.SessionHandler,
	tokenManagerHandler *handler.TokenManagerHandler,
	passwordHandler *handler.PasswordHandler,
	requireAccessToken gin.HandlerFunc,
	requireSession gin.HandlerFunc,
	jwksHandler *handler.JWKSHandler,
	dexBotKillerHasher *appdexbotkiller.Hasher,
) *http.Server {
	if cfg.App.Debug {
		gin.SetMode(gin.DebugMode)
	} else {
		gin.SetMode(gin.ReleaseMode)
	}

	app := gin.New()
	if strings.EqualFold(cfg.App.ProxyPreset, "cloudflare") {
		app.RemoteIPHeaders = []string{"CF-Connecting-IP", "X-Forwarded-For", "X-Real-IP"}
	}
	if err := app.SetTrustedProxies(cfg.App.TrustedProxies); err != nil {
		logger.Fatal("invalid trusted proxy configuration", zap.Error(err), zap.Strings("trusted_proxies", cfg.App.TrustedProxies))
	}
	app.HandleMethodNotAllowed = true
	app.Use(
		middleware.RequestBodyLimit(middleware.BodyLimitConfig{
			MaxBytes: cfg.App.MaxRequestBodyBytes,
		}),
		middleware.CORS(middleware.CORSConfig{
			AllowedOrigins:   cfg.CORS.AllowedOrigins,
			AllowedMethods:   cfg.CORS.AllowedMethods,
			AllowedHeaders:   cfg.CORS.AllowedHeaders,
			ExposedHeaders:   cfg.CORS.ExposedHeaders,
			AllowCredentials: cfg.CORS.AllowCredentials,
			MaxAge:           cfg.CORS.MaxAge,
		}),
		middleware.Recovery(logger),
		middleware.RequestLogger(logger),
		middleware.RequireUserAgent(),
	)
	if cfg.DexBotKiller.Enabled && dexBotKillerHasher != nil {
		app.Use(middleware.ClientContext(middleware.ClientContextConfig{
			DeviceCookieName:     cfg.DexBotKiller.DeviceCookieName,
			DeviceCookieMaxAge:   cfg.DexBotKiller.DeviceCookieMaxAge,
			DeviceCookieSecure:   cfg.DexBotKiller.DeviceCookieSecure,
			DeviceCookieSameSite: sameSiteMode(cfg.DexBotKiller.DeviceCookieSameSite),
		}, *dexBotKillerHasher))
	}
	app.NoRoute(middleware.NoRoute())
	app.NoMethod(middleware.NoMethod())
	app.OPTIONS("/*path", func(c *gin.Context) {
		c.Status(http.StatusNoContent)
	})
	registerHandler := handler.NewRegisterHandler(registerService)
	registerRoutes(
		app,
		registerHandler,
		loginHandler,
		settingsHandler,
		sessionHandler,
		tokenManagerHandler,
		passwordHandler,
		requireAccessToken,
		requireSession,
		jwksHandler,
	)

	return &http.Server{
		Addr:              fmt.Sprintf(":%d", cfg.App.Port),
		Handler:           app,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      15 * time.Second,
		IdleTimeout:       60 * time.Second,
		MaxHeaderBytes:    http.DefaultMaxHeaderBytes,
	}
}

func run(server *http.Server, logger *zap.Logger) {
	logger.Info(
		"starting http server",
		zap.String("addr", server.Addr),
		zap.String("mode", gin.Mode()),
	)

	go func() {
		if err := server.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			logger.Fatal("http server stopped unexpectedly", zap.Error(err))
		}
	}()

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	<-ctx.Done()
	logger.Info("shutdown signal received")

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	if err := server.Shutdown(shutdownCtx); err != nil {
		logger.Fatal("failed to shutdown server gracefully", zap.Error(err))
	}

	logger.Info("server stopped")
}

func registerRoutes(
	router *gin.Engine,
	registerHandler *handler.RegisterHandler,
	loginHandler *handler.LoginHandler,
	settingsHandler *handler.SettingsHandler,
	sessionHandler *handler.SessionHandler,
	tokenManagerHandler *handler.TokenManagerHandler,
	passwordHandler *handler.PasswordHandler,
	requireAccessToken gin.HandlerFunc,
	requireSession gin.HandlerFunc,
	jwksHandler *handler.JWKSHandler,
) {
	router.GET("/healthz", handler.Healthz)
	router.GET("/robots.txt", handler.RobotsTXT)
	router.GET("/.well-known/jwks.json", jwksHandler.PublicJWKS)

	publicAuthRoutes := router.Group("")
	publicAuthRoutes.POST("/registrations", registerHandler.Register)
	publicAuthRoutes.POST("/registrations/resend", registerHandler.ResendOTP)
	publicAuthRoutes.POST("/registrations/verify", registerHandler.VerifyRegister)
	publicAuthRoutes.POST("/tokens", loginHandler.Login)
	publicAuthRoutes.POST("/tokens/refresh", loginHandler.Refresh)
	publicAuthRoutes.POST("/sessions", loginHandler.LoginSession)
	publicAuthRoutes.POST("/password-resets", passwordHandler.ForgotPassword)
	publicAuthRoutes.POST("/password-resets/resend", passwordHandler.ResendForgotPassword)
	publicAuthRoutes.POST("/password-resets/verify", passwordHandler.VerifyForgotPassword)

	settingsRoutes := router.Group("/settings")
	settingsRoutes.Use(requireAccessToken)
	settingsRoutes.GET("", settingsHandler.GetMe)
	settingsRoutes.GET("/me", settingsHandler.GetMe)
	settingsRoutes.PATCH("/username", settingsHandler.PatchUsername)
	settingsRoutes.POST("/password", passwordHandler.ChangePassword)

	tokenRoutes := router.Group("/tokens")
	tokenRoutes.Use(requireAccessToken)
	tokenRoutes.GET("", tokenManagerHandler.List)
	tokenRoutes.POST("/revoke-all", tokenManagerHandler.RevokeAll)
	tokenRoutes.DELETE("/:tokenId", tokenManagerHandler.Revoke)

	sessionRoutes := router.Group("/sessions")
	sessionRoutes.Use(requireSession)
	sessionRoutes.POST("/token", sessionHandler.Token)
	sessionRoutes.GET("", sessionHandler.List)
	sessionRoutes.GET("/current", sessionHandler.Current)
	sessionRoutes.POST("/revoke-others", sessionHandler.RevokeOthers)
	sessionRoutes.POST("/revoke-all", sessionHandler.RevokeAll)
	sessionRoutes.DELETE("/:sessionId", sessionHandler.Revoke)
}
