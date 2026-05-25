package main

import (
	"context"
	"ddone-server-auth/config"
	"ddone-server-auth/internal/adapters/handler"
	"ddone-server-auth/internal/adapters/middleware"
	appregister "ddone-server-auth/internal/application/register"
	"errors"
	"fmt"
	"net/http"
	"os/signal"
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
	otpSpamDetection gin.HandlerFunc,
	jwksHandler *handler.JWKSHandler,
) *http.Server {
	if cfg.App.Debug {
		gin.SetMode(gin.DebugMode)
	} else {
		gin.SetMode(gin.ReleaseMode)
	}

	app := gin.New()
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
	)
	app.NoRoute(middleware.NoRoute())
	app.NoMethod(middleware.NoMethod())
	app.OPTIONS("/*path", func(c *gin.Context) {
		c.Status(http.StatusNoContent)
	})
	registerHandler := handler.NewRegisterHandler(registerService)
	botProtection := middleware.BotProtection(middleware.BotProtectionConfig{
		Enabled:       cfg.Security.Bot.Enabled,
		Window:        cfg.Security.Bot.Window,
		MaxRequests:   cfg.Security.Bot.MaxRequests,
		BlockDuration: cfg.Security.Bot.BlockDuration,
	})

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
		botProtection,
		otpSpamDetection,
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
	botProtection gin.HandlerFunc,
	otpSpamDetection gin.HandlerFunc,
	jwksHandler *handler.JWKSHandler,
) {
	router.GET("/healthz", handler.Healthz)
	router.GET("/robots.txt", handler.RobotsTXT)
	router.GET("/.well-known/jwks.json", jwksHandler.PublicJWKS)

	publicAuthRoutes := router.Group("")
	publicAuthRoutes.Use(botProtection)
	publicAuthRoutes.POST("/registrations", otpSpamDetection, registerHandler.Register)
	publicAuthRoutes.POST("/registrations/resend", otpSpamDetection, registerHandler.ResendOTP)
	publicAuthRoutes.POST("/registrations/verify", otpSpamDetection, registerHandler.VerifyRegister)
	publicAuthRoutes.POST("/tokens", loginHandler.Login)
	publicAuthRoutes.POST("/tokens/refresh", loginHandler.Refresh)
	publicAuthRoutes.POST("/sessions", loginHandler.LoginSession)
	publicAuthRoutes.POST("/password-resets", otpSpamDetection, passwordHandler.ForgotPassword)
	publicAuthRoutes.POST("/password-resets/resend", otpSpamDetection, passwordHandler.ResendForgotPassword)
	publicAuthRoutes.POST("/password-resets/verify", otpSpamDetection, passwordHandler.VerifyForgotPassword)

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
