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
	accountManagerHandler *handler.AccountManagerHandler,
	passwordHandler *handler.PasswordHandler,
	requireAccessToken gin.HandlerFunc,
	jwksHandler *handler.JWKSHandler,
) *http.Server {
	if cfg.App.Debug {
		gin.SetMode(gin.DebugMode)
	} else {
		gin.SetMode(gin.ReleaseMode)
	}

	app := gin.New()
	app.HandleMethodNotAllowed = true
	app.Use(
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

	registerRoutes(app, registerHandler, loginHandler, accountManagerHandler, passwordHandler, requireAccessToken, jwksHandler)

	return &http.Server{
		Addr:              fmt.Sprintf(":%d", cfg.App.Port),
		Handler:           app,
		ReadHeaderTimeout: 5 * time.Second,
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
	router gin.IRoutes,
	registerHandler *handler.RegisterHandler,
	loginHandler *handler.LoginHandler,
	accountManagerHandler *handler.AccountManagerHandler,
	passwordHandler *handler.PasswordHandler,
	requireAccessToken gin.HandlerFunc,
	jwksHandler *handler.JWKSHandler,
) {
	router.GET("/healthz", handler.Healthz)
	router.POST("/register", registerHandler.Register)
	router.POST("/register/resend", registerHandler.ResendOTP)
	router.POST("/register/verify", registerHandler.VerifyRegister)
	router.POST("/login", loginHandler.Login)
	router.POST("/login/refresh", loginHandler.Refresh)
	router.POST("/login/session", loginHandler.LoginSession)
	router.POST("/login/session/token", loginHandler.SessionToken)
	router.POST("/password/forgot", passwordHandler.ForgotPassword)
	router.POST("/password/forgot/resend", passwordHandler.ResendForgotPassword)
	router.POST("/password/forgot/verify", passwordHandler.VerifyForgotPassword)
	router.GET("/.well-known/jwks.json", jwksHandler.PublicJWKS)

	accountRoutes := router.(*gin.Engine).Group("/account")
	accountRoutes.Use(requireAccessToken)
	accountRoutes.GET("/me", accountManagerHandler.GetMe)
	accountRoutes.GET("/sessions", accountManagerHandler.ListSessions)
	accountRoutes.POST("/password", passwordHandler.ChangePassword)
}
