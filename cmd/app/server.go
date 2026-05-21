package main

import (
	"context"
	"ddone-server-auth/config"
	"ddone-server-auth/internal/adapters/handler"
	"ddone-server-auth/internal/adapters/middleware"
	"errors"
	"fmt"
	"net/http"
	"os/signal"
	"syscall"
	"time"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"
)

func newHTTPServer(cfg *config.Config, logger *zap.Logger) *http.Server {
	if cfg.App.Debug {
		gin.SetMode(gin.DebugMode)
	} else {
		gin.SetMode(gin.ReleaseMode)
	}

	app := gin.New()
	app.HandleMethodNotAllowed = true
	app.Use(
		middleware.Recovery(logger),
		middleware.RequestLogger(logger),
	)
	app.NoRoute(middleware.NoRoute())
	app.NoMethod(middleware.NoMethod())
	app.GET("/healthz", handler.Healthz)

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
