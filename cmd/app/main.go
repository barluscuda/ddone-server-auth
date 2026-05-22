package main

import (
	"ddone-server-auth/config"
	"ddone-server-auth/internal/adapters/cache"
	"ddone-server-auth/internal/adapters/database"
	"ddone-server-auth/internal/adapters/repository"
	"ddone-server-auth/internal/adapters/sms"
	appregister "ddone-server-auth/internal/application/register"
	"ddone-server-auth/internal/bootstrap/logging"
	"ddone-server-auth/internal/domain/account"

	"github.com/barluscuda/dextools"
	"go.uber.org/zap"
)

func main() {
	// Load runtime configuration.
	cfg, err := config.Load()
	if err != nil {
		panic(err)
	}

	// Initialize the application logger.
	logger, err := logging.New(cfg.App.Debug)
	if err != nil {
		panic(err)
	}
	defer func() {
		_ = logger.Sync()
	}()

	// Connect to PostgreSQL before serving requests.
	db, err := database.New(cfg.Database, cfg.App.Debug)
	if err != nil {
		logger.Fatal("failed to connect database", zap.Error(err))
	}
	logger.Info("connected to database")

	redisClient, err := cache.New(cfg.Redis, cfg.App.Debug)
	if err != nil {
		logger.Fatal("failed to connect redis", zap.Error(err))
	}
	defer func() {
		if err := redisClient.Close(); err != nil {
			logger.Warn("failed to close redis client", zap.Error(err))
		}
	}()
	logger.Info("connected to redis")

	// Migrate account tables after the database is available.
	if err := account.Migrate(db); err != nil {
		logger.Fatal("failed to migrate account tables", zap.Error(err))
	}
	logger.Info("account tables migrated")

	// Wenova Client
	wnvClient := dextools.WenovaAPI(cfg.WenovaAPI.Token)
	smsClient := sms.NewSMS(&wnvClient)

	accountRepository := repository.NewAccountRepository(db)
	registerStore := cache.NewRegisterStore(redisClient)
	registerService := appregister.NewRegisterService(accountRepository, registerStore, smsClient)

	// Start the HTTP server once dependencies are ready.
	httpServer := newHTTPServer(cfg, logger, registerService)
	run(httpServer, logger)
}
