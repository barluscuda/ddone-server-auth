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
	"net/http"

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
	db, err := database.New(cfg.Database, cfg.App.Debug)
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

	wnvClient := dextools.WenovaAPI(cfg.WenovaAPI.Token)
	smsClient := sms.NewSMS(&wnvClient)
	accountRepository := repository.NewAccountRepository(db)
	registerStore := cache.NewRegisterStore(redisClient)
	registerService := appregister.NewRegisterService(accountRepository, registerStore, smsClient)

	return newHTTPServer(cfg, logger, registerService), func() {
		if err := redisClient.Close(); err != nil {
			logger.Warn("failed to close redis client", zap.Error(err))
		}
	}
}

func syncLogger(logger *zap.Logger) {
	_ = logger.Sync()
}
