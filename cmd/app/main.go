package main

import (
	"ddone-server-auth/config"
	"ddone-server-auth/internal/bootstrap/logging"
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
	defer func() {
		_ = logger.Sync()
	}()

	httpServer := newHTTPServer(cfg, logger)
	run(httpServer, logger)
}
