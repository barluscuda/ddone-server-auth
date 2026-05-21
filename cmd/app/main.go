package main

import (
	"ddone-server-auth/config"
	"ddone-server-auth/internal/adapters/handler"
	"fmt"

	"github.com/gin-gonic/gin"
)

func main()  {
	app := gin.New()
	cfg, err := config.Load()
	if err != nil {
		panic(err)
	}

	app.GET("/healthz", handler.Healthz)
	app.Run(fmt.Sprintf(":%d", cfg.App.Port))
}