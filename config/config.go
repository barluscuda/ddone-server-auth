package config

import (
	"strings"

	"github.com/joho/godotenv"
	"github.com/spf13/viper"
)

type Config struct {
	App struct {
		Debug bool
		Port  int
	}
}

func Load() (*Config, error) {
	var cfg Config

	godotenv.Load()

	viper.SetConfigName("config")
	viper.SetConfigType("yaml")
	viper.AddConfigPath("./config")

	viper.SetEnvPrefix("DDONE")
	viper.SetEnvKeyReplacer(
		strings.NewReplacer(".", "_"),
	)
	viper.AutomaticEnv()

	viper.BindEnv("app.port", "APP_PORT")
	viper.BindEnv("app.debug", "APP_DEBUG")

	err := viper.Unmarshal(&cfg)
	if err != nil {
		return nil, err
	}

	return &cfg, nil
}
