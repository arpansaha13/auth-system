// Package config re-exports auth system configuration
package config

import config_internal "github.com/arpansaha13/auth-system/internal/config"

type Config = config_internal.Config

func Load() (*Config, error) {
	return config_internal.Load()
}
