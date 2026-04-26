package config

import "time"

type Config struct {
	DBPath       string
	AlertPath    string
	ProfilerPath string
	RulesDir     string
	TailInterval time.Duration
}

func (c Config) WithDefaults() Config {
	if c.TailInterval <= 0 {
		c.TailInterval = 500 * time.Millisecond
	}
	return c
}
