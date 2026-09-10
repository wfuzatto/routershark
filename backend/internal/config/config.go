package config

import (
	"os"
	"strconv"
	"strings"
)

type Config struct {
	HTTPAddr        string
	UDPAddr         string
	DatabaseURL     string
	Allowlist       []string
	APIToken        string
	BatchSize       int
	BatchIntervalMs int
	RetentionDays   int
}

func Load() Config {
	return Config{
		HTTPAddr:        env("HTTP_ADDR", ":8080"),
		UDPAddr:         env("UDP_ADDR", ":37008"),
		DatabaseURL:     env("DATABASE_URL", "postgres://routershark:routershark@postgres:5432/routershark?sslmode=disable"),
		Allowlist:       splitCSV(os.Getenv("ROUTER_IP_ALLOWLIST")),
		APIToken:        os.Getenv("API_TOKEN"),
		BatchSize:       envInt("DB_BATCH_SIZE", 250),
		BatchIntervalMs: envInt("DB_BATCH_INTERVAL_MS", 200),
		RetentionDays:   envInt("RETENTION_DAYS", 30),
	}
}

func env(k, d string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return d
}
func envInt(k string, d int) int {
	if v := os.Getenv(k); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			return n
		}
	}
	return d
}
func splitCSV(s string) []string {
	if strings.TrimSpace(s) == "" {
		return nil
	}
	parts := strings.Split(s, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p != "" {
			out = append(out, p)
		}
	}
	return out
}
