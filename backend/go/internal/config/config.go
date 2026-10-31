// Package config reads every setting from the environment (05 §Configuration) into one struct.
package config

import (
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"
)

// Core is the configuration of cmd/core.
type Core struct {
	DatabaseURL   string
	SensorKeys    map[string]string // sensor id -> HMAC key
	SensorAddr    string            // sensor API listen address (decoy_net)
	AnalystAddr   string            // analyst API listen address (mgmt_net)
	JWTSecret     []byte
	AdminEmail    string
	AdminPassword string
	MLURL         string
	DiscordURL    string
	SlackURL      string
	DashboardURL  string
	MazeAdaptive  bool
	ScorerLearn   bool
	InputRiskMin  float64
	NarrateMaxHr  int
	CookieSecure  bool
	SessionTTL    time.Duration
	LogLevel      string
}

// LoadCore reads and validates the core configuration.
func LoadCore() (Core, error) {
	c := Core{
		DatabaseURL:   os.Getenv("DATABASE_URL"),
		SensorAddr:    env("SENSOR_ADDR", ":8443"),
		AnalystAddr:   env("ANALYST_ADDR", ":8090"),
		JWTSecret:     []byte(os.Getenv("JWT_SECRET")),
		AdminEmail:    os.Getenv("SOC_ADMIN_EMAIL"),
		AdminPassword: os.Getenv("SOC_ADMIN_PASSWORD"),
		MLURL:         strings.TrimRight(os.Getenv("ML_URL"), "/"),
		DiscordURL:    os.Getenv("DISCORD_WEBHOOK_URL"),
		SlackURL:      os.Getenv("SLACK_WEBHOOK_URL"),
		DashboardURL:  strings.TrimRight(env("DASHBOARD_URL", "http://localhost:3000"), "/"),
		MazeAdaptive:  envBool("MAZE_ADAPTIVE", true),
		ScorerLearn:   envBool("SCORER_LEARN", false),
		InputRiskMin:  envFloat("INPUT_RISK_MIN", 0.5),
		NarrateMaxHr:  envInt("NARRATE_MAX_PER_HOUR", 120),
		CookieSecure:  envBool("COOKIE_SECURE", false),
		SessionTTL:    12 * time.Hour,
		LogLevel:      env("LOG_LEVEL", "info"),
	}
	keys, err := ParseSensorKeys(os.Getenv("SENSOR_KEYS"))
	if err != nil {
		return c, err
	}
	c.SensorKeys = keys
	var errs []error
	if c.DatabaseURL == "" {
		errs = append(errs, errors.New("DATABASE_URL is required"))
	}
	if len(c.JWTSecret) < 32 {
		errs = append(errs, errors.New("JWT_SECRET must be at least 32 bytes"))
	}
	return c, errors.Join(errs...)
}

// ParseSensorKeys parses "ssh-01:secret1,web-01:secret2".
func ParseSensorKeys(s string) (map[string]string, error) {
	out := map[string]string{}
	for _, part := range strings.Split(s, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		id, key, ok := strings.Cut(part, ":")
		if !ok || id == "" || key == "" {
			return nil, fmt.Errorf("SENSOR_KEYS: bad entry %q (want id:key)", part)
		}
		if len(key) < 16 {
			return nil, fmt.Errorf("SENSOR_KEYS: key for %s is shorter than 16 chars", id)
		}
		out[id] = key
	}
	return out, nil
}

// Sensor is the configuration shared by every decoy and the log collector.
type Sensor struct {
	SensorID string
	Key      string
	CoreURL  string
	Addr     string
	DataDir  string
	SeedDir  string
}

// LoadSensor reads SENSOR_ID, SENSOR_KEY, CORE_URL and LISTEN_ADDR (default given by the caller).
func LoadSensor(defaultAddr string) (Sensor, error) {
	s := Sensor{
		SensorID: os.Getenv("SENSOR_ID"),
		Key:      os.Getenv("SENSOR_KEY"),
		CoreURL:  strings.TrimRight(env("CORE_URL", "http://localhost:8443"), "/"),
		Addr:     env("LISTEN_ADDR", defaultAddr),
		DataDir:  env("DATA_DIR", "/data"),
		SeedDir:  env("SEED_DIR", "/seed"),
	}
	if s.SensorID == "" || s.Key == "" {
		return s, errors.New("SENSOR_ID and SENSOR_KEY are required")
	}
	return s, nil
}

func env(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}

func envBool(k string, def bool) bool {
	v, err := strconv.ParseBool(os.Getenv(k))
	if err != nil {
		return def
	}
	return v
}

func envInt(k string, def int) int {
	v, err := strconv.Atoi(os.Getenv(k))
	if err != nil {
		return def
	}
	return v
}

func envFloat(k string, def float64) float64 {
	v, err := strconv.ParseFloat(os.Getenv(k), 64)
	if err != nil {
		return def
	}
	return v
}
