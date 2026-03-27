package config

// Config holds all service configuration parsed from environment variables.
type Config struct {
	DatabaseURL   string
	MinioEndpoint string
	MinioAccessKey string
	MinioSecretKey string
	RabbitmqURL   string
	MinioSecure   bool
	MinioBucket   string
	RabbitmqQueue string
	MaxFileSize   int64
	CORSOrigins   string
	LogLevel      string
	Port          int
	StagesTotal   int
}

// Load parses environment variables into Config.
// Stub — to be implemented.
func Load() (*Config, error) {
	return &Config{}, nil
}
