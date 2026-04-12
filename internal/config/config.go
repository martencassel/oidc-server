package config

// AppConfig holds the configuration settings for the OIDC server application.
type AppConfig struct {
	PublicURL string
}

// NewAppConfig creates a new AppConfig with the given public URL.
func NewAppConfig(publicUrl string) *AppConfig {
	return &AppConfig{
		PublicURL: publicUrl,
	}
}
