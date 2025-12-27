package registryauth

import (
	"fmt"
	"os"

	"k8s.io/apimachinery/pkg/util/yaml"
)

type Config struct {
	Registries map[string]RegistryEntry `yaml:"registries"`
}

type RegistryEntry struct {
	Auth AuthConfig `yaml:"auth"`
}

type AuthConfig struct {
	Type        string `yaml:"type"` //docker|basic|token|anonymous
	Username    string `yaml:"username,omitempty"`
	Password    string `yaml:"password,omitempty"`
	PasswordEnv string `yaml:"passwordEnv,omitempty"`
	Token       string `yaml:"token,omitempty"`
	TokenEnv    string `yaml:"tokenEnv,omitempty"`
}

func LoadConfig(path string) (*Config, error) {
	if path == "" {
		// Empty means no overrides. just use docker default keychain

		return &Config{Registries: map[string]RegistryEntry{}}, nil
	}

	b, err := os.ReadFile(path)

	if err != nil {
		return nil, fmt.Errorf("read auth config: %w", err)
	}

	var cfg Config
	if err := yaml.Unmarshal(b, &cfg); err != nil {
		return nil, fmt.Errorf("parse auth config yaml: %w", err)
	}

	if cfg.Registries == nil {
		cfg.Registries = map[string]RegistryEntry{}
	}

	// Validate entries early so failure is clear
	for host, entry := range cfg.Registries {
		if err := validateEntry(host, entry); err != nil {
			return nil, err
		}
	}

	return &cfg, nil
}

func validateEntry(host string, entry RegistryEntry) error {
	t := entry.Auth.Type
	switch t {
	case "docker", "anonymous":
		return nil
	case "basic":
		if entry.Auth.Username == "" {
			return fmt.Errorf("registry %q: auth.type=basic requires auth.username", host)
		}
		if entry.Auth.Password == "" && entry.Auth.PasswordEnv == "" {
			return fmt.Errorf("registry %q: auth.type=basic requires auth.password or auth.passwordEnv", host)
		}
		return nil
	case "token":
		if entry.Auth.Token == "" && entry.Auth.TokenEnv == "" {
			return fmt.Errorf("registry %q: auth.type=token requires auth.token or auth.tokenEnv", host)
		}
		return nil
	default:
		return fmt.Errorf("registry %q: unsupported auth.type %q (supported: docker|basic|token|anonymous)", host, t)
	}
}
func (a AuthConfig) resolveSecret() (username, password string, isAnon bool, err error) {
	switch a.Type {
	case "anonymous":
		return "", "", true, nil
	case "docker":
		// handled elsewhere
		return "", "", false, nil
	case "basic":
		pw := a.Password
		if pw == "" && a.PasswordEnv != "" {
			pw = os.Getenv(a.PasswordEnv)
		}
		if pw == "" {
			return "", "", false, fmt.Errorf("basic auth: missing password (password or passwordEnv)")
		}
		return a.Username, pw, false, nil
	case "token":
		tok := a.Token
		if tok == "" && a.TokenEnv != "" {
			tok = os.Getenv(a.TokenEnv)
		}
		if tok == "" {
			return "", "", false, fmt.Errorf("token auth: missing token (token or tokenEnv)")
		}
		// Common pattern: put token into password; username is registry-specific.
		// "oauth2" works for many registries; you can make this configurable later.
		return "oauth2", tok, false, nil
	default:
		return "", "", false, fmt.Errorf("unknown auth type %q", a.Type)
	}
}
