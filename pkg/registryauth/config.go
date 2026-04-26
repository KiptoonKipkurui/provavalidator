package registryauth

import (
	"fmt"
	"os"

	"github.com/kiptoonkipkurui/provavalidator/pkg/runtimecfg"
	"k8s.io/apimachinery/pkg/util/yaml"
)

type Config struct {
	Registries map[string]RegistryEntry `yaml:"registries"`
	Notation   NotationConfig           `yaml:"notation"`
	Runtime    runtimecfg.Config        `yaml:"runtime"`
}

type RegistryEntry struct {
	Auth AuthConfig `yaml:"auth"`
}

type AuthConfig struct {
	Type        string `yaml:"type"` //docker|basic|token|anonymous
	Username    string `yaml:"username,omitempty"`
	UsernameEnv string `yaml:"usernameEnv,omitempty"`
	Password    string `yaml:"password,omitempty"`
	PasswordEnv string `yaml:"passwordEnv,omitempty"`
	Token       string `yaml:"token,omitempty"`
	TokenEnv    string `yaml:"tokenEnv,omitempty"`
}

type NotationConfig struct {
	ConfigDir       string `yaml:"configDir,omitempty"`
	TrustPolicyPath string `yaml:"trustPolicyPath,omitempty"`
	TrustStorePath  string `yaml:"trustStorePath,omitempty"`
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
	case "docker", "anonymous", "docker_or_anonymous":
		return nil
	case "basic", "basic_or_anonymous":
		if entry.Auth.Username == "" && entry.Auth.UsernameEnv == "" {
			return fmt.Errorf("registry %q: auth.type=basic requires auth.username", host)
		}
		if t == "basic" && entry.Auth.Password == "" && entry.Auth.PasswordEnv == "" {
			return fmt.Errorf("registry %q: auth.type=basic requires auth.password or auth.passwordEnv", host)
		}
		return nil
	case "token", "token_or_anonymous":
		if t == "token" && entry.Auth.Token == "" && entry.Auth.TokenEnv == "" {
			return fmt.Errorf("registry %q: auth.type=token requires auth.token or auth.tokenEnv", host)
		}
		return nil
	default:
		return fmt.Errorf("registry %q: unsupported auth.type %q (supported: docker|docker_or_anonymous|basic|basic_or_anonymous|token|token_or_anonymous|anonymous)", host, t)
	}
}
func (a AuthConfig) resolveSecret() (username, password string, isAnon bool, err error) {
	switch a.Type {
	case "anonymous":
		return "", "", true, nil
	case "docker", "docker_or_anonymous":
		// handled elsewhere
		return "", "", false, nil
	case "basic", "basic_or_anonymous":
		user := a.Username
		if user == "" && a.UsernameEnv != "" {
			user = os.Getenv(a.UsernameEnv)
		}
		pw := a.Password
		if pw == "" && a.PasswordEnv != "" {
			pw = os.Getenv(a.PasswordEnv)
		}
		if a.Type == "basic_or_anonymous" && (user == "" || pw == "") {
			return "", "", true, nil
		}
		if user == "" {
			return "", "", false, fmt.Errorf("basic auth: missing username (username or usernameEnv)")
		}
		if pw == "" {
			return "", "", false, fmt.Errorf("basic auth: missing password (password or passwordEnv)")
		}
		return user, pw, false, nil
	case "token", "token_or_anonymous":
		tok := a.Token
		if tok == "" && a.TokenEnv != "" {
			tok = os.Getenv(a.TokenEnv)
		}
		if a.Type == "token_or_anonymous" && tok == "" {
			return "", "", true, nil
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
