package registryauth

import (
	"fmt"

	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/name"
)

type OverrideKeychain struct {
	cfg  *Config
	base authn.Keychain // typically authn.DefaultKeychain
}

func NewOverrideKeychain(cfg *Config, base authn.Keychain) *OverrideKeychain {
	if cfg == nil {
		cfg = &Config{
			Registries: map[string]RegistryEntry{},
		}
	}

	if cfg.Registries == nil {
		cfg.Registries = map[string]RegistryEntry{}
	}

	if base == nil {
		base = authn.DefaultKeychain
	}

	return &OverrideKeychain{cfg: cfg, base: base}
}

// Resolve implements authn.Keychain
func (k *OverrideKeychain) Resolve(res authn.Resource) (authn.Authenticator, error) {
	host := res.RegistryStr()
	var authenticator authn.Authenticator

	// exact-match override
	if entry, ok := k.cfg.Registries[host]; ok {
		switch entry.Auth.Type {
		case "docker":
			authenticator, err := k.base.Resolve(res)

			if err != nil {
				return nil, err
			}
			return authenticator, nil
		case "anonymous":
			return authn.FromConfig(authn.AuthConfig{}), nil
		case "basic", "token":
			u, p, anon, err := entry.Auth.resolveSecret()
			if err != nil {
				return nil, fmt.Errorf("registry %q: %w", host, err)
			}
			if anon {
				return authn.Anonymous, nil
			}

			return authn.FromConfig(authn.AuthConfig{
				Username: u,
				Password: p,
			}), nil

		default:
			return nil, fmt.Errorf("registry %q: unsupported auth.type %q", host, entry.Auth.Type)
		}

	}

	// fallback: docker default credentials (or whatever the base is)

	authenticator, err := k.base.Resolve(res)

	if err != nil {
		return nil, fmt.Errorf("registry: default resolve error %s: %w", host, err)
	}

	return authenticator, nil
}

// Convinience: build a keychain for a given image ref string
// This is handy for wiring into cosign/remote without duplicating parse logic
func KeyChainForImage(cfg *Config, imageRef string) (authn.Keychain, string, error) {
	ref, err := name.ParseReference(imageRef)
	if err != nil {
		return nil, "", err
	}

	host := ref.Context().RegistryStr()

	kc := NewOverrideKeychain(cfg, authn.DefaultKeychain)

	return kc, host, nil
}
