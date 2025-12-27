package registryauth

import "fmt"

func (c *Config) DebugString() string {
	if c == nil || len(c.Registries) == 0 {
		return "registry auth: (no overrides) -> docker default keychain"
	}
	s := "registry auth overrides:\n"
	for host, entry := range c.Registries {
		a := entry.Auth
		switch a.Type {
		case "docker", "anonymous":
			s += fmt.Sprintf("  - %s: %s\n", host, a.Type)
		case "basic":
			src := "password"
			if a.PasswordEnv != "" {
				src = "passwordEnv:" + a.PasswordEnv
			}
			s += fmt.Sprintf("  - %s: basic (username=%s, %s)\n", host, a.Username, src)
		case "token":
			src := "token"
			if a.TokenEnv != "" {
				src = "tokenEnv:" + a.TokenEnv
			}
			s += fmt.Sprintf("  - %s: token (%s)\n", host, src)
		default:
			s += fmt.Sprintf("  - %s: (unknown type=%s)\n", host, a.Type)
		}
	}
	return s
}
