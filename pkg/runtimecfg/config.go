package runtimecfg

type Config struct {
	TempDir              string `yaml:"tempDir,omitempty"`
	SyftCacheDir         string `yaml:"syftCacheDir,omitempty"`
	CleanupTempOnSuccess *bool  `yaml:"cleanupTempOnSuccess,omitempty"`
	CleanupTempOnFailure *bool  `yaml:"cleanupTempOnFailure,omitempty"`
	MinFreeBytes         int64  `yaml:"minFreeBytes,omitempty"`
}

func Default() Config {
	cleanup := true
	return Config{
		TempDir:              ".cache/provavalidator/tmp",
		SyftCacheDir:         ".cache/provavalidator/syft",
		CleanupTempOnSuccess: &cleanup,
		CleanupTempOnFailure: &cleanup,
		MinFreeBytes:         0,
	}
}

func WithDefaults(cfg Config) Config {
	defaults := Default()
	if cfg.TempDir == "" {
		cfg.TempDir = defaults.TempDir
	}
	if cfg.SyftCacheDir == "" {
		cfg.SyftCacheDir = defaults.SyftCacheDir
	}
	if cfg.CleanupTempOnSuccess == nil {
		cfg.CleanupTempOnSuccess = defaults.CleanupTempOnSuccess
	}
	if cfg.CleanupTempOnFailure == nil {
		cfg.CleanupTempOnFailure = defaults.CleanupTempOnFailure
	}
	return cfg
}
