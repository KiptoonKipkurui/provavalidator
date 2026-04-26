package sbom

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sync"

	"github.com/kiptoonkipkurui/provavalidator/pkg/runtimecfg"
)

type runtimeContextKey struct{}

type resolvedRuntimeConfig struct {
	tempRoot             string
	syftCacheDir         string
	xdgCacheHome         string
	cleanupTempOnSuccess bool
	cleanupTempOnFailure bool
	minFreeBytes         int64
}

var runtimeEnvMu sync.Mutex

func WithRuntimeConfig(ctx context.Context, cfg runtimecfg.Config) context.Context {
	return context.WithValue(ctx, runtimeContextKey{}, cfg)
}

func runtimeConfigFromContext(ctx context.Context) runtimecfg.Config {
	if ctx != nil {
		if cfg, ok := ctx.Value(runtimeContextKey{}).(runtimecfg.Config); ok {
			return runtimecfg.WithDefaults(cfg)
		}
	}
	return runtimecfg.Default()
}

func resolveRuntimeConfig(cfg runtimecfg.Config, cwd string) resolvedRuntimeConfig {
	cfg = runtimecfg.WithDefaults(cfg)
	return resolvedRuntimeConfig{
		tempRoot:             resolveRuntimePath(cwd, cfg.TempDir),
		syftCacheDir:         resolveRuntimePath(cwd, cfg.SyftCacheDir),
		xdgCacheHome:         xdgCacheHome(cfg.SyftCacheDir, cwd),
		cleanupTempOnSuccess: cfg.CleanupTempOnSuccess == nil || *cfg.CleanupTempOnSuccess,
		cleanupTempOnFailure: cfg.CleanupTempOnFailure == nil || *cfg.CleanupTempOnFailure,
		minFreeBytes:         cfg.MinFreeBytes,
	}
}

func resolveRuntimePath(cwd, path string) string {
	if filepath.IsAbs(path) {
		return filepath.Clean(path)
	}
	return filepath.Join(cwd, path)
}

func xdgCacheHome(syftCacheDir, cwd string) string {
	resolved := resolveRuntimePath(cwd, syftCacheDir)
	if filepath.Base(resolved) == "syft" {
		return filepath.Dir(resolved)
	}
	return resolved
}

func withRuntimeEnvironment(ctx context.Context, fn func(context.Context, resolvedRuntimeConfig) (*ResolvedSBOM, error)) (*ResolvedSBOM, error) {
	cfg := runtimeConfigFromContext(ctx)
	cwd, err := os.Getwd()
	if err != nil {
		return nil, fmt.Errorf("resolve working directory: %w", err)
	}
	resolved := resolveRuntimeConfig(cfg, cwd)

	if err := os.MkdirAll(resolved.tempRoot, 0o755); err != nil {
		return nil, fmt.Errorf("configure sbom runtime temp root: %w", err)
	}
	if err := os.MkdirAll(resolved.syftCacheDir, 0o755); err != nil {
		return nil, fmt.Errorf("configure sbom runtime cache root: %w", err)
	}
	if err := os.MkdirAll(resolved.xdgCacheHome, 0o755); err != nil {
		return nil, fmt.Errorf("configure sbom runtime xdg cache root: %w", err)
	}
	if err := ensureMinFreeSpace(resolved.tempRoot, resolved.minFreeBytes); err != nil {
		return nil, err
	}

	scratchDir, err := os.MkdirTemp(resolved.tempRoot, "run-")
	if err != nil {
		return nil, fmt.Errorf("create sbom runtime scratch dir: %w", err)
	}

	runtimeEnvMu.Lock()
	defer runtimeEnvMu.Unlock()

	restore := captureEnv("TMPDIR", "TMP", "TEMP", "XDG_CACHE_HOME")
	defer restore()

	if err := os.Setenv("TMPDIR", scratchDir); err != nil {
		return nil, fmt.Errorf("set sbom runtime TMPDIR: %w", err)
	}
	if err := os.Setenv("TMP", scratchDir); err != nil {
		return nil, fmt.Errorf("set sbom runtime TMP: %w", err)
	}
	if err := os.Setenv("TEMP", scratchDir); err != nil {
		return nil, fmt.Errorf("set sbom runtime TEMP: %w", err)
	}
	if err := os.Setenv("XDG_CACHE_HOME", resolved.xdgCacheHome); err != nil {
		return nil, fmt.Errorf("set sbom runtime XDG_CACHE_HOME: %w", err)
	}

	sbomDoc, runErr := fn(ctx, resolved)
	shouldCleanup := runErr == nil && resolved.cleanupTempOnSuccess
	if runErr != nil && resolved.cleanupTempOnFailure {
		shouldCleanup = true
	}
	if shouldCleanup {
		if cleanupErr := os.RemoveAll(scratchDir); cleanupErr != nil && runErr == nil {
			return nil, fmt.Errorf("cleanup sbom runtime temp dir: %w", cleanupErr)
		}
	}
	return sbomDoc, runErr
}

func ensureMinFreeSpace(path string, minFreeBytes int64) error {
	if minFreeBytes <= 0 {
		return nil
	}

	freeBytes, ok, err := freeSpaceBytes(path)
	if err != nil {
		return fmt.Errorf("check sbom runtime free space: %w", err)
	}
	if !ok {
		return nil
	}
	if freeBytes < uint64(minFreeBytes) {
		return fmt.Errorf("sbom runtime temp root %q has %s free, below required minimum %s", path, humanBytes(freeBytes), humanBytes(uint64(minFreeBytes)))
	}
	return nil
}

func humanBytes(bytes uint64) string {
	const unit = 1024
	if bytes < unit {
		return fmt.Sprintf("%dB", bytes)
	}

	value := float64(bytes)
	for _, suffix := range []string{"KiB", "MiB", "GiB", "TiB", "PiB"} {
		value /= unit
		if value < unit {
			return fmt.Sprintf("%.1f%s", value, suffix)
		}
	}
	return fmt.Sprintf("%.1fEiB", value/unit)
}

func captureEnv(keys ...string) func() {
	type envState struct {
		value string
		ok    bool
	}
	states := make(map[string]envState, len(keys))
	for _, key := range keys {
		value, ok := os.LookupEnv(key)
		states[key] = envState{value: value, ok: ok}
	}

	return func() {
		for _, key := range keys {
			state := states[key]
			if state.ok {
				_ = os.Setenv(key, state.value)
			} else {
				_ = os.Unsetenv(key)
			}
		}
	}
}
