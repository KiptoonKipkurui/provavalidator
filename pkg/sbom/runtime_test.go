package sbom

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/kiptoonkipkurui/provavalidator/pkg/runtimecfg"
)

func TestRuntimeConfigFromContext_Defaults(t *testing.T) {
	cfg := runtimeConfigFromContext(context.Background())

	if cfg.TempDir != ".cache/provavalidator/tmp" {
		t.Fatalf("unexpected temp dir default: %q", cfg.TempDir)
	}
	if cfg.SyftCacheDir != ".cache/provavalidator/syft" {
		t.Fatalf("unexpected syft cache dir default: %q", cfg.SyftCacheDir)
	}
	if cfg.CleanupTempOnSuccess == nil || !*cfg.CleanupTempOnSuccess {
		t.Fatalf("expected cleanupTempOnSuccess to default true")
	}
}

func TestResolveRuntimeConfig_RelativePaths(t *testing.T) {
	cwd := filepath.Join(string(filepath.Separator), "workspace", "repo")
	cleanup := false
	resolved := resolveRuntimeConfig(runtimecfg.Config{
		TempDir:              ".cache/provavalidator/tmp",
		SyftCacheDir:         ".cache/provavalidator/syft",
		CleanupTempOnSuccess: &cleanup,
	}, cwd)

	if resolved.tempRoot != filepath.Join(cwd, ".cache/provavalidator/tmp") {
		t.Fatalf("unexpected temp root: %q", resolved.tempRoot)
	}
	if resolved.syftCacheDir != filepath.Join(cwd, ".cache/provavalidator/syft") {
		t.Fatalf("unexpected syft cache dir: %q", resolved.syftCacheDir)
	}
	if resolved.xdgCacheHome != filepath.Join(cwd, ".cache/provavalidator") {
		t.Fatalf("unexpected xdg cache home: %q", resolved.xdgCacheHome)
	}
	if resolved.cleanupTempOnSuccess {
		t.Fatalf("expected cleanup on success to be false")
	}
}

func TestWithRuntimeEnvironment_SetsEnvAndCleansUpOnSuccess(t *testing.T) {
	originalWD, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}

	root := t.TempDir()
	if err := os.Chdir(root); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = os.Chdir(originalWD) }()

	ctx := WithRuntimeConfig(context.Background(), runtimecfg.Default())

	var scratchDir string
	var cacheHome string
	_, err = withRuntimeEnvironment(ctx, func(_ context.Context, cfg resolvedRuntimeConfig) (*ResolvedSBOM, error) {
		scratchDir = os.Getenv("TMPDIR")
		cacheHome = os.Getenv("XDG_CACHE_HOME")

		if scratchDir == "" {
			t.Fatal("expected TMPDIR to be set")
		}
		if !filepath.IsAbs(scratchDir) {
			t.Fatalf("expected TMPDIR to be absolute, got %q", scratchDir)
		}
		if _, statErr := os.Stat(scratchDir); statErr != nil {
			t.Fatalf("expected scratch dir to exist: %v", statErr)
		}

		expectedCacheHome := filepath.Join(root, ".cache", "provavalidator")
		if cacheHome != expectedCacheHome {
			t.Fatalf("unexpected cache home: got %q want %q", cacheHome, expectedCacheHome)
		}
		if _, statErr := os.Stat(filepath.Join(root, ".cache", "provavalidator", "syft")); statErr != nil {
			t.Fatalf("expected syft cache dir to exist: %v", statErr)
		}

		return &ResolvedSBOM{}, nil
	})
	if err != nil {
		t.Fatalf("withRuntimeEnvironment returned error: %v", err)
	}

	if _, statErr := os.Stat(scratchDir); !errors.Is(statErr, os.ErrNotExist) {
		t.Fatalf("expected scratch dir to be removed after success, got %v", statErr)
	}
	if os.Getenv("TMPDIR") == scratchDir {
		t.Fatalf("expected TMPDIR to be restored")
	}
}

func TestWithRuntimeEnvironment_KeepsTempDirOnFailure(t *testing.T) {
	originalWD, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}

	root := t.TempDir()
	if err := os.Chdir(root); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = os.Chdir(originalWD) }()

	ctx := WithRuntimeConfig(context.Background(), runtimecfg.Default())

	var scratchDir string
	expectedErr := errors.New("boom")
	_, err = withRuntimeEnvironment(ctx, func(_ context.Context, _ resolvedRuntimeConfig) (*ResolvedSBOM, error) {
		scratchDir = os.Getenv("TMPDIR")
		return nil, expectedErr
	})
	if !errors.Is(err, expectedErr) {
		t.Fatalf("expected error %v, got %v", expectedErr, err)
	}

	if _, statErr := os.Stat(scratchDir); statErr != nil {
		t.Fatalf("expected scratch dir to remain after failure: %v", statErr)
	}
}
