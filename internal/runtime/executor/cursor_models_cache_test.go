package executor

import (
	"testing"

	"github.com/router-for-me/CLIProxyAPI/v7/internal/registry"
)

// withCursorModelsCache swaps the package-level cache for the duration of a test
// and restores the previous state on cleanup.
func withCursorModelsCache(t *testing.T, seed map[string][]*registry.ModelInfo) {
	t.Helper()
	cursorModelsCacheMu.Lock()
	prev := cursorModelsCache
	cursorModelsCache = make(map[string][]*registry.ModelInfo, len(seed))
	for k, v := range seed {
		// copy to avoid test mutation leaking across runs
		dup := make([]*registry.ModelInfo, len(v))
		copy(dup, v)
		cursorModelsCache[k] = dup
	}
	cursorModelsCacheMu.Unlock()
	t.Cleanup(func() {
		cursorModelsCacheMu.Lock()
		cursorModelsCache = prev
		cursorModelsCacheMu.Unlock()
	})
}

// TestCursorModelsOrFallback_PrefersCacheOverHardcoded ensures that when a
// previous successful fetch cached models for an auth, a subsequent fetch
// failure returns the cached models instead of the hardcoded fallback.
// This prevents the live->fallback->live churn that removes working models
// (e.g. composer-2.5) from the registry after a transient network blip.
func TestCursorModelsOrFallback_PrefersCacheOverHardcoded(t *testing.T) {
	cached := []*registry.ModelInfo{
		{ID: "composer-2.5", Object: "model", OwnedBy: "cursor", Type: cursorAuthType, DisplayName: "Composer 2.5"},
	}
	withCursorModelsCache(t, map[string][]*registry.ModelInfo{
		"auth-with-cache": cached,
	})

	got := cursorModelsOrFallback("auth-with-cache")
	if len(got) != 1 || got[0].ID != "composer-2.5" {
		t.Fatalf("expected cached [composer-2.5], got %+v", got)
	}

	// Unknown auth id with no cache entry must fall through to the hardcoded list.
	fb := cursorModelsOrFallback("never-seen-auth")
	if len(fb) == 0 {
		t.Fatal("expected non-empty hardcoded fallback for unknown auth")
	}
}

// TestGetCursorFallbackModels_IsCurrent guards against the hardcoded list
// drifting to stale model ids (e.g. claude-3.5-sonnet, gpt-4o) and against
// it losing the models users actually call (e.g. composer-2.5).
func TestGetCursorFallbackModels_IsCurrent(t *testing.T) {
	fb := GetCursorFallbackModels()
	if len(fb) == 0 {
		t.Fatal("hardcoded fallback must not be empty")
	}

	ids := make(map[string]bool, len(fb))
	for _, m := range fb {
		ids[m.ID] = true
	}

	// Must contain: the model the user actually calls, plus a representative
	// slice of current Cursor model families.
	mustHave := []string{
		"composer-2.5",
		"composer-2.5-fast",
		"gpt-5.3-codex",
		"gpt-5.2",
		"claude-opus-4-8-thinking-high",
		"gemini-3.1-pro",
	}
	for _, id := range mustHave {
		if !ids[id] {
			t.Errorf("hardcoded fallback missing required current model %q; have %v", id, mapKeys(ids))
		}
	}

	// Must NOT contain: model ids Cursor no longer serves (verified by a live
	// GetUsableModels call returning 0 occurrences of these names).
	mustNotHave := []string{
		"claude-3.5-sonnet",
		"gpt-4o",
		"cursor-small",
		"gemini-2.5-pro",
	}
	for _, id := range mustNotHave {
		if ids[id] {
			t.Errorf("hardcoded fallback still contains stale model %q (Cursor no longer serves it)", id)
		}
	}
}

func mapKeys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}
