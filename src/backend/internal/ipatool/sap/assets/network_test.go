package assets

import (
	"context"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"
)

type assetTestTransport func(*http.Request) (*http.Response, error)

func (f assetTestTransport) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestUncachedAssetsUseConfiguredClient(t *testing.T) {
	// os.UserCacheDir uses the platform-specific one of these variables.
	cache := t.TempDir()
	t.Setenv("LOCALAPPDATA", cache)
	t.Setenv("XDG_CACHE_HOME", cache)
	t.Setenv("HOME", cache)
	calls := 0
	client := &http.Client{Transport: assetTestTransport(func(r *http.Request) (*http.Response, error) {
		calls++
		if r.URL.String() != macOSRestoreURL || r.Header.Get("Range") != "bytes=0-0" {
			t.Fatal("asset resolution did not request the pinned sparse image")
		}
		return &http.Response{StatusCode: 503, Status: "503 fixture unavailable", Body: io.NopCloser(strings.NewReader("")), Header: make(http.Header)}, nil
	})}
	if _, err := LoadWithClient(context.Background(), client); err == nil || calls != 1 {
		t.Fatalf("cold cache bypassed the supplied client: calls=%d err=%v", calls, err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := LoadWithClient(ctx, client); !errors.Is(err, context.Canceled) || calls != 1 {
		t.Fatalf("canceled asset loading made a request: calls=%d err=%v", calls, err)
	}
}
