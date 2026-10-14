package unicorn

import (
	"context"
	"os"
	"testing"
)

func newTestEngine(t *testing.T) *Engine {
	t.Helper()
	if os.Getenv("APPLEVAULT_NATIVE_TESTS") != "1" {
		t.Skip("set APPLEVAULT_NATIVE_TESTS=1 to exercise the native ARM64 runtime")
	}

	engine, err := New(context.Background())
	if err != nil {
		t.Fatalf("create Unicorn engine: %v", err)
	}

	return engine
}
