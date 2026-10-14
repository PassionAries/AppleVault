//go:build (darwin && !ios) || linux

package unicorn

import (
	"context"
	"fmt"
	"net/http"

	"github.com/ebitengine/purego"
)

func openLibrary(ctx context.Context, client *http.Client) (library, error) {
	paths, err := cachedRuntimePaths(ctx, client)
	if err != nil {
		return library{}, err
	}

	if err := ctx.Err(); err != nil {
		return library{}, fmt.Errorf("load Unicorn library: %w", err)
	}

	handle, err := purego.Dlopen(paths.library, purego.RTLD_NOW|purego.RTLD_LOCAL)
	if err != nil {
		return library{}, fmt.Errorf("%s: %w", paths.library, err)
	}

	return library{
		handle: handle,
		close: func() error {
			return purego.Dlclose(handle)
		},
	}, nil
}
