package appstore

import (
	"context"
	gohttp "net/http"
	"testing"
)

func TestSignerReceivesTheStoreNetworkConfiguration(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	transport := gohttp.DefaultTransport.(*gohttp.Transport).Clone()
	transport.Proxy = nil
	called := false
	store := NewAppStore(Args{Context: ctx, Transport: transport, ActionSignerFactory: func(config SAPConfig, _ []byte) (ActionSigner, error) {
		called = true
		if config.Context != ctx || config.Transport != transport {
			t.Fatal("signer must share the store context and network policy")
		}
		return nil, nil
	}}).(*appstore)
	if _, err := store.actionSignerFactory(SAPConfig{}, []byte{0, 1, 2, 3, 4, 5}); err != nil || !called {
		t.Fatalf("factory not invoked: %v", err)
	}
}
