package appstore

import (
	"context"
	"fmt"
	gohttp "net/http"
	"time"

	"AppleVault/src/backend/internal/ipatool/http"
	"AppleVault/src/backend/internal/ipatool/sap"
)

type SAPConfig struct {
	AuthEndpoint     string
	SetupURL         string
	CertificateURL   string
	Version          uint32
	DiagnosticLogger http.DiagnosticLogger
	Context          context.Context
	Transport        gohttp.RoundTripper
}

type ActionSigner interface {
	http.ActionSigner
	Close() error
}

type ActionSignerFactory func(config SAPConfig, machineID []byte) (ActionSigner, error)

func defaultActionSignerFactory(config SAPConfig, machineID []byte) (output ActionSigner, signerErr error) {
	started := time.Now()
	if config.DiagnosticLogger != nil {
		config.DiagnosticLogger("sap.start", map[string]interface{}{"version": config.Version})
		defer func() {
			fields := map[string]interface{}{"elapsed_ms": time.Since(started).Milliseconds(), "success": signerErr == nil}
			if signerErr != nil {
				fields["error"] = signerErr.Error()
			}
			config.DiagnosticLogger("sap.complete", fields)
		}()
	}
	ctx := config.Context
	if ctx == nil {
		ctx = context.Background()
	}
	signer, err := sap.NewSigner(ctx, sap.Config{
		SetupURL:         config.SetupURL,
		CertificateURL:   config.CertificateURL,
		Version:          config.Version,
		HardwareID:       machineID,
		DiagnosticLogger: config.DiagnosticLogger,
		Transport:        config.Transport,
	})
	if err != nil {
		return nil, fmt.Errorf("create SAP signer: %w", err)
	}

	return signer, nil
}
