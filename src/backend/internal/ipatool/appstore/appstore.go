package appstore

import (
	"context"
	gohttp "net/http"
	"time"

	"AppleVault/src/backend/internal/ipatool/http"
	"AppleVault/src/backend/internal/ipatool/keychain"
	"AppleVault/src/backend/internal/ipatool/util/machine"
	"AppleVault/src/backend/internal/ipatool/util/operatingsystem"
)

type AppStore interface {
	// Login authenticates with the App Store.
	Login(input LoginInput) (LoginOutput, error)
	// AccountInfo returns the information of the authenticated account.
	AccountInfo() (AccountInfoOutput, error)
	// Revoke revokes the active credentials.
	Revoke() error
	// Lookup looks apps up based on the specified bundle identifier.
	Lookup(input LookupInput) (LookupOutput, error)
	// Search searches the App Store for apps matching the specified term.
	Search(input SearchInput) (SearchOutput, error)
	// OwnedApps lists apps owned by the authenticated account.
	OwnedApps(input OwnedAppsInput) (OwnedAppsOutput, error)
	// Purchase acquires a license for the desired app.
	// Note: only free apps are supported.
	Purchase(input PurchaseInput) error
	// Download downloads the IPA package from the App Store to the desired location.
	Download(input DownloadInput) (DownloadOutput, error)
	// ReplicateSinf replicates the sinf for the IPA package.
	ReplicateSinf(input ReplicateSinfInput) error
	// VersionHistory lists the available versions of the specified app.
	ListVersions(input ListVersionsInput) (ListVersionsOutput, error)
	// GetVersionMetadata returns the metadata for the specified version.
	GetVersionMetadata(input GetVersionMetadataInput) (GetVersionMetadataOutput, error)
	// Bag fetches the bag which contains endpoint definitions.
	Bag(input BagInput) (BagOutput, error)
}

type appstore struct {
	keychain            keychain.Keychain
	loginClient         http.Client[loginResult]
	searchClient        http.Client[searchResult]
	purchaseClient      http.Client[purchaseResult]
	downloadClient      http.Client[downloadResult]
	platformClient      http.Client[platformVersionLookupResult]
	storefrontClient    http.Client[[]byte]
	bagClient           http.Client[bagResult]
	ownedAppsClient     http.Client[[]byte]
	httpClient          http.Client[interface{}]
	actionSignerFactory ActionSignerFactory
	authRetrySleep      func(time.Duration)
	machine             machine.Machine
	os                  operatingsystem.OperatingSystem
	diagnosticLogger    http.DiagnosticLogger
	context             context.Context
}

type Args struct {
	Keychain            keychain.Keychain
	CookieJar           http.CookieJar
	OperatingSystem     operatingsystem.OperatingSystem
	Machine             machine.Machine
	ActionSignerFactory ActionSignerFactory
	Context             context.Context
	Transport           gohttp.RoundTripper
	DiagnosticLogger    http.DiagnosticLogger
}

func NewAppStore(args Args) AppStore {
	if args.Context == nil {
		args.Context = context.Background()
	}
	clientArgs := http.Args{
		CookieJar:        args.CookieJar,
		Context:          args.Context,
		Transport:        args.Transport,
		DiagnosticLogger: args.DiagnosticLogger,
	}

	actionSignerFactory := args.ActionSignerFactory
	if actionSignerFactory == nil {
		actionSignerFactory = defaultActionSignerFactory
	}
	configuredSignerFactory := func(config SAPConfig, machineID []byte) (ActionSigner, error) {
		config.DiagnosticLogger = args.DiagnosticLogger
		config.Context = args.Context
		config.Transport = args.Transport
		return actionSignerFactory(config, machineID)
	}

	return &appstore{
		keychain:            args.Keychain,
		loginClient:         http.NewClient[loginResult](http.Args{CookieJar: args.CookieJar, Context: args.Context, Transport: args.Transport, DiagnosticLogger: args.DiagnosticLogger, Authentication: true}),
		searchClient:        http.NewClient[searchResult](clientArgs),
		purchaseClient:      http.NewClient[purchaseResult](clientArgs),
		downloadClient:      http.NewClient[downloadResult](clientArgs),
		platformClient:      http.NewClient[platformVersionLookupResult](clientArgs),
		storefrontClient:    http.NewClient[[]byte](clientArgs),
		bagClient:           http.NewClient[bagResult](http.Args{CookieJar: args.CookieJar, Context: args.Context, Transport: args.Transport, DiagnosticLogger: args.DiagnosticLogger, Timeout: http.DefaultAuthenticationTimeout}),
		ownedAppsClient:     http.NewClient[[]byte](clientArgs),
		httpClient:          http.NewClient[interface{}](clientArgs),
		actionSignerFactory: configuredSignerFactory,
		context:             args.Context,
		machine:             args.Machine,
		os:                  args.OperatingSystem,
		diagnosticLogger:    args.DiagnosticLogger,
	}
}

func (t *appstore) trace(event string, fields map[string]interface{}) {
	if t.diagnosticLogger != nil {
		t.diagnosticLogger(event, fields)
	}
}
