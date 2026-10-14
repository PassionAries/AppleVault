package backend

import (
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"AppleVault/src/backend/internal/ipatool/appstore"
	ipahttp "AppleVault/src/backend/internal/ipatool/http"
	"AppleVault/src/backend/internal/ipatool/util/machine"
)

type localIdentityTestMachine struct {
	machine.Machine
	calls int
}

func (m *localIdentityTestMachine) MacAddress() (string, error) {
	m.calls++
	return "02:01:02:03:04:05", nil
}

func TestLocalMachineDelegatesIdentityAndKeepsAppStorage(t *testing.T) {
	identity := &localIdentityTestMachine{}
	adapter := localMachine{home: t.TempDir(), identity: identity}
	for range 2 {
		address, err := adapter.MacAddress()
		if err != nil || address != "02:01:02:03:04:05" {
			t.Fatalf("identity = %q, %v", address, err)
		}
	}
	if identity.calls != 2 || adapter.HomeDirectory() != adapter.home {
		t.Fatal("local adapter must retain the same identity provider and app data directory")
	}
	if _, err := adapter.ReadPassword(0); err == nil {
		t.Fatal("desktop password input must remain noninteractive")
	}
}

func TestMapStoreApp(t *testing.T) {
	purchasedAt := time.Date(2026, time.September, 12, 8, 30, 0, 0, time.UTC)
	result := mapStoreApp(appstore.App{
		ID: 123, BundleID: "com.example.app", Name: "Example", Version: "2.0",
		Price: 1.5, PurchaseDate: purchasedAt,
	})

	if result.ID != 123 || result.BundleID != "com.example.app" || result.DisplayPrice != "¥1.50" {
		t.Fatalf("unexpected mapped app: %#v", result)
	}
	if result.PurchaseDate != purchasedAt.Format(time.RFC3339) {
		t.Fatalf("unexpected purchase date: %q", result.PurchaseDate)
	}
}

func TestParseStorePlatformAliases(t *testing.T) {
	platform, err := parseStorePlatform(" iOS ")
	if err != nil {
		t.Fatal(err)
	}
	if platform != appstore.PlatformIPhone {
		t.Fatalf("expected iphone platform, got %q", platform)
	}

	if _, err := parseStorePlatform("android"); err == nil {
		t.Fatal("expected unsupported platform to fail")
	}
}

func TestIsRetryableAppleResponse(t *testing.T) {
	for _, message := range []string{
		"unexpected response from Apple (HTTP 500)",
		"empty or non-plist body",
		"invalid response",
	} {
		if !isRetryableAppleResponse(assertionError(message)) {
			t.Fatalf("expected %q to be retryable", message)
		}
	}
	if isRetryableAppleResponse(assertionError("invalid credentials")) {
		t.Fatal("credentials error must not be retried as a transient response")
	}
}

func TestAuthenticationErrorMessageDistinguishesUnusableResponse(t *testing.T) {
	responseErr := appstore.NewErrorWithMetadata(fmt.Errorf("%w: %w", appstore.ErrAuthenticationUnavailable, &ipahttp.UnexpectedResponseError{StatusCode: 301, Reason: "missing Location"}), nil)
	message := authenticationErrorMessage(fmt.Errorf("request failed: %w", responseErr))
	if !strings.Contains(message, "切换代理节点或网络") || !strings.Contains(message, "HTTP 301") || strings.Contains(message, "missing Location") {
		t.Fatalf("missing actionable authentication diagnosis: %s", message)
	}
	credentialErr := errors.New("invalid credentials")
	if message := authenticationErrorMessage(credentialErr); message != credentialErr.Error() {
		t.Fatalf("real credential failure must retain its original message: %s", message)
	}
}

type assertionError string

func (e assertionError) Error() string { return string(e) }

type accountRetryTestStore struct {
	appstore.AppStore
	cached     appstore.Account
	refreshed  appstore.Account
	loginErr   error
	loginCalls int
	loginInput appstore.LoginInput
}

func (s *accountRetryTestStore) AccountInfo() (appstore.AccountInfoOutput, error) {
	return appstore.AccountInfoOutput{Account: s.cached}, nil
}

func (s *accountRetryTestStore) Login(input appstore.LoginInput) (appstore.LoginOutput, error) {
	s.loginCalls++
	s.loginInput = input
	return appstore.LoginOutput{Account: s.refreshed}, s.loginErr
}

func TestExpiredAccountRetriesWithFreshCredentials(t *testing.T) {
	store := &accountRetryTestStore{
		cached:    appstore.Account{Email: "test@example.com", Password: "password", PasswordToken: "expired"},
		refreshed: appstore.Account{Email: "test@example.com", PasswordToken: "fresh"},
	}
	var tokens []string
	result, err := withAccountRetry(store, func(account appstore.Account) (string, error) {
		tokens = append(tokens, account.PasswordToken)
		if account.PasswordToken == "expired" {
			return "", appstore.ErrPasswordTokenExpired
		}
		return account.PasswordToken, nil
	})
	if err != nil || result != "fresh" || len(tokens) != 2 || tokens[1] != "fresh" {
		t.Fatalf("expired credentials were not replaced: result=%q tokens=%v err=%v", result, tokens, err)
	}
	if store.loginCalls != 1 || store.loginInput.Email != store.cached.Email || store.loginInput.Password != store.cached.Password {
		t.Fatal("reauthentication must use the saved account's credentials exactly once")
	}
}

func TestFailedReauthenticationStopsQueryAndPreservesCause(t *testing.T) {
	for _, loginErr := range []error{appstore.ErrAuthCodeRequired, errors.New("Apple returned HTTP 404: Not Found")} {
		store := &accountRetryTestStore{
			cached: appstore.Account{Email: "test@example.com", Password: "password"}, loginErr: loginErr,
		}
		calls := 0
		_, err := withAccountRetry(store, func(appstore.Account) (string, error) {
			calls++
			return "", appstore.ErrPasswordTokenExpired
		})
		if calls != 1 || store.loginCalls != 1 || !errors.Is(err, loginErr) || !strings.Contains(err.Error(), "登录已失效") {
			t.Fatalf("failed reauthentication must preserve its cause without retrying the query: calls=%d err=%v", calls, err)
		}
	}
}

func TestRefreshAccountDoesNotAcceptCachedCredentialsWithoutLogin(t *testing.T) {
	store := &accountRetryTestStore{
		cached:   appstore.Account{Email: "test@example.com", Password: "password", PasswordToken: "expired"},
		loginErr: errors.New("HTTP 404: Not Found"),
	}
	account, err := refreshAccount(store, store.cached)
	if err == nil || account.PasswordToken != "" || store.loginCalls != 1 {
		t.Fatalf("local cached credentials must not count as a successful refresh: account token=%q err=%v", account.PasswordToken, err)
	}
	store.cached.Password = ""
	store.loginCalls = 0
	if _, err := refreshAccount(store, store.cached); err == nil || store.loginCalls != 0 {
		t.Fatal("missing credentials must ask for a new login without sending an empty password")
	}
}
