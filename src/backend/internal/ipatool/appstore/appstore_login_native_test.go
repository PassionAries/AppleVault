package appstore

import (
	"context"
	"encoding/base64"
	"errors"
	gohttp "net/http"
	"net/http/cookiejar"
	"os"
	"testing"
	"time"

	"AppleVault/src/backend/internal/ipatool/http"
)

// Only certificate/setup requests can leave this fixture. The synthetic
// credentials are handled locally while the production signer runs unchanged.
func TestDefaultSignerThroughStoreLogin(t *testing.T) {
	if os.Getenv("APPLEVAULT_NATIVE_TESTS") != "1" {
		t.Skip("set APPLEVAULT_NATIVE_TESTS=1 for live SAP setup")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	direct := gohttp.DefaultTransport.(*gohttp.Transport).Clone()
	direct.Proxy = nil
	defer direct.CloseIdleConnections()
	jar, _ := cookiejar.New(nil)
	keychain := &authenticationTestKeychain{}
	var setupCalls, authCalls int
	transport := authenticationTestTransport(func(r *gohttp.Request) (*gohttp.Response, error) {
		switch {
		case r.URL.Host == PrivateInitDomain && r.URL.Path == PrivateInitPath:
			return loginFixtureResponse(t, r, 200, loginFixtureBag()), nil
		case r.URL.Host == "s.mzstatic.com" && r.URL.Path == "/sap/setupCert.plist",
			r.URL.Host == "fpinit.itunes.apple.com" && r.URL.Path == "/v1/signSapSetup/legacy":
			setupCalls++
			return direct.RoundTrip(r)
		case r.URL.Host == PrivateAppStoreAPIDomain && r.URL.Path == PrivateAppStoreAPIPathAuth+"/":
			authCalls++
			signature, err := base64.StdEncoding.DecodeString(r.Header.Get(http.HeaderAppleActionSignature))
			if err != nil || len(signature) < 100 {
				t.Fatal("production signer did not produce a native Apple action signature")
			}
			return loginFixtureResponse(t, r, 200, map[string]any{"customerMessage": CustomerMessageBadLogin}), nil
		default:
			return nil, errors.New("native test forbids all other network destinations")
		}
	})
	store := NewAppStore(Args{Context: ctx, Machine: loginFixtureMachine{}, Transport: transport, Keychain: keychain, CookieJar: authenticationTestCookieJar{jar}})
	_, err := store.Login(LoginInput{Email: "fixture@example.invalid", Password: "fixture-password"})
	if !errors.Is(err, ErrAuthCodeRequired) || setupCalls != 2 || authCalls != 1 || len(keychain.saved) != 0 {
		t.Fatalf("production signing path failed: setup=%d auth=%d err=%v", setupCalls, authCalls, err)
	}
}
