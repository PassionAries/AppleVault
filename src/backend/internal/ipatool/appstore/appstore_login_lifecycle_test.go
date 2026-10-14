package appstore

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	gohttp "net/http"
	"net/http/cookiejar"
	"reflect"
	"strings"
	"testing"
	"time"

	"AppleVault/src/backend/internal/ipatool/http"
	"howett.net/plist"
)

const fixtureAuthEndpoint = "https://buy.itunes.apple.com/WebObjects/MZFinance.woa/wa/authenticate"

type loginFixtureMachine struct{}

func (loginFixtureMachine) MacAddress() (string, error) { return "02:00:00:00:00:01", nil }
func (loginFixtureMachine) HomeDirectory() string       { return "" }
func (loginFixtureMachine) ReadPassword(int) ([]byte, error) {
	return nil, errors.New("interactive passwords are forbidden in tests")
}

type lifecycleSigner struct{ closed int }

func (*lifecycleSigner) Sign(body []byte) ([]byte, error) {
	return authenticationTestSigner{}.Sign(body)
}
func (s *lifecycleSigner) Close() error { s.closed++; return nil }

func loginFixtureBag() map[string]any {
	return map[string]any{"urlBag": map[string]any{
		"authenticateAccount": fixtureAuthEndpoint,
		"sign-sap-setup":      "https://fpinit.itunes.apple.com/v1/signSapSetup/legacy",
		"sign-sap-setup-cert": "https://s.mzstatic.com/sap/setupCert.plist",
		"sign-sap-version":    "200",
	}}
}

func loginFixtureResponse(t *testing.T, request *gohttp.Request, status int, payload map[string]any) *gohttp.Response {
	t.Helper()
	var body []byte
	if payload != nil {
		var err error
		body, err = plist.Marshal(payload, plist.XMLFormat)
		if err != nil {
			t.Fatal(err)
		}
	}
	return &gohttp.Response{StatusCode: status, Header: make(gohttp.Header), Request: request, Body: io.NopCloser(bytes.NewReader(body))}
}

func TestLoginLifecycleThenVersionHistory(t *testing.T) {
	jar, _ := cookiejar.New(nil)
	keychain := &authenticationTestKeychain{}
	var signers []*lifecycleSigner
	var authCalls, bagCalls int
	var redirectedBody []byte
	transport := authenticationTestTransport(func(r *gohttp.Request) (*gohttp.Response, error) {
		if r.URL.Path == PrivateInitPath {
			bagCalls++
			if r.URL.Query().Get("guid") != "020000000001" || r.Method != gohttp.MethodGet {
				t.Fatal("bag and login must use the same device identity")
			}
			return loginFixtureResponse(t, r, 200, loginFixtureBag()), nil
		}
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Fatal(err)
		}
		var payload map[string]any
		if _, err := plist.Unmarshal(body, &payload); err != nil {
			t.Fatal(err)
		}
		if strings.HasPrefix(r.URL.Path, PrivateAppStoreAPIPathAuth) {
			authCalls++
			if authCalls <= 3 && r.URL.Path != PrivateAppStoreAPIPathAuth+"/" {
				t.Fatal("initial login and credential retry must use the canonical trailing slash")
			}
			expected, _ := authenticationTestSigner{}.Sign(body)
			if r.Method != gohttp.MethodPost || r.Header.Get(http.HeaderAppleActionSignature) != base64.StdEncoding.EncodeToString(expected) || payload["guid"] != "020000000001" {
				t.Fatal("login must sign the exact outgoing body with the bag identity")
			}
			if authCalls > 1 {
				cookie, err := r.Cookie("fixture-session")
				if err != nil || cookie.Value != "retained" {
					t.Fatal("2FA or redirect lost the session cookie")
				}
			}
			response := loginFixtureResponse(t, r, 200, map[string]any{})
			switch authCalls {
			case 1:
				if payload["password"] != "fixture-password" {
					t.Fatal("initial login unexpectedly appended a code")
				}
				response = loginFixtureResponse(t, r, 200, map[string]any{"customerMessage": CustomerMessageBadLogin})
				response.Header.Set("Set-Cookie", "fixture-session=retained; Domain=itunes.apple.com; Path=/; Secure")
			case 2:
				if payload["password"] != "fixture-password123456" || payload["attempt"] != "1" {
					t.Fatal("2FA did not start a fresh attempt with normalized code")
				}
				response = loginFixtureResponse(t, r, 200, map[string]any{"failureType": FailureTypeInvalidCredentials})
			case 3:
				if payload["attempt"] != "2" {
					t.Fatal("credential retry did not increment attempt")
				}
				redirectedBody = body
				response.StatusCode = 307
				response.Header.Set("Location", PrivateAppStoreAPIPathAuth+"/")
			case 4:
				if r.URL.String() != fixtureAuthEndpoint+"/" || !bytes.Equal(body, redirectedBody) {
					t.Fatal("relative redirect changed the signed request")
				}
				response.StatusCode = 302
				response.Header.Set("Location", "https://p34-buy.itunes.apple.com"+PrivateAppStoreAPIPathAuth)
			case 5:
				if r.URL.Host != "p34-buy.itunes.apple.com" || !bytes.Equal(body, redirectedBody) {
					t.Fatal("Store pod redirect changed the signed request")
				}
				response = loginFixtureResponse(t, r, 200, map[string]any{
					"passwordToken": "fixture-token", "dsPersonId": "123",
					"accountInfo": map[string]any{"appleId": "fixture@example.invalid", "address": map[string]any{"firstName": "Fixture", "lastName": "User"}},
				})
				response.Header.Set(HTTPHeaderStoreFront, "143465-1,29")
				response.Header.Set(HTTPHeaderPod, "34")
			default:
				t.Fatal("authentication exceeded the expected request count")
			}
			return response, nil
		}
		if r.URL.Path == PrivateAppStoreAPIPathDownload {
			if r.URL.Host != "p34-buy.itunes.apple.com" || r.Header.Get("X-Dsid") != "123" || r.Header.Get("X-Token") != "fixture-token" || payload["guid"] != "020000000001" {
				t.Fatal("version history did not use the authenticated account, pod and device")
			}
			return loginFixtureResponse(t, r, 200, map[string]any{"songList": []any{map[string]any{"metadata": map[string]any{
				"softwareVersionExternalIdentifiers": []any{uint64(100), uint64(200)}, "softwareVersionExternalIdentifier": uint64(200),
			}}}}), nil
		}
		t.Fatalf("unexpected network destination: %s", r.URL)
		return nil, errors.New("unexpected request")
	})
	store := NewAppStore(Args{
		Keychain: keychain, CookieJar: authenticationTestCookieJar{jar}, Machine: loginFixtureMachine{}, Transport: transport,
		ActionSignerFactory: func(config SAPConfig, id []byte) (ActionSigner, error) {
			if config.AuthEndpoint != fixtureAuthEndpoint+"/" || config.Version != 200 || config.Transport == nil || !bytes.Equal(id, []byte{2, 0, 0, 0, 0, 1}) {
				t.Fatal("bag configuration did not reach the signer")
			}
			signer := &lifecycleSigner{}
			signers = append(signers, signer)
			return signer, nil
		},
	})
	input := LoginInput{Email: "fixture@example.invalid", Password: "fixture-password"}
	if _, err := store.Login(input); !errors.Is(err, ErrAuthCodeRequired) || len(keychain.saved) != 0 {
		t.Fatalf("2FA must require user input without saving an account: %v", err)
	}
	input.AuthCode = "12\u00a034\t56"
	output, err := store.Login(input)
	if err != nil {
		t.Fatal(err)
	}
	var saved Account
	if err := json.Unmarshal(keychain.saved, &saved); err != nil || !reflect.DeepEqual(saved, output.Account) {
		t.Fatal("saved account differs from the authenticated account")
	}
	history, err := store.ListVersions(ListVersionsInput{Account: saved, App: App{ID: 1234, BundleID: "invalid.example.fixture"}})
	if err != nil || !reflect.DeepEqual(history.ExternalVersionIdentifiers, []string{"100", "200"}) || history.LatestExternalVersionID != "200" {
		t.Fatalf("history failed after login: output=%+v err=%v", history, err)
	}
	if authCalls != 5 || bagCalls != 2 || len(signers) != 2 {
		t.Fatalf("unexpected lifecycle: auth=%d bag=%d signers=%d", authCalls, bagCalls, len(signers))
	}
	for _, signer := range signers {
		if signer.closed != 1 {
			t.Fatal("each authentication attempt must close its signer exactly once")
		}
	}
}

func TestEmpty204NeverSavesAnAccountAndHonorsCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	jar, _ := cookiejar.New(nil)
	keychain := &authenticationTestKeychain{}
	signer := &lifecycleSigner{}
	calls := 0
	store := NewAppStore(Args{
		Context: ctx, Keychain: keychain, CookieJar: authenticationTestCookieJar{jar}, Machine: loginFixtureMachine{},
		Transport: authenticationTestTransport(func(r *gohttp.Request) (*gohttp.Response, error) {
			if r.URL.Path == PrivateInitPath {
				return loginFixtureResponse(t, r, 200, loginFixtureBag()), nil
			}
			calls++
			cancel()
			return loginFixtureResponse(t, r, 204, nil), nil
		}),
		ActionSignerFactory: func(SAPConfig, []byte) (ActionSigner, error) { return signer, nil },
	})
	started := time.Now()
	_, err := store.Login(LoginInput{Email: "fixture@example.invalid", Password: "fixture-password"})
	if !errors.Is(err, context.Canceled) || calls != 1 || len(keychain.saved) != 0 || signer.closed != 1 || time.Since(started) > time.Second {
		t.Fatalf("canceled login waited, retried or saved an account: calls=%d err=%v", calls, err)
	}
}
