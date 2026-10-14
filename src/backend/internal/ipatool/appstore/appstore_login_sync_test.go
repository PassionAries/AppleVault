package appstore

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"io"
	gohttp "net/http"
	"net/http/cookiejar"
	"strings"
	"testing"
	"time"

	"AppleVault/src/backend/internal/ipatool/http"
	"howett.net/plist"
)

type authenticationTestTransport func(*gohttp.Request) (*gohttp.Response, error)

func (f authenticationTestTransport) RoundTrip(r *gohttp.Request) (*gohttp.Response, error) {
	return f(r)
}

type authenticationTestKeychain struct{ saved []byte }

func (s *authenticationTestKeychain) Get(string) ([]byte, error)       { return s.saved, nil }
func (s *authenticationTestKeychain) Set(_ string, value []byte) error { s.saved = value; return nil }
func (s *authenticationTestKeychain) Remove(string) error              { return nil }

type authenticationTestSigner struct{}

func (authenticationTestSigner) Sign(body []byte) ([]byte, error) {
	sum := sha256.Sum256(body)
	return sum[:], nil
}
func (authenticationTestSigner) Close() error { return nil }

func TestCredentialRetryAndPodRedirectsKeepSignedBodyCookiesAndPhoneStorefront(t *testing.T) {
	endpoint := "https://buy.itunes.apple.com/WebObjects/MZFinance.woa/wa/authenticate"
	podEndpoint := "https://p34-buy.itunes.apple.com/WebObjects/MZFinance.woa/wa/authenticate/"
	jar, _ := cookiejar.New(nil)
	var attempts []string
	var bodies [][]byte
	transport := authenticationTestTransport(func(r *gohttp.Request) (*gohttp.Response, error) {
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Fatal(err)
		}
		var payload map[string]string
		if _, err := plist.Unmarshal(body, &payload); err != nil {
			t.Fatal(err)
		}
		attempts = append(attempts, payload["attempt"])
		bodies = append(bodies, body)
		sum := sha256.Sum256(body)
		if r.Method != gohttp.MethodPost || r.Header.Get(http.HeaderAppleActionSignature) != base64.StdEncoding.EncodeToString(sum[:]) || payload["password"] != "password123456" || r.Header.Get("X-Apple-Store-Front") != "143465" {
			t.Fatalf("signed credentials or phone routing changed at request %d", len(attempts))
		}
		if len(attempts) > 1 {
			if cookie, err := r.Cookie("session"); err != nil || cookie.Value != "kept" {
				t.Fatalf("redirect lost session cookie: %v", err)
			}
		}
		response := &gohttp.Response{StatusCode: 200, Header: make(gohttp.Header), Request: r}
		document := map[string]interface{}{}
		switch len(attempts) {
		case 1:
			document["failureType"] = FailureTypeInvalidCredentials
			response.Header.Set("Set-Cookie", "session=kept; Domain=itunes.apple.com; Path=/; Secure")
		case 2:
			response.StatusCode = 307
			response.Header.Set("Location", PrivateAppStoreAPIPathAuth+"/")
		case 3:
			if r.URL.String() != endpoint+"/" {
				t.Fatalf("relative redirect resolved incorrectly: %s", r.URL)
			}
			response.StatusCode = 302
			response.Header.Set("Location", podEndpoint)
		case 4:
			if r.URL.String() != podEndpoint {
				t.Fatalf("pod redirect resolved incorrectly: %s", r.URL)
			}
			document = map[string]interface{}{"passwordToken": "token", "dsPersonId": "123", "accountInfo": map[string]interface{}{"appleId": "+8613912345678"}}
			response.Header.Set(HTTPHeaderStoreFront, "143465-1,29")
		default:
			t.Fatal("unexpected additional authentication request")
		}
		encoded, _ := plist.Marshal(document, plist.XMLFormat)
		response.Body = io.NopCloser(bytes.NewReader(encoded))
		return response, nil
	})
	keychain := &authenticationTestKeychain{}
	store := &appstore{keychain: keychain, loginClient: http.NewClient[loginResult](http.Args{CookieJar: authenticationTestCookieJar{jar}, Transport: transport, Authentication: true})}
	account, err := store.login("+8613912345678", "password", "123456", "001122334455", endpoint, authenticationTestSigner{})
	if err != nil || account.PasswordToken != "token" || len(keychain.saved) == 0 || strings.Join(attempts, ",") != "1,2,2,2" {
		t.Fatalf("pod login did not complete correctly: attempts=%v err=%v", attempts, err)
	}
	if !bytes.Equal(bodies[1], bodies[2]) || !bytes.Equal(bodies[2], bodies[3]) {
		t.Fatal("redirect changed the original signed request body")
	}
}

func TestAuthenticationRetryAfterExceedsBudgetWithoutEarlyRetry(t *testing.T) {
	jar, _ := cookiejar.New(nil)
	calls, waits := 0, 0
	store := &appstore{
		loginClient: http.NewClient[loginResult](http.Args{CookieJar: authenticationTestCookieJar{jar}, Authentication: true, Transport: authenticationTestTransport(func(r *gohttp.Request) (*gohttp.Response, error) {
			calls++
			return &gohttp.Response{StatusCode: 429, Header: gohttp.Header{"Retry-After": []string{"3600"}}, Request: r, Body: io.NopCloser(strings.NewReader(""))}, nil
		})}),
		authRetrySleep: func(time.Duration) { waits++ },
	}
	_, err := store.sendAuthenticationRequest(http.Request{Method: http.MethodPOST, URL: "https://buy.itunes.apple.com/WebObjects/MZFinance.woa/wa/authenticate", ResponseFormat: http.ResponseFormatXML})
	if err == nil || calls != 1 || waits != 0 || !strings.Contains(err.Error(), "try again later") {
		t.Fatalf("Retry-After was ignored: calls=%d waits=%d err=%v", calls, waits, err)
	}
}

func TestAuthCodeAndPhoneStorefrontMatchUpstream(t *testing.T) {
	if code, err := normalizeAuthCode("12\u00a034\t56"); err != nil || code != "123456" {
		t.Fatalf("pasted code was not normalized: code=%q err=%v", code, err)
	}
	if _, err := normalizeAuthCode("12345"); err == nil {
		t.Fatal("invalid verification code was accepted")
	}
	for input, want := range map[string]string{"user@example.com": "", "+86 139-1234-5678": "143465", "+91 9123456789": "143467", "+44 7912345678": ""} {
		if got := phoneNumberStorefront(input); got != want {
			t.Fatalf("phone storefront %q = %q, want %q", input, got, want)
		}
	}
}
