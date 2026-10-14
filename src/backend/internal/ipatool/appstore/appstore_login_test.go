package appstore

import (
	"errors"
	gohttp "net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"AppleVault/src/backend/internal/ipatool/http"
)

func TestAuthenticationRedirectsValidateAppleEndpoint(t *testing.T) {
	for _, status := range []int{301, 302, 307, 308} {
		t.Run(strconv.Itoa(status), func(t *testing.T) {
			store := &appstore{}
			endpoint := "https://p34-buy.itunes.apple.com/WebObjects/MZFinance.woa/wa/authenticate"
			response := http.Result[loginResult]{StatusCode: status, Headers: map[string]string{"Location": endpoint}}
			retry, redirect, err := store.parseLoginResponse(&response, 1, "", "https://buy.itunes.apple.com/WebObjects/MZFinance.woa/wa/authenticate")
			if err != nil || !retry || redirect != endpoint {
				t.Fatalf("valid Apple redirect was rejected: retry=%v redirect=%q err=%v", retry, redirect, err)
			}
			response.Headers["Location"] = "https://example.com/WebObjects/MZFinance.woa/wa/authenticate"
			if retry, _, err := store.parseLoginResponse(&response, 1, "", "https://buy.itunes.apple.com/WebObjects/MZFinance.woa/wa/authenticate"); err == nil || retry {
				t.Fatal("credentials must not be redirected to an untrusted host")
			}
		})
	}
}

func TestAuthenticationErrorsIdentifyInvalidResponse(t *testing.T) {
	tests := []struct {
		name     string
		response http.Result[loginResult]
		want     string
	}{
		{name: "missing redirect", response: http.Result[loginResult]{StatusCode: 301}, want: "missing Location header (HTTP 301)"},
		{name: "empty redirect", response: http.Result[loginResult]{StatusCode: 301, Headers: map[string]string{"Location": " "}}, want: "missing Location header (HTTP 301)"},
		{name: "empty successful response", response: http.Result[loginResult]{StatusCode: gohttp.StatusOK}, want: "HTTP 200): missing login credentials"},
		{name: "unrecognized failure", response: http.Result[loginResult]{StatusCode: 200, Data: loginResult{FailureType: "1234"}}, want: "failureType 1234"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			store := &appstore{}
			retry, _, err := store.parseLoginResponse(&tt.response, 1, "", "https://buy.itunes.apple.com/WebObjects/MZFinance.woa/wa/authenticate")
			if err == nil || retry || !strings.Contains(err.Error(), tt.want) || strings.Contains(err.Error(), "something went wrong") {
				t.Fatalf("authentication error lost its cause: retry=%v err=%v", retry, err)
			}
			if got := errors.Is(err, ErrAuthenticationUnavailable); got != (tt.name != "unrecognized failure") {
				t.Fatalf("unexpected authentication failure classification: %v", err)
			}
		})
	}
	store := &appstore{}
	response := http.Result[loginResult]{StatusCode: 200, Data: loginResult{CustomerMessage: CustomerMessageBadLogin}}
	if _, _, err := store.parseLoginResponse(&response, 1, "", "https://buy.itunes.apple.com/WebObjects/MZFinance.woa/wa/authenticate"); !errors.Is(err, ErrAuthCodeRequired) {
		t.Fatalf("two-factor authentication must remain actionable: %v", err)
	}
}

type authenticationTestCookieJar struct {
	*cookiejar.Jar
}

func (authenticationTestCookieJar) Save() error { return nil }

func TestUnusableAuthenticationResponsesPreserveCauseAndBoundRetries(t *testing.T) {
	for _, scenario := range []struct {
		name      string
		statuses  []int
		wantCalls int
	}{
		{name: "observed 404 then redirect without location", statuses: []int{404, 301}, wantCalls: 2},
		{name: "repeated 404", statuses: []int{404}, wantCalls: maxAuthenticationRequestAttempts},
		{name: "repeated empty 204", statuses: []int{204}, wantCalls: maxAuthenticationRequestAttempts},
		{name: "empty forbidden", statuses: []int{403}, wantCalls: maxAuthenticationRequestAttempts},
	} {
		t.Run(scenario.name, func(t *testing.T) {
			calls := 0
			server := httptest.NewServer(gohttp.HandlerFunc(func(w gohttp.ResponseWriter, r *gohttp.Request) {
				index := calls
				if index >= len(scenario.statuses) {
					index = len(scenario.statuses) - 1
				}
				calls++
				w.Header().Set("Server", "Apple")
				w.Header().Set("Content-Type", "text/html")
				w.WriteHeader(scenario.statuses[index])
			}))
			defer server.Close()
			jar, err := cookiejar.New(nil)
			if err != nil {
				t.Fatal(err)
			}
			store := &appstore{
				loginClient:    http.NewClient[loginResult](http.Args{CookieJar: authenticationTestCookieJar{jar}, Authentication: true}),
				authRetrySleep: func(time.Duration) {},
			}
			result, err := store.sendAuthenticationRequest(http.Request{URL: server.URL, Method: http.MethodPOST, ResponseFormat: http.ResponseFormatXML})
			if err == nil {
				_, _, err = store.parseLoginResponse(&result, 1, "", server.URL)
			} else {
				var responseErr *http.UnexpectedResponseError
				if !errors.As(err, &responseErr) || responseErr.StatusCode != scenario.statuses[len(scenario.statuses)-1] {
					t.Fatalf("HTTP cause was lost: %v", err)
				}
			}
			if !errors.Is(err, ErrAuthenticationUnavailable) || calls != scenario.wantCalls {
				t.Fatalf("unusable response was not classified or retries exceeded limit: calls=%d err=%v", calls, err)
			}
		})
	}
}
