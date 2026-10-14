package http

import (
	"errors"
	gohttp "net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

func TestAuthenticationIsolatesConnectionsWithoutDiscardingConfiguredProxy(t *testing.T) {
	var remoteAddresses []string
	proxy := httptest.NewServer(gohttp.HandlerFunc(func(w gohttp.ResponseWriter, r *gohttp.Request) {
		remoteAddresses = append(remoteAddresses, r.RemoteAddr)
		_, _ = w.Write([]byte("<plist version=\"1.0\"><dict/></plist>"))
	}))
	defer proxy.Close()
	proxyURL, _ := url.Parse(proxy.URL)
	base := gohttp.DefaultTransport.(*gohttp.Transport).Clone()
	base.Proxy = gohttp.ProxyURL(proxyURL)
	client := NewClient[map[string]interface{}](Args{CookieJar: testCookieJar{}, Transport: base, Authentication: true})
	for range 2 {
		if _, err := client.Send(Request{URL: "http://apple.example/authenticate", Method: MethodPOST, ResponseFormat: ResponseFormatXML}); err != nil {
			t.Fatal(err)
		}
	}
	if len(remoteAddresses) != 2 || remoteAddresses[0] == remoteAddresses[1] || base.DisableKeepAlives {
		t.Fatalf("login reused connections or mutated the shared transport: %v", remoteAddresses)
	}
}

func TestMissingAuthenticationRedirectExcludesResponseSecrets(t *testing.T) {
	server := httptest.NewServer(gohttp.HandlerFunc(func(w gohttp.ResponseWriter, r *gohttp.Request) {
		w.WriteHeader(301)
		_, _ = w.Write([]byte("private-password private-token"))
	}))
	defer server.Close()
	client := NewClient[map[string]interface{}](Args{CookieJar: testCookieJar{}, Authentication: true})
	_, err := client.Send(Request{URL: server.URL, Method: MethodPOST, ResponseFormat: ResponseFormatXML})
	var responseErr *UnexpectedResponseError
	if !errors.As(err, &responseErr) || responseErr.StatusCode != 301 || !strings.Contains(responseErr.Reason, "missing Location") || strings.Contains(err.Error(), "private-") {
		t.Fatalf("redirect error lost cause or exposed secrets: %v", err)
	}
}
