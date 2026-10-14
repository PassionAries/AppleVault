package sap

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"howett.net/plist"
)

func TestSetupUsesAppProxyPolicyForCertificateAndExchange(t *testing.T) {
	for _, useProxy := range []bool{false, true} {
		t.Run(map[bool]string{false: "direct", true: "proxy"}[useProxy], func(t *testing.T) {
			directRequests, proxyRequests := 0, 0
			handler := func(w http.ResponseWriter, r *http.Request) {
				if r.Method == http.MethodGet {
					body, _ := plist.Marshal(map[string]any{setupCertificateKey: []byte("certificate")}, plist.XMLFormat)
					_, _ = w.Write(body)
					return
				}
				var payload map[string]any
				requestBody, err := io.ReadAll(r.Body)
				if err != nil {
					t.Error(err)
				}
				if _, err := plist.Unmarshal(requestBody, &payload); err != nil {
					t.Error(err)
				}
				input, _ := payload[setupBufferKey].([]byte)
				if !bytes.Equal(input, []byte("setup message")) {
					t.Error("setup input changed")
				}
				body, _ := plist.Marshal(map[string]any{setupBufferKey: []byte("setup reply")}, plist.XMLFormat)
				_, _ = w.Write(body)
			}
			direct := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { directRequests++; handler(w, r) }))
			defer direct.Close()
			proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				proxyRequests++
				if r.URL.Host != "sap.example" {
					t.Errorf("proxy destination = %s", r.URL.Host)
				}
				handler(w, r)
			}))
			defer proxy.Close()
			t.Setenv("HTTP_PROXY", proxy.URL)
			t.Setenv("HTTPS_PROXY", proxy.URL)
			transport := http.DefaultTransport.(*http.Transport).Clone()
			transport.Proxy = nil
			if useProxy {
				proxyURL, _ := url.Parse(proxy.URL)
				transport.Proxy = http.ProxyURL(proxyURL)
			} else {
				directURL, _ := url.Parse(direct.URL)
				transport.DialContext = func(ctx context.Context, network, address string) (net.Conn, error) {
					if address != "sap.example:80" {
						t.Errorf("direct destination = %s", address)
					}
					return (&net.Dialer{}).DialContext(ctx, network, directURL.Host)
				}
			}
			defer transport.CloseIdleConnections()
			protocol := newSetupProtocol(Config{Transport: transport})
			certificate, err := protocol.certificate(context.Background(), "http://sap.example/certificate")
			if err != nil || string(certificate) != "certificate" {
				t.Fatalf("certificate = %q, %v", certificate, err)
			}
			reply, err := protocol.exchange(context.Background(), "http://sap.example/setup", []byte("setup message"))
			if err != nil || string(reply) != "setup reply" {
				t.Fatalf("reply = %q, %v", reply, err)
			}
			if useProxy && (proxyRequests != 2 || directRequests != 0) {
				t.Fatalf("configured proxy bypassed: direct=%d proxy=%d", directRequests, proxyRequests)
			}
			if !useProxy && (directRequests != 2 || proxyRequests != 0) {
				t.Fatalf("disabled proxy still used: direct=%d proxy=%d", directRequests, proxyRequests)
			}
			ctx, cancel := context.WithCancel(context.Background())
			cancel()
			if _, err := protocol.certificate(ctx, "http://sap.example/certificate"); !errors.Is(err, context.Canceled) {
				t.Fatalf("cancellation cause lost: %v", err)
			}
		})
	}
}
