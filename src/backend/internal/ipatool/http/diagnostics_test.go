package http

import (
	"context"
	"encoding/json"
	gohttp "net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"howett.net/plist"
)

func TestHTTPDiagnosticTracePreservesResponseWithoutLoggingCredentials(t *testing.T) {
	server := httptest.NewServer(gohttp.HandlerFunc(func(w gohttp.ResponseWriter, r *gohttp.Request) {
		w.Header().Set("Content-Type", "application/x-apple-plist")
		body, _ := plist.Marshal(map[string]interface{}{"passwordToken": "private-response-token", "dsPersonId": "private-dsid"}, plist.XMLFormat)
		_, _ = w.Write(body)
	}))
	defer server.Close()
	var events []string
	var fields []map[string]interface{}
	client := NewClient[map[string]interface{}](Args{CookieJar: testCookieJar{}, Context: context.Background(), DiagnosticLogger: func(event string, row map[string]interface{}) {
		events = append(events, event)
		fields = append(fields, row)
	}})
	result, err := client.Send(Request{
		URL: server.URL + "/authenticate?token=private-query-token", Method: MethodPOST, ResponseFormat: ResponseFormatXML,
		Headers: map[string]string{"X-Token": "private-request-token", "Cookie": "session=private-cookie"},
		Payload: &XMLPayload{Content: map[string]interface{}{"password": "private-password", "appleId": "private@example.com", "attempt": "1"}},
	})
	if err != nil || result.Data["passwordToken"] != "private-response-token" {
		t.Fatalf("logging changed the response: %v", err)
	}
	encoded, _ := json.Marshal(fields)
	for _, secret := range []string{"private-response-token", "private-dsid", "private-query-token", "private-request-token", "private-cookie", "private-password", "private@example.com"} {
		if strings.Contains(string(encoded), secret) {
			t.Fatalf("HTTP log exposed %q", secret)
		}
	}
	if len(events) != 4 || events[0] != "http.request" || events[1] != "http.response" || events[3] != "http.complete" {
		t.Fatalf("missing HTTP trace: %v", events)
	}
}

func TestHTTPDiagnosticTraceIncludes404Response(t *testing.T) {
	server := httptest.NewServer(gohttp.HandlerFunc(func(w gohttp.ResponseWriter, r *gohttp.Request) {
		w.WriteHeader(404)
		_, _ = w.Write([]byte("<html><title>404 Not Found</title></html>"))
	}))
	defer server.Close()
	var records []map[string]interface{}
	client := NewClient[map[string]interface{}](Args{CookieJar: testCookieJar{}, DiagnosticLogger: func(_ string, fields map[string]interface{}) { records = append(records, fields) }})
	_, err := client.Send(Request{URL: server.URL, Method: MethodGET, ResponseFormat: ResponseFormatXML})
	if err == nil {
		t.Fatal("unexpected response must remain an error")
	}
	if records[1]["status"] != 404 || records[2]["non_plist_preview"] != "404 Not Found" || records[3]["error"] == nil {
		t.Fatalf("404 cause is missing from the trace: %v", records)
	}
}
