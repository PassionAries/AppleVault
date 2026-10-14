package backend

import (
	"encoding/json"
	"html"
	"net/url"
	"os"
	"strings"
	"sync"
	"testing"
)

func TestDiagnosticLogRedactsSecretsAndRemainsValidJSON(t *testing.T) {
	a := &App{dataDirOverride: t.TempDir()}
	password := `secret&password"with\escapes`
	a.addDiagnosticSecrets(password, "123456", "session-token", "test@example.com")
	a.writeDiagnostic("test.failure", map[string]interface{}{
		"error":  "login for test@example.com: " + password,
		"nested": map[string]interface{}{"html": html.EscapeString(password), "query": url.QueryEscape(password)},
		"values": []string{"session-token", "123456"}, "status": 404,
		"download_error": `Get "https://cdn.apple.com/a.ipa?token=unregistered-signed-token": denied`,
	})
	data, err := os.ReadFile(a.diagnosticLogPath())
	if err != nil {
		t.Fatal(err)
	}
	var row map[string]interface{}
	if err := json.Unmarshal(data, &row); err != nil {
		t.Fatalf("redaction corrupted JSON: %v", err)
	}
	for _, secret := range []string{"secret", "session-token", "123456", "test@example.com", url.QueryEscape(password), "unregistered-signed-token"} {
		if strings.Contains(string(data), secret) {
			t.Fatalf("diagnostic log exposed %q", secret)
		}
	}
	if !strings.Contains(string(data), "[redacted]") || !strings.Contains(string(data), "404") {
		t.Fatal("redaction must preserve useful status information")
	}
}

func TestConcurrentDiagnosticWritesProduceCompleteLines(t *testing.T) {
	a := &App{dataDirOverride: t.TempDir()}
	var group sync.WaitGroup
	for i := 0; i < 20; i++ {
		group.Add(1)
		go func(i int) {
			defer group.Done()
			a.writeDiagnostic("test.concurrent", map[string]interface{}{"sequence": i})
		}(i)
	}
	group.Wait()
	data, err := os.ReadFile(a.diagnosticLogPath())
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSpace(string(data)), "\n")
	if len(lines) != 20 {
		t.Fatalf("lost log events: got %d", len(lines))
	}
	for _, line := range lines {
		if !json.Valid([]byte(line)) {
			t.Fatal("concurrent writes interleaved JSON records")
		}
	}
}
