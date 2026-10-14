package http

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"regexp"
	"sort"
	"strings"
	"time"

	"howett.net/plist"
)

const appStoreAuthPath = "/WebObjects/MZFinance.woa/wa/authenticate"

const DefaultAuthenticationTimeout = 30 * time.Second

func IsAuthenticationRedirect(status int) bool {
	return status == http.StatusMovedPermanently || status == http.StatusFound || status == http.StatusTemporaryRedirect || status == http.StatusPermanentRedirect
}

var (
	documentXMLPattern = regexp.MustCompile(`(?is)<Document\b[^>]*>(.*)</Document>`)
	plistXMLPattern    = regexp.MustCompile(`(?is)<plist\b[^>]*>.*?</plist>`)
	dictXMLPattern     = regexp.MustCompile(`(?is)<dict\b[^>]*>.*</dict>`)
	htmlTagPattern     = regexp.MustCompile(`(?is)<[^>]*>`)
)

//go:generate go run go.uber.org/mock/mockgen -source=client.go -destination=client_mock.go -package=http
type Client[R interface{}] interface {
	Send(request Request) (Result[R], error)
	Do(req *http.Request) (*http.Response, error)
	NewRequest(method, url string, body io.Reader) (*http.Request, error)
}

type client[R interface{}] struct {
	internalClient   http.Client
	cookieJar        CookieJar
	context          context.Context
	diagnosticLogger DiagnosticLogger
	authentication   bool
}

type Args struct {
	CookieJar        CookieJar
	Context          context.Context
	Transport        http.RoundTripper
	DiagnosticLogger DiagnosticLogger
	Authentication   bool
	Timeout          time.Duration
}

// UnexpectedResponseError preserves the HTTP status when Apple returns an
// HTML or empty response where an XML plist was expected.
type UnexpectedResponseError struct {
	StatusCode    int
	Snippet       string
	Reason        string
	BodyLength    int
	ContentType   string
	CorrelationID string
	RetryAfter    string
}

func (e *UnexpectedResponseError) Error() string {
	if e.Reason != "" {
		return fmt.Sprintf("unexpected response from Apple (HTTP %d): %s (body length=%d, content type=%q, correlation ID=%q)", e.StatusCode, e.Reason, e.BodyLength, e.ContentType, e.CorrelationID)
	}
	if e.Snippet == "" {
		return fmt.Sprintf("unexpected response from Apple (HTTP %d): empty or non-plist body", e.StatusCode)
	}

	return fmt.Sprintf("unexpected response from Apple (HTTP %d): %s", e.StatusCode, e.Snippet)
}

type AddHeaderTransport struct {
	T http.RoundTripper
}

func (t *AddHeaderTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	if req.Header.Get("User-Agent") == "" {
		req.Header.Set("User-Agent", DefaultUserAgent)
	}

	res, err := t.T.RoundTrip(req)
	if err != nil {
		return nil, fmt.Errorf("failed to make round trip: %w", err)
	}

	return res, nil
}

func NewClient[R interface{}](args Args) Client[R] {
	ctx := args.Context
	if ctx == nil {
		ctx = context.Background()
	}
	transport := args.Transport
	if transport == nil {
		transport = http.DefaultTransport
	}
	timeout := args.Timeout
	if args.Authentication {
		if timeout == 0 {
			timeout = DefaultAuthenticationTimeout
		}
		if base, ok := transport.(*http.Transport); ok {
			isolated := base.Clone()
			isolated.DisableKeepAlives = true
			isolated.DialContext = (&net.Dialer{Timeout: 15 * time.Second, KeepAlive: 30 * time.Second}).DialContext
			transport = isolated
		}
	}
	return &client[R]{
		internalClient: http.Client{
			Timeout: timeout,
			Jar:     args.CookieJar,
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				if args.Authentication || (len(via) > 0 && (via[len(via)-1].URL.Path == appStoreAuthPath || via[len(via)-1].URL.Path == appStoreAuthPath+"/")) {
					return http.ErrUseLastResponse
				}

				return nil
			},
			Transport: &AddHeaderTransport{transport},
		},
		cookieJar:        args.CookieJar,
		context:          ctx,
		diagnosticLogger: args.DiagnosticLogger,
		authentication:   args.Authentication,
	}
}

func (c *client[R]) Send(req Request) (output Result[R], sendErr error) {
	id := diagnosticRequestID.Add(1)
	started := time.Now()
	defer func() {
		fields := map[string]interface{}{"request_id": id, "elapsed_ms": time.Since(started).Milliseconds(), "endpoint": DiagnosticURL(req.URL)}
		if sendErr != nil {
			fields["error"] = sendErr.Error()
		}
		c.trace("http.complete", fields)
	}()
	var (
		data []byte
		err  error
	)

	if req.Payload != nil {
		data, err = req.Payload.data()
		if err != nil {
			return Result[R]{}, fmt.Errorf("failed to get payload data: %w", err)
		}
	}

	request, err := http.NewRequestWithContext(c.context, req.Method, req.URL, bytes.NewReader(data))
	if err != nil {
		return Result[R]{}, fmt.Errorf("failed to create request: %w", err)
	}

	for key, val := range req.Headers {
		request.Header.Set(key, val)
	}

	if req.ActionSigner != nil {
		signature, err := req.ActionSigner.Sign(data)
		if err != nil {
			return Result[R]{}, fmt.Errorf("failed to sign Apple action: %w", err)
		}

		request.Header.Set(HeaderAppleActionSignature, base64.StdEncoding.EncodeToString(signature))
	}
	if request.Header.Get("User-Agent") == "" {
		request.Header.Set("User-Agent", DefaultUserAgent)
	}
	requestFields := diagnosticRequestFields(request, id)
	if c.internalClient.Jar != nil {
		requestFields["cookie_count"] = len(request.Cookies()) + len(c.internalClient.Jar.Cookies(request.URL))
	}
	if payload, ok := req.Payload.(*XMLPayload); ok {
		keys := make([]string, 0, len(payload.Content))
		for key := range payload.Content {
			keys = append(keys, key)
		}
		sort.Strings(keys)
		requestFields["payload_format"] = "xml_plist"
		requestFields["payload_keys"] = keys
		if attempt, ok := payload.Content["attempt"]; ok {
			requestFields["auth_attempt"] = attempt
		}
	}
	c.trace("http.request", requestFields)

	res, err := c.internalClient.Do(request)
	if err != nil {
		return Result[R]{}, fmt.Errorf("request failed: %w", &TransportError{Err: err})
	}
	defer res.Body.Close()
	c.trace("http.response", diagnosticResponseFields(res, id))
	if c.diagnosticLogger != nil && req.ResponseFormat != ResponseFormatRaw {
		body, err := io.ReadAll(res.Body)
		if err != nil {
			return Result[R]{}, fmt.Errorf("failed to read response body: %w", &TransportError{Err: err, RetryAfter: res.Header.Get("Retry-After")})
		}
		res.Body = io.NopCloser(bytes.NewReader(body))
		fields := diagnosticBodySummary(body, req.ResponseFormat)
		fields["request_id"] = id
		c.trace("http.body_summary", fields)
	}

	err = c.cookieJar.Save()
	if err != nil {
		return Result[R]{}, fmt.Errorf("failed to save cookies: %w", err)
	}

	if req.ResponseFormat == ResponseFormatJSON {
		return c.handleJSONResponse(res)
	}

	if req.ResponseFormat == ResponseFormatRaw {
		return c.handleRawResponse(res)
	}

	if req.ResponseFormat == ResponseFormatXML {
		return c.handleXMLResponse(res)
	}

	return Result[R]{}, fmt.Errorf("content type is not supported (%s)", req.ResponseFormat)
}

func (c *client[R]) handleRawResponse(res *http.Response) (Result[R], error) {
	body, err := io.ReadAll(res.Body)
	if err != nil {
		return Result[R]{}, fmt.Errorf("failed to read response body: %w", err)
	}

	data, ok := any(body).(R)
	if !ok {
		return Result[R]{}, errors.New("raw response format requires a []byte result type")
	}

	return Result[R]{
		StatusCode: res.StatusCode,
		Headers:    responseHeaders(res),
		Data:       data,
	}, nil
}

func (c *client[R]) Do(req *http.Request) (*http.Response, error) {
	id := diagnosticRequestID.Add(1)
	started := time.Now()
	if req.Header.Get("User-Agent") == "" {
		req.Header.Set("User-Agent", DefaultUserAgent)
	}
	c.trace("http.stream_request", diagnosticRequestFields(req, id))
	res, err := c.internalClient.Do(req)
	if err != nil {
		c.trace("http.stream_error", map[string]interface{}{"request_id": id, "error": err.Error(), "elapsed_ms": time.Since(started).Milliseconds()})
		return nil, fmt.Errorf("received error: %w", err)
	}
	fields := diagnosticResponseFields(res, id)
	fields["elapsed_ms"] = time.Since(started).Milliseconds()
	fields["content_range"] = res.Header.Get("Content-Range")
	c.trace("http.stream_response", fields)

	return res, nil
}

func (c *client[R]) NewRequest(method, url string, body io.Reader) (*http.Request, error) {
	req, err := http.NewRequestWithContext(c.context, method, url, body)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	return req, nil
}

func (c *client[R]) handleJSONResponse(res *http.Response) (Result[R], error) {
	body, err := io.ReadAll(res.Body)
	if err != nil {
		return Result[R]{}, fmt.Errorf("failed to read response body: %w", err)
	}

	var data R

	err = json.Unmarshal(body, &data)
	if err != nil {
		return Result[R]{}, fmt.Errorf("failed to unmarshal json: %w", err)
	}

	return Result[R]{
		StatusCode: res.StatusCode,
		Data:       data,
	}, nil
}

func (c *client[R]) handleXMLResponse(res *http.Response) (Result[R], error) {
	body, err := io.ReadAll(res.Body)
	if err != nil {
		return Result[R]{}, fmt.Errorf("failed to read response body: %w", &TransportError{Err: err, RetryAfter: res.Header.Get("Retry-After")})
	}

	if c.authentication && IsAuthenticationRedirect(res.StatusCode) && strings.TrimSpace(res.Header.Get("Location")) == "" {
		return Result[R]{}, authenticationResponseError(res, body, "authentication redirect is missing Location")
	}
	if !c.authentication && res.StatusCode == http.StatusTooManyRequests {
		return Result[R]{}, fmt.Errorf("rate limited by Apple (HTTP %d): %s", res.StatusCode, strings.TrimSpace(string(body)))
	}

	// The legacy authentication endpoint redirects to an assigned Store pod.
	// Preserve the redirect response and its Location header so callers can
	// repeat the original POST request at that pod.
	if res.StatusCode >= http.StatusMultipleChoices && res.StatusCode < http.StatusBadRequest {
		return Result[R]{
			StatusCode: res.StatusCode,
			Headers:    responseHeaders(res),
		}, nil
	}

	var data R

	normalizedBody := normalizeXMLPlistBody(body)

	if !looksLikePropertyList(normalizedBody) {
		if c.authentication {
			return Result[R]{}, authenticationResponseError(res, body, "empty or non-plist authentication response")
		}
		snippet := bodySnippet(body)

		return Result[R]{}, &UnexpectedResponseError{
			StatusCode: res.StatusCode,
			Snippet:    snippet,
		}
	}

	_, err = plist.Unmarshal(normalizedBody, &data)
	if err != nil {
		if c.authentication {
			return Result[R]{}, authenticationResponseError(res, body, "malformed authentication plist")
		}
		return Result[R]{}, fmt.Errorf("failed to unmarshal xml: %w", err)
	}

	return Result[R]{
		StatusCode: res.StatusCode,
		Headers:    responseHeaders(res),
		Data:       data,
	}, nil
}

func authenticationResponseError(res *http.Response, body []byte, reason string) *UnexpectedResponseError {
	return &UnexpectedResponseError{
		StatusCode: res.StatusCode, Reason: reason, BodyLength: len(body),
		ContentType:   bodySnippet([]byte(res.Header.Get("Content-Type"))),
		CorrelationID: bodySnippet([]byte(res.Header.Get("X-Apple-Jingle-Correlation-Key"))),
		RetryAfter:    res.Header.Get("Retry-After"),
	}
}

func responseHeaders(res *http.Response) map[string]string {
	headers := map[string]string{}
	for key, val := range res.Header {
		headers[key] = strings.Join(val, "; ")
	}

	return headers
}

func normalizeXMLPlistBody(body []byte) []byte {
	normalized := bytes.TrimSpace(body)
	if len(normalized) == 0 {
		return normalized
	}

	if documentBody := extractDocumentInnerBody(normalized); len(documentBody) > 0 {
		normalized = documentBody
	}

	if embeddedPlist := extractEmbeddedPlist(normalized); len(embeddedPlist) > 0 {
		normalized = embeddedPlist
	}

	if dictBody := extractEmbeddedDict(normalized); len(dictBody) > 0 {
		return dictBody
	}

	if bytes.Contains(normalized, []byte("<key>")) {
		return []byte("<dict>" + string(normalized) + "</dict>")
	}

	return normalized
}

// looksLikePropertyList reports whether body appears to be a (binary or XML)
// property list. Apple occasionally answers with an HTML error page or a plain
// text message; those must not be handed to plist.Unmarshal, which would
// misinterpret a leading "<h..." as an OpenStep hex-data block and fail with an
// opaque "unexpected hex digit" error instead of surfacing Apple's actual response.
func looksLikePropertyList(body []byte) bool {
	trimmed := bytes.TrimSpace(body)
	if len(trimmed) == 0 {
		return false
	}

	if bytes.HasPrefix(trimmed, []byte("bplist")) {
		return true
	}

	lower := bytes.ToLower(trimmed)
	for _, marker := range [][]byte{
		[]byte("<?xml"),
		[]byte("<plist"),
		[]byte("<dict"),
		[]byte("<key"),
	} {
		if bytes.Contains(lower, marker) {
			return true
		}
	}

	return false
}

// bodySnippet returns a compact, single-line excerpt of a non-plist response
// body suitable for embedding in an error message. HTML markup is stripped so
// the underlying message (if any) is readable.
func bodySnippet(body []byte) string {
	text := htmlTagPattern.ReplaceAll(body, []byte(" "))
	snippet := strings.Join(strings.Fields(string(text)), " ")

	const maxLen = 200
	if len(snippet) > maxLen {
		snippet = snippet[:maxLen] + "…"
	}

	return snippet
}

func extractEmbeddedPlist(body []byte) []byte {
	plistMatch := plistXMLPattern.Find(body)
	if len(plistMatch) == 0 {
		return nil
	}

	return bytes.TrimSpace(plistMatch)
}

func extractEmbeddedDict(body []byte) []byte {
	dictMatch := dictXMLPattern.Find(body)
	if len(dictMatch) == 0 {
		return nil
	}

	return bytes.TrimSpace(dictMatch)
}

func extractDocumentInnerBody(body []byte) []byte {
	documentMatch := documentXMLPattern.FindSubmatch(body)
	if len(documentMatch) < 2 {
		return nil
	}

	documentBody := bytes.TrimSpace(documentMatch[1])
	if len(documentBody) == 0 {
		return nil
	}

	return documentBody
}
