package http

import (
	"encoding/json"
	gohttp "net/http"
	"net/url"
	"sort"
	"sync/atomic"

	"howett.net/plist"
)

type DiagnosticLogger func(event string, fields map[string]interface{})

var diagnosticRequestID atomic.Uint64

// DiagnosticURL deliberately omits credentials, query strings and fragments.
func DiagnosticURL(value string) string {
	parsed, err := url.Parse(value)
	if err != nil || parsed.Host == "" {
		return "[invalid URL]"
	}
	return parsed.Scheme + "://" + parsed.Host + parsed.EscapedPath()
}

func (c *client[R]) trace(event string, fields map[string]interface{}) {
	if c.diagnosticLogger != nil {
		c.diagnosticLogger(event, fields)
	}
}

func diagnosticRequestFields(req *gohttp.Request, id uint64) map[string]interface{} {
	return map[string]interface{}{
		"request_id": id, "method": req.Method, "endpoint": DiagnosticURL(req.URL.String()),
		"body_bytes": req.ContentLength, "user_agent": req.Header.Get("User-Agent"),
		"content_type": req.Header.Get("Content-Type"),
		"signed":       req.Header.Get(HeaderAppleActionSignature) != "", "signature_chars": len(req.Header.Get(HeaderAppleActionSignature)),
		"has_token": req.Header.Get("X-Token") != "", "has_dsid": req.Header.Get("X-Dsid") != "",
		"cookie_count": len(req.Cookies()),
	}
}

func diagnosticResponseFields(res *gohttp.Response, id uint64) map[string]interface{} {
	fields := map[string]interface{}{
		"request_id": id, "status": res.StatusCode, "content_type": res.Header.Get("Content-Type"),
		"content_length": res.ContentLength, "server": res.Header.Get("Server"),
		"apple_request_id":         res.Header.Get("X-Apple-Request-Uuid"),
		"apple_originating_system": res.Header.Get("Apple-Originating-System"),
		"has_apple_correlation_id": res.Header.Get("X-Apple-Jingle-Correlation-Key") != "",
		"has_location":             res.Header.Get("Location") != "",
	}
	if res.Request != nil {
		fields["endpoint"] = DiagnosticURL(res.Request.URL.String())
	}
	if location := res.Header.Get("Location"); location != "" {
		fields["location"] = DiagnosticURL(location)
	}
	return fields
}

// Summaries never serialize full plist/JSON responses or authentication values.
func diagnosticBodySummary(body []byte, format ResponseFormat) map[string]interface{} {
	fields := map[string]interface{}{"body_bytes": len(body)}
	var document map[string]interface{}
	var err error
	if format == ResponseFormatXML {
		if !looksLikePropertyList(normalizeXMLPlistBody(body)) {
			fields["non_plist_preview"] = bodySnippet(body)
			return fields
		}
		_, err = plist.Unmarshal(normalizeXMLPlistBody(body), &document)
	} else if format == ResponseFormatJSON {
		err = json.Unmarshal(body, &document)
	} else {
		return fields
	}
	if err != nil {
		fields["decode_failed"] = true
		return fields
	}
	keys := make([]string, 0, len(document))
	for key := range document {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	fields["root_key_count"] = len(keys)
	if len(keys) > 20 {
		keys = keys[:20]
	}
	fields["root_keys"] = keys
	for _, key := range []string{"failureType", "customerMessage", "resultCount"} {
		if value, ok := document[key]; ok {
			fields[key] = value
		}
	}
	token, _ := document["passwordToken"].(string)
	dsid, _ := document["dsPersonId"].(string)
	fields["has_password_token"] = token != ""
	fields["has_account_id"] = dsid != ""
	if songs, ok := document["songList"].([]interface{}); ok {
		fields["song_count"] = len(songs)
		if len(songs) > 0 {
			if song, ok := songs[0].(map[string]interface{}); ok {
				if metadata, ok := song["metadata"].(map[string]interface{}); ok {
					if versions, ok := metadata["softwareVersionExternalIdentifiers"].([]interface{}); ok {
						fields["history_count"] = len(versions)
					}
				}
			}
		}
	}
	return fields
}
