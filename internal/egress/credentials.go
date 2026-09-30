package egress

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"unicode/utf8"
)

// checkCredentials refuses a request that carries anything credential-like
// but the placeholder: a credential of the agent's own would reach a service
// under an identity that is not the user's, the way data has been taken out
// through allowed APIs with an attacker's key. The placeholder itself may
// only appear, whole, in Authorization or X-Api-Key, where it is dropped.
// The user's real secrets may appear nowhere.
func checkCredentials(r *http.Request, placeholder string, secrets []string) *refusal {
	for name, values := range r.Header {
		v := values[0]
		if _, cred := credentialHeaders[name]; cred {
			if !placeholderForm(name, v, placeholder) {
				return refuse(reasonCred, "%s is not the placeholder", name)
			}
			continue
		}
		if strings.Contains(v, placeholder) {
			return refuse(reasonCred, "the placeholder in %s", name)
		}
		for _, s := range secrets {
			if s != "" && strings.Contains(v, s) {
				return refuse(reasonCred, "a secret in %s", name)
			}
		}
	}
	// The target as sent, and its query as the upstream decodes it.
	targets := []string{r.RequestURI}
	if _, q, ok := strings.Cut(r.RequestURI, "?"); ok {
		if decoded, err := url.QueryUnescape(q); err == nil {
			targets = append(targets, decoded)
		}
	}
	for _, t := range targets {
		if strings.Contains(t, placeholder) {
			return refuse(reasonCred, "the placeholder in the request target")
		}
		for _, s := range secrets {
			if s != "" && strings.Contains(t, s) {
				return refuse(reasonCred, "a secret in the request target")
			}
		}
	}
	return nil
}

// placeholderForm reports whether a credential header holds the placeholder
// as Claude Code and the GitHub CLI send it, and nothing else.
func placeholderForm(name, value, placeholder string) bool {
	switch name {
	case "X-Api-Key":
		return value == placeholder
	case "Authorization":
		return value == "Bearer "+placeholder || value == "token "+placeholder
	}
	return false
}

// credentialValue formats a secret for its header.
func credentialValue(c *Credential, secret string) string {
	switch c.Scheme {
	case "Bearer", "token":
		return c.Scheme + " " + secret
	case "basic-x-access-token":
		return "Basic " + base64.StdEncoding.EncodeToString([]byte("x-access-token:"+secret))
	}
	return secret
}

// Server-side tools make Anthropic's servers fetch or run what the proxy never
// sees: a request could have them carry the user's data anywhere.
func serverTool(toolType string) bool {
	for _, prefix := range []string{"web_fetch", "code_execution", "bash_code_execution", "text_editor_code_execution", "mcp"} {
		if strings.HasPrefix(toolType, prefix) {
			return true
		}
	}
	return false
}

// firstWebSearch is the web search tool that only sends queries to
// Anthropic's search provider. Later versions let code execution call the
// search by default, which runs code on Anthropic's servers: they are
// allowed only when the tool's callers are limited to direct use.
const firstWebSearch = "web_search_20250305"

func webSearchAllowed(toolType string, tool map[string]json.RawMessage) bool {
	if toolType == firstWebSearch {
		return true
	}
	var callers []string
	raw, ok := tool["allowed_callers"]
	return ok && json.Unmarshal(raw, &callers) == nil && len(callers) == 1 && callers[0] == "direct"
}

// checkMessages reads a Messages API request body and refuses one asking
// for a server-side tool or an MCP server. The body must be one JSON object
// with no key repeated at any depth: a repeated key could be read one way
// here and another way by the API. It returns the body, to be forwarded as
// the same bytes.
func checkMessages(body io.Reader) ([]byte, *refusal) {
	b, err := io.ReadAll(body)
	if err != nil {
		var tooLarge *http.MaxBytesError
		if errors.As(err, &tooLarge) {
			return nil, refuse(reasonTooLarge, "more than %d bytes", MaxBodyBytes)
		}
		var malformed *refusal
		if errors.As(err, &malformed) {
			return nil, malformed
		}
		return nil, refuse(reasonBody, "%v", err)
	}
	// Bytes that are not UTF-8 could be read one way here and another way by
	// the API.
	if !utf8.Valid(b) {
		return nil, refuse(reasonBody, "not UTF-8")
	}
	if t := bytes.TrimLeft(b, " \t\r\n"); len(t) == 0 || t[0] != '{' {
		return nil, refuse(reasonBody, "not a JSON object")
	}
	dec := json.NewDecoder(bytes.NewReader(b))
	if err := noRepeatedKeys(dec, 0); err != nil {
		return nil, refuse(reasonBody, "%v", err)
	}
	if _, err := dec.Token(); err != io.EOF {
		return nil, refuse(reasonBody, "more than one JSON value")
	}
	// Keys are looked up exactly, through maps: Go's struct decoding matches
	// keys case-insensitively, and "Tools" read as "tools" here could hide the
	// "tools" the API reads.
	var top map[string]json.RawMessage
	if err := json.Unmarshal(b, &top); err != nil {
		return nil, refuse(reasonBody, "%v", err)
	}
	if m, ok := top["mcp_servers"]; ok {
		if v := strings.TrimSpace(string(m)); v != "null" && v != "[]" {
			return nil, refuse(reasonTool, "mcp_servers")
		}
	}
	if raw, ok := top["tools"]; ok && strings.TrimSpace(string(raw)) != "null" {
		var tools []map[string]json.RawMessage
		if err := json.Unmarshal(raw, &tools); err != nil {
			return nil, refuse(reasonBody, "tools: %v", err)
		}
		for _, tool := range tools {
			raw, ok := tool["type"]
			if !ok {
				continue // a tool of Claude Code's own, run on the agent's side
			}
			var typ string
			if err := json.Unmarshal(raw, &typ); err != nil {
				return nil, refuse(reasonBody, "a tool type that is not a string")
			}
			if serverTool(typ) || strings.HasPrefix(typ, "web_search") && !webSearchAllowed(typ, tool) {
				return nil, refuse(reasonTool, "%s", typ)
			}
		}
	}
	// Content that Anthropic's servers fetch by URL, an image or a document,
	// would carry the user's data to the URL's host, unseen by the proxy:
	// refused wherever it appears, in any turn or tool result.
	var doc any
	if err := json.Unmarshal(b, &doc); err != nil {
		return nil, refuse(reasonBody, "%v", err)
	}
	if fetchedByURL(doc, 0) {
		return nil, refuse(reasonTool, "content fetched by URL")
	}
	return b, nil
}

// fetchedByURL reports whether a JSON value holds, at any depth, an object
// whose "source" is of type "url".
func fetchedByURL(v any, depth int) bool {
	if depth > 128 {
		return true
	}
	switch v := v.(type) {
	case map[string]any:
		if src, ok := v["source"].(map[string]any); ok {
			if t, _ := src["type"].(string); t == "url" {
				return true
			}
		}
		for _, child := range v {
			if fetchedByURL(child, depth+1) {
				return true
			}
		}
	case []any:
		for _, child := range v {
			if fetchedByURL(child, depth+1) {
				return true
			}
		}
	}
	return false
}

// noRepeatedKeys walks one JSON value and fails on any object key repeated
// within its object.
func noRepeatedKeys(dec *json.Decoder, depth int) error {
	if depth > 128 {
		return errors.New("JSON nested too deeply")
	}
	tok, err := dec.Token()
	if err != nil {
		return err
	}
	switch tok {
	case json.Delim('{'):
		seen := map[string]bool{}
		for dec.More() {
			key, err := dec.Token()
			if err != nil {
				return err
			}
			// Repeated in any letter case: parsers differ on which one wins,
			// and on whether keys are matched case-insensitively.
			k := strings.ToLower(key.(string))
			if seen[k] {
				return fmt.Errorf("JSON key %q repeated", key)
			}
			seen[k] = true
			if err := noRepeatedKeys(dec, depth+1); err != nil {
				return err
			}
		}
		_, err = dec.Token()
		return err
	case json.Delim('['):
		for dec.More() {
			if err := noRepeatedKeys(dec, depth+1); err != nil {
				return err
			}
		}
		_, err = dec.Token()
		return err
	}
	return nil
}
