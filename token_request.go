/*
 *  Copyright (c) 2026, WSO2 LLC. (http://www.wso2.org) All Rights Reserved.
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 *
 */

// Token-endpoint HTTP plumbing: one POST helper shared by every step, an RFC
// 7009 revocation helper, bounded retry with jittered backoff, a process-wide
// transport registry keyed by proxy/TLS configuration, logging hygiene, and
// the parameter accessors.
package mcpauthidjag

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/rand"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	// defaultTokenRequestTimeout bounds a token-endpoint HTTP call so a hung server can't block indefinitely.
	defaultTokenRequestTimeout = 10 * time.Second

	// defaultTokenTTLFallback is used when a cacheable token response omits expires_in.
	defaultTokenTTLFallback = time.Hour

	// defaultHeaderName is the header the Resource AS access token is injected into when headerName is omitted.
	defaultHeaderName = "Authorization"

	// defaultValuePrefix is prepended to the injected value when valuePrefix is omitted; an
	// explicitly configured empty string is honored as "no prefix".
	defaultValuePrefix = "Bearer"

	// defaultTokenRequestMaxRetries bounds fetchWithRetry's retries on a transient token-endpoint error.
	defaultTokenRequestMaxRetries = 2

	// retryBaseDelay/retryMaxDelay bound fetchWithRetry's exponential backoff, with jitter
	// so replicas don't retry a struggling server in lockstep.
	retryBaseDelay = 100 * time.Millisecond
	retryMaxDelay  = 2 * time.Second

	// maxTokenResponseBytes bounds how much of a token response is read, regardless of
	// Content-Length, so a misbehaving server can't exhaust memory.
	maxTokenResponseBytes = 1 << 20 // 1MiB

	// revocationTimeout bounds the best-effort refresh-token revocation that runs after the
	// ID-JAG is issued; it is detached from the request context so a client disconnect never
	// leaves a live refresh token behind.
	revocationTimeout = 5 * time.Second
)

// defaultPurgeStatusCodes is applied when tokenPurgeStatusCodes is omitted. 401 is the standard
// signal (RFC 6750 §3) that a bearer token was rejected as invalid.
var defaultPurgeStatusCodes = []int{http.StatusUnauthorized}

// Token is the subset of an RFC 6749 §5.1 / RFC 8693 §2.2.1 token response the policy needs.
// For the ID-JAG exchange AccessToken carries the ID-JAG itself (the profile reuses the field).
type Token struct {
	AccessToken     string
	TokenType       string
	RefreshToken    string
	IssuedTokenType string
	Scope           string
	Expiry          time.Time
}

// TokenError represents an RFC 6749 §5.2 error response FROM the token endpoint, as opposed to a
// network-level failure that never got a response at all. CorrelationID carries the server's
// correlation_id when present, for log correlation with the other side.
type TokenError struct {
	StatusCode       int
	ErrorCode        string
	ErrorDescription string
	CorrelationID    string
}

// nonRetryableTokenError wraps a token-response error that retrying can never fix: a malformed
// body or a well-formed-but-incomplete response. Distinct from *TokenError (a definitive rejection
// FROM the token endpoint, retryable only on 429/5xx) and from a plain network/build-request
// error (retryable by default) - see isRetryableTokenError.
type nonRetryableTokenError struct {
	err error
}

func (e *nonRetryableTokenError) Error() string { return e.err.Error() }
func (e *nonRetryableTokenError) Unwrap() error { return e.err }

func (e *TokenError) Error() string {
	switch {
	case e.ErrorDescription != "":
		return fmt.Sprintf("token endpoint returned %d %s: %s", e.StatusCode, e.ErrorCode, e.ErrorDescription)
	case e.ErrorCode != "":
		return fmt.Sprintf("token endpoint returned %d %s", e.StatusCode, e.ErrorCode)
	default:
		return fmt.Sprintf("token endpoint returned status %d", e.StatusCode)
	}
}

// clientAuthStyle mirrors clientAuthMethod as a type doTokenRequest can switch on.
type clientAuthStyle int

const (
	authStyleInHeader clientAuthStyle = iota // client_secret_basic: HTTP Basic auth
	authStyleInParams                        // client_secret_post: client_id/client_secret as form fields
)

// authStyleFor maps clientAuthMethod to the style doTokenRequest consumes.
func authStyleFor(method string) clientAuthStyle {
	if method == ClientAuthMethodBasic {
		return authStyleInHeader
	}
	return authStyleInParams
}

// clientCredential is one confidential-client registration plus how it authenticates.
type clientCredential struct {
	id     string
	secret string
	style  clientAuthStyle
}

// tokenJSON is the raw shape of a token response. ExpiresIn is left as json.RawMessage since
// some servers send it as a JSON string instead of a number.
type tokenJSON struct {
	AccessToken     string          `json:"access_token"`
	TokenType       string          `json:"token_type"`
	RefreshToken    string          `json:"refresh_token"`
	IssuedTokenType string          `json:"issued_token_type"`
	Scope           string          `json:"scope"`
	ExpiresIn       json.RawMessage `json:"expires_in"`
}

func (t tokenJSON) expiresInSeconds() (int64, bool) {
	if len(t.ExpiresIn) == 0 {
		return 0, false
	}
	var n int64
	if err := json.Unmarshal(t.ExpiresIn, &n); err == nil {
		return n, true
	}
	var s string
	if err := json.Unmarshal(t.ExpiresIn, &s); err == nil {
		if n, err := strconv.ParseInt(strings.TrimSpace(s), 10, 64); err == nil {
			return n, true
		}
	}
	return 0, false
}

// doTokenRequest POSTs form to tokenEndpoint and parses the response. cred selects how the
// client authenticates (HTTP Basic header vs client_id/client_secret form fields); extraHeaders
// is applied last, skipping Authorization/Content-Type so it can never override them.
// id/secret are form-urlencoded before being combined into the Basic credential
// (RFC 6749 Appendix B) - a raw base64(id+":"+secret) would mishandle a colon in either value.
func doTokenRequest(ctx context.Context, httpClient *http.Client, tokenEndpoint string, cred clientCredential,
	form url.Values, extraHeaders map[string]string) (*Token, error) {
	resp, body, err := postForm(ctx, httpClient, tokenEndpoint, cred, form, extraHeaders)
	if err != nil {
		return nil, err
	}

	if resp.StatusCode != http.StatusOK {
		return nil, tokenErrorFrom(resp.StatusCode, body)
	}

	var parsed tokenJSON
	if err := json.Unmarshal(body, &parsed); err != nil {
		return nil, &nonRetryableTokenError{err: fmt.Errorf("decoding token response: %w", err)}
	}
	if parsed.AccessToken == "" {
		return nil, &nonRetryableTokenError{err: fmt.Errorf("token endpoint response is missing access_token")}
	}

	tok := &Token{
		AccessToken:     parsed.AccessToken,
		TokenType:       parsed.TokenType,
		RefreshToken:    parsed.RefreshToken,
		IssuedTokenType: parsed.IssuedTokenType,
		Scope:           strings.TrimSpace(parsed.Scope),
	}
	if secs, ok := parsed.expiresInSeconds(); ok {
		tok.Expiry = time.Now().Add(time.Duration(secs) * time.Second)
	}
	return tok, nil
}

// doRevocationRequest POSTs an RFC 7009 revocation for token. The server answers 200 whether or
// not the token was valid; anything else is reported so the caller can log it. Never retried:
// it is best effort and runs after the response-critical work is done.
func doRevocationRequest(ctx context.Context, httpClient *http.Client, revocationEndpoint string,
	cred clientCredential, token, tokenTypeHint string, extraHeaders map[string]string) error {
	form := url.Values{}
	form.Set("token", token)
	if tokenTypeHint != "" {
		form.Set("token_type_hint", tokenTypeHint)
	}
	resp, body, err := postForm(ctx, httpClient, revocationEndpoint, cred, form, extraHeaders)
	if err != nil {
		return err
	}
	if resp.StatusCode != http.StatusOK {
		return tokenErrorFrom(resp.StatusCode, body)
	}
	return nil
}

// postForm sends one form-encoded POST with client authentication and returns the response
// plus its (bounded) body.
func postForm(ctx context.Context, httpClient *http.Client, endpoint string, cred clientCredential,
	form url.Values, extraHeaders map[string]string) (*http.Response, []byte, error) {
	if cred.style == authStyleInParams {
		form.Set("client_id", cred.id)
		form.Set("client_secret", cred.secret)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return nil, nil, fmt.Errorf("build token request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	for k, v := range extraHeaders {
		if strings.EqualFold(k, "Authorization") || strings.EqualFold(k, "Content-Type") {
			continue
		}
		req.Header.Set(k, v)
	}
	if cred.style == authStyleInHeader {
		req.SetBasicAuth(url.QueryEscape(cred.id), url.QueryEscape(cred.secret))
	}

	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, nil, fmt.Errorf("token request failed: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	body, err := io.ReadAll(io.LimitReader(resp.Body, maxTokenResponseBytes+1))
	if err != nil {
		return nil, nil, fmt.Errorf("reading token response: %w", err)
	}
	if len(body) > maxTokenResponseBytes {
		return nil, nil, fmt.Errorf("token response exceeded %d bytes", maxTokenResponseBytes)
	}
	return resp, body, nil
}

// tokenErrorFrom builds a *TokenError from a non-200 token-endpoint response, reading the RFC
// 6749 §5.2 fields when the body is JSON.
func tokenErrorFrom(status int, body []byte) *TokenError {
	tokErr := &TokenError{StatusCode: status}
	var errBody struct {
		Error            string `json:"error"`
		ErrorDescription string `json:"error_description"`
		CorrelationID    string `json:"correlation_id"`
	}
	if json.Unmarshal(body, &errBody) == nil {
		tokErr.ErrorCode = errBody.Error
		tokErr.ErrorDescription = errBody.ErrorDescription
		tokErr.CorrelationID = errBody.CorrelationID
	}
	return tokErr
}

// fetchWithRetry runs fetch with bounded retry for transient failures.
func fetchWithRetry(ctx context.Context, maxRetries int, fetch func(ctx context.Context) (*Token, error)) (*Token, error) {
	var lastErr error
	for attempt := 0; attempt <= maxRetries; attempt++ {
		if attempt > 0 {
			select {
			case <-time.After(retryBackoff(attempt)):
			case <-ctx.Done():
				return nil, ctx.Err()
			}
		}
		tok, err := fetch(ctx)
		if err == nil {
			return tok, nil
		}
		lastErr = err
		if !isRetryableTokenError(err) {
			return nil, err
		}
	}
	return nil, lastErr
}

// isRetryableTokenError classifies a token-fetch error as worth retrying. A *nonRetryableTokenError
// (malformed/incomplete response body) never succeeds by retrying unchanged. A *TokenError is only
// retryable on 429/5xx. Any other error (network failure, request build failure) didn't get a
// definitive rejection and is retried by default.
func isRetryableTokenError(err error) bool {
	var nonRetryable *nonRetryableTokenError
	if errors.As(err, &nonRetryable) {
		return false
	}
	var tokErr *TokenError
	if errors.As(err, &tokErr) {
		return tokErr.StatusCode == http.StatusTooManyRequests || tokErr.StatusCode >= 500
	}
	return true
}

// retryBackoff returns the delay before retry attempt n (n >= 1): exponential from
// retryBaseDelay, capped at retryMaxDelay, plus up to 50% jitter to avoid lockstep retries.
func retryBackoff(attempt int) time.Duration {
	backoff := retryBaseDelay * time.Duration(uint64(1)<<uint(attempt-1))
	if backoff > retryMaxDelay || backoff <= 0 {
		backoff = retryMaxDelay
	}
	jitter := time.Duration(rand.Int63n(int64(backoff)/2 + 1))
	return backoff + jitter
}

// ─── Transport registry ───────────────────────────────────────────────────────

// keyedSingleton is a process-wide, get-or-create registry of shared values.
// build always runs outside the lock, so a slow build never stalls other keys.
type keyedSingleton[K comparable, V any] struct {
	mu sync.Mutex
	m  map[K]V
}

func newKeyedSingleton[K comparable, V any]() *keyedSingleton[K, V] {
	return &keyedSingleton[K, V]{m: make(map[K]V)}
}

// getOrCreate returns the cached value for key, building it on a miss.
// created is false on a hit or a lost build race. A failed build isn't cached.
func (r *keyedSingleton[K, V]) getOrCreate(key K, build func() (V, error)) (value V, created bool, err error) {
	r.mu.Lock()
	if v, ok := r.m[key]; ok {
		r.mu.Unlock()
		return v, false, nil
	}
	r.mu.Unlock()

	v, err := build()
	if err != nil {
		var zero V
		return zero, false, err
	}

	r.mu.Lock()
	defer r.mu.Unlock()
	if existing, ok := r.m[key]; ok {
		return existing, false, nil
	}
	r.m[key] = v
	return v, true, nil
}

// tokenEndpointTransportKey identifies a distinct token-endpoint HTTP client configuration.
// tlsCACert is the raw PEM content, not hashed - it's not sensitive like a client secret.
type tokenEndpointTransportKey struct {
	proxyURL              string
	tlsCACert             string
	tlsInsecureSkipVerify bool
}

// tokenEndpointTransports is the process-wide registry of shared *http.Transport values for the
// token-endpoint HTTP client, keyed by proxy/TLS configuration.
var tokenEndpointTransports = newKeyedSingleton[tokenEndpointTransportKey, *http.Transport]()

// getOrCreateTokenEndpointTransport returns the process-wide shared Transport for this
// proxy/TLS configuration, building it on first use.
func getOrCreateTokenEndpointTransport(key tokenEndpointTransportKey) (*http.Transport, error) {
	transport, _, err := tokenEndpointTransports.getOrCreate(key, func() (*http.Transport, error) {
		return buildTokenEndpointTransport(key)
	})
	return transport, err
}

// buildTokenEndpointTransport wires proxyURL and TLS settings into one Transport, setting Proxy
// explicitly alongside TLSClientConfig - an unset Transport.Proxy means "never proxy", it does
// not fall back to ProxyFromEnvironment.
func buildTokenEndpointTransport(key tokenEndpointTransportKey) (*http.Transport, error) {
	proxyFunc := http.ProxyFromEnvironment
	if key.proxyURL != "" {
		proxyURL, err := url.Parse(key.proxyURL)
		if err != nil {
			// url.Error embeds the raw input verbatim, which could leak proxyURL's userinfo - scrub before wrapping.
			return nil, fmt.Errorf("invalid proxyURL: %s", redactURLCredentials(err.Error()))
		}
		proxyFunc = http.ProxyURL(proxyURL)
	}

	transport := &http.Transport{Proxy: proxyFunc}

	if key.tlsCACert != "" || key.tlsInsecureSkipVerify {
		tlsConfig := &tls.Config{InsecureSkipVerify: key.tlsInsecureSkipVerify} //nolint:gosec // opt-in, logged at extraction time
		if key.tlsCACert != "" {
			pool, err := parseCACertPool(key.tlsCACert)
			if err != nil {
				return nil, fmt.Errorf("tlsCaCert: %w", err)
			}
			tlsConfig.RootCAs = pool
		}
		transport.TLSClientConfig = tlsConfig
	}

	return transport, nil
}

// parseCACertPool parses PEM-encoded CA certificate content into a pool that trusts only these
// CA(s), not the system's default public CAs - a deliberate, tighter trust boundary.
func parseCACertPool(pemContent string) (*x509.CertPool, error) {
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM([]byte(pemContent)) {
		return nil, fmt.Errorf("no valid PEM certificates found in tlsCaCert")
	}
	return pool, nil
}

// ─── Logging hygiene ──────────────────────────────────────────────────────────

// credentialedURLPattern captures a "scheme://" prefix immediately followed by a "userinfo@"
// segment, so redactURLCredentials can strip just the latter.
var credentialedURLPattern = regexp.MustCompile(`([a-zA-Z][a-zA-Z0-9+.-]*://)[^/@\s]+@`)

// redactURLCredentials scrubs any "scheme://user:pass@" userinfo out of s, replacing it with
// "[REDACTED]" while leaving the rest of s intact.
func redactURLCredentials(s string) string {
	return credentialedURLPattern.ReplaceAllString(s, "${1}[REDACTED]@")
}

// sanitizeEndpointForLogging reduces an operator-configured endpoint URL to scheme+host+path
// before it's logged, since an endpoint is user configuration and can carry sensitive URL
// components. Falls back to a fixed placeholder rather than log the raw value when it doesn't
// even parse as a URL.
func sanitizeEndpointForLogging(raw string) string {
	u, err := url.Parse(raw)
	if err != nil || u.Scheme == "" || u.Host == "" {
		return "[unparsable-endpoint]"
	}
	u.User = nil
	u.RawQuery = ""
	u.Fragment = ""
	return u.String()
}

// buildHeaderValue combines valuePrefix and the credential into the header value to inject.
// An empty prefix yields the raw credential with no scheme prefix.
func buildHeaderValue(prefix, token string) string {
	if prefix == "" {
		return token
	}
	return prefix + " " + token
}

// cloneURLValues copies form values so a retry never observes a mutated map.
func cloneURLValues(v url.Values) url.Values {
	out := make(url.Values, len(v))
	for k, vals := range v {
		out[k] = append([]string(nil), vals...)
	}
	return out
}

// ─── Param helpers ────────────────────────────────────────────────────────────

// getStringParam safely extracts a string parameter, returning "" if absent or the wrong type.
// Leading/trailing whitespace is trimmed since pasted values often carry a stray newline.
func getStringParam(params map[string]interface{}, key string) string {
	if val, ok := params[key]; ok {
		if str, ok := val.(string); ok {
			return strings.TrimSpace(str)
		}
	}
	return ""
}

// getStringParamOrDefault extracts a string parameter, falling back to def when the key is
// absent or the wrong type - but not when it's an explicitly empty string.
func getStringParamOrDefault(params map[string]interface{}, key, def string) string {
	val, ok := params[key]
	if !ok {
		return def
	}
	str, ok := val.(string)
	if !ok {
		return def
	}
	return strings.TrimSpace(str)
}

// getRequiredStringParam extracts a required, non-empty string parameter, trimmed per getStringParam.
func getRequiredStringParam(params map[string]interface{}, key string) (string, error) {
	val, ok := params[key]
	if !ok {
		return "", fmt.Errorf("'%s' parameter is required", key)
	}
	str, ok := val.(string)
	if !ok {
		return "", fmt.Errorf("'%s' must be a string", key)
	}
	str = strings.TrimSpace(str)
	if str == "" {
		return "", fmt.Errorf("'%s' cannot be empty", key)
	}
	return str, nil
}

// getEnumParam extracts an optional string parameter that must be one of allowed, falling back
// to def when absent or empty.
func getEnumParam(params map[string]interface{}, key, def string, allowed ...string) (string, error) {
	v := getStringParam(params, key)
	if v == "" {
		v = def
	}
	for _, a := range allowed {
		if v == a {
			return v, nil
		}
	}
	return "", fmt.Errorf("'%s' must be one of %s", key, strings.Join(quoteAll(allowed), ", "))
}

func quoteAll(ss []string) []string {
	out := make([]string, len(ss))
	for i, s := range ss {
		out[i] = strconv.Quote(s)
	}
	return out
}

// getBoolParam extracts an optional boolean parameter, falling back to def if absent or the wrong type.
func getBoolParam(params map[string]interface{}, key string, def bool) bool {
	if val, ok := params[key]; ok {
		if b, ok := val.(bool); ok {
			return b
		}
	}
	return def
}

// getIntParam extracts an optional integer parameter, tolerating int/int64/float64, falling back
// to def if absent, the wrong type, or negative.
func getIntParam(params map[string]interface{}, key string, def int) int {
	val, ok := params[key]
	if !ok {
		return def
	}
	var n int
	switch v := val.(type) {
	case int:
		n = v
	case int64:
		n = int(v)
	case float64:
		n = int(v)
	default:
		return def
	}
	if n < 0 {
		return def
	}
	return n
}

// getDurationParam extracts an optional Go-duration-formatted string parameter (e.g. "10s"),
// falling back to def if absent, the wrong type, or unparsable.
func getDurationParam(params map[string]interface{}, key string, def time.Duration) time.Duration {
	if val, ok := params[key]; ok {
		if str, ok := val.(string); ok {
			if d, err := time.ParseDuration(strings.TrimSpace(str)); err == nil {
				return d
			}
		}
	}
	return def
}

// getPositiveDurationParam is getDurationParam plus a non-positive guard, falling back to def
// when the parsed duration is <= 0. expiryBuffer deliberately doesn't use this - 0 is a valid
// value there (no early-refresh margin), unlike the durations that do.
func getPositiveDurationParam(params map[string]interface{}, key string, def time.Duration) time.Duration {
	d := getDurationParam(params, key, def)
	if d <= 0 {
		return def
	}
	return d
}

// getStringMapParam extracts an optional flat string-to-string map parameter by key. Absent or
// wrong-shaped input yields no entries rather than an error.
func getStringMapParam(params map[string]interface{}, key string) map[string]string {
	raw, ok := params[key]
	if !ok {
		return nil
	}
	m, ok := raw.(map[string]interface{})
	if !ok {
		return nil
	}
	out := make(map[string]string, len(m))
	for k, v := range m {
		if s, ok := v.(string); ok {
			if trimmed := strings.TrimSpace(s); trimmed != "" {
				out[k] = trimmed
			}
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// getPurgeStatusCodesParam extracts "tokenPurgeStatusCodes", falling back to def when absent or
// wrong-shaped. An explicit empty list ([]) is honored as-is, disabling purging entirely.
func getPurgeStatusCodesParam(params map[string]interface{}, key string, def []int) map[int]struct{} {
	codes := def
	if raw, ok := params[key]; ok {
		if arr, ok := raw.([]interface{}); ok {
			parsed := make([]int, 0, len(arr))
			for _, v := range arr {
				switch n := v.(type) {
				case int:
					parsed = append(parsed, n)
				case int64:
					parsed = append(parsed, int(n))
				case float64:
					parsed = append(parsed, int(n))
				case string:
					if code, err := strconv.Atoi(strings.TrimSpace(n)); err == nil {
						parsed = append(parsed, code)
					}
				}
			}
			codes = parsed
		}
	}
	set := make(map[int]struct{}, len(codes))
	for _, c := range codes {
		set[c] = struct{}{}
	}
	return set
}
