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

// Package oauth2idjag implements the Identity Assertion JWT Authorization Grant
// (ID-JAG) two-step token exchange as a gateway policy:
//
//  1. RFC 8693 token exchange at the IdP (e.g. WSO2 Identity Server) to obtain an ID-JAG JWT.
//  2. JWT-bearer grant at the Resource AS (e.g. Atlassian) to obtain an access token.
//
// The final access token replaces the inbound credential before the request is
// forwarded. Fork of gateway-obo-token with a two-step exchange instead of one.
package oauth2idjag

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"time"

	policy "github.com/wso2/api-platform/sdk/core/policy/v1alpha2"
)

const (
	// AuthType is the AuthContext.AuthType this policy stamps.
	AuthType = "oauth2-id-jag"

	// GrantTypeTokenExchange is the RFC 8693 token exchange grant used in step 1.
	GrantTypeTokenExchange = "urn:ietf:params:oauth:grant-type:token-exchange"

	// GrantTypeJWTBearer is the JWT-bearer grant used in step 2.
	GrantTypeJWTBearer = "urn:ietf:params:oauth:grant-type:jwt-bearer"

	// RequestedTokenTypeIDJAG is the requested_token_type for step 1.
	RequestedTokenTypeIDJAG = "urn:ietf:params:oauth:token-type:id-jag"

	// SubjectTokenTypeAccessToken is the subject_token_type for access tokens.
	SubjectTokenTypeAccessToken = "urn:ietf:params:oauth:token-type:access_token"

	// SubjectTokenTypeIDToken is the subject_token_type for ID tokens.
	SubjectTokenTypeIDToken = "urn:ietf:params:oauth:token-type:id_token"

	// MetadataKeyCacheKey carries the request's cache key from the request phase
	// to the response phase, so an upstream 401 purges only that entry.
	MetadataKeyCacheKey = "oauth2idjag.cacheKey"

	// MetadataKeyPrmPointer is where mcp-auth-passthrough stashes the gateway's
	// PRM pointer; used in 401 challenges when challengeResourceMetadata is unset.
	MetadataKeyPrmPointer = "mcpauth.prmPointer"

	// ClientAuthMethodBasic (client_secret_basic) sends client ID/secret via HTTP Basic auth.
	ClientAuthMethodBasic = "client_secret_basic"

	// ClientAuthMethodPost (client_secret_post) sends client ID/secret as form fields.
	ClientAuthMethodPost = "client_secret_post"

	// defaultExpiryBuffer is how far ahead of expiry a cached token is treated as
	// stale. 2m keeps the cache useful while never sending a credential that
	// expires mid-flight.
	defaultExpiryBuffer = 2 * time.Minute

	// defaultCacheMaxEntries bounds the per-assertion cache.
	defaultCacheMaxEntries = 10000

	// minAssertionLength rejects obviously-not-a-token header values defensively.
	minAssertionLength = 20
)

// subjectTokenTypeURN maps the short-form enum values from the policy definition
// to the full URN used in the RFC 8693 token exchange request.
var subjectTokenTypeURN = map[string]string{
	"access_token": SubjectTokenTypeAccessToken,
	"id_token":     SubjectTokenTypeIDToken,
}

// idJagParams bundles all extracted, validated policy params.
type idJagParams struct {
	// Step 1: IdP
	idpTokenEndpoint       string
	idpClientID            string
	idpClientSecret        string
	idpClientAuthMethod    string
	audience               string
	subjectTokenType       string // full URN
	idpScopes              string
	idpResource            string
	idpTokenRequestParams  map[string]string
	idpTokenRequestHeaders map[string]string

	// Step 2: Resource AS
	resourceAsTokenEndpoint       string
	resourceAsClientID            string
	resourceAsClientSecret        string
	resourceAsClientAuthMethod    string
	resourceAsScopes              string
	resourceAsTokenRequestParams  map[string]string
	resourceAsTokenRequestHeaders map[string]string

	// Shared
	assertionHeader           string
	requireAuthContext        bool
	cacheMaxEntries           int
	challengeResourceMetadata string
	userIdClaim               string

	tokenRequestTimeout    time.Duration
	defaultTokenTTL        time.Duration
	expiryBuffer           time.Duration
	tokenRequestMaxRetries int

	tokenPurgeStatusCodes map[int]struct{}

	headerName  string
	valuePrefix string

	proxyURL              string
	tlsCaCert             string
	tlsInsecureSkipVerify bool
}

// Policy exchanges the validated inbound bearer token for a per-user upstream
// token via the two-step ID-JAG flow and injects it into headerName.
type Policy struct {
	params               idJagParams
	idpHTTPClient        *http.Client // step 1 (IdP)
	resourceAsHTTPClient *http.Client // step 2 (Resource AS)
	cache                *tokenCache
	flight               *flightGroup
}

// step1Error wraps an error from the IdP token exchange (step 1).
type step1Error struct {
	err error
}

func (e *step1Error) Error() string { return "step 1 (IdP token exchange): " + e.err.Error() }
func (e *step1Error) Unwrap() error { return e.err }

// step2Error wraps an error from the Resource AS JWT-bearer grant (step 2).
type step2Error struct {
	err error
}

func (e *step2Error) Error() string { return "step 2 (Resource AS JWT-bearer): " + e.err.Error() }
func (e *step2Error) Unwrap() error { return e.err }

// GetPolicy is the v1alpha2 factory entry point (loaded by v1alpha2 kernels).
func GetPolicy(metadata policy.PolicyMetadata, params map[string]interface{}) (policy.Policy, error) {
	slog.Debug("OAuth2IDJAG: constructing policy from params")

	p, err := validateAndExtractParams(params)
	if err != nil {
		return nil, fmt.Errorf("invalid params: %w", err)
	}

	transport, err := getOrCreateTokenEndpointTransport(p)
	if err != nil {
		return nil, fmt.Errorf("invalid token endpoint transport config: %w", err)
	}

	// Both steps share the same transport (same proxy/TLS config).
	pol := &Policy{
		params:               p,
		idpHTTPClient:        &http.Client{Timeout: p.tokenRequestTimeout, Transport: transport},
		resourceAsHTTPClient: &http.Client{Timeout: p.tokenRequestTimeout, Transport: transport},
		cache:                newTokenCache(),
		flight:               newFlightGroup(),
	}

	slog.Debug("OAuth2IDJAG: policy initialized",
		"idpTokenEndpoint", sanitizeEndpointForLogging(p.idpTokenEndpoint),
		"resourceAsTokenEndpoint", sanitizeEndpointForLogging(p.resourceAsTokenEndpoint),
		"idpClientId", p.idpClientID, "resourceAsClientId", p.resourceAsClientID,
		"headerName", p.headerName, "assertionHeader", p.assertionHeader,
		"requireAuthContext", p.requireAuthContext)

	return pol, nil
}

// validateAndExtractParams validates and extracts all policy params.
func validateAndExtractParams(params map[string]interface{}) (idJagParams, error) {
	var p idJagParams
	var err error

	// Step 1: IdP params
	p.idpTokenEndpoint, err = getRequiredStringParam(params, "idpTokenEndpoint")
	if err != nil {
		return idJagParams{}, err
	}
	p.idpClientID, err = getRequiredStringParam(params, "idpClientId")
	if err != nil {
		return idJagParams{}, err
	}
	p.idpClientSecret, err = getRequiredStringParam(params, "idpClientSecret")
	if err != nil {
		return idJagParams{}, err
	}
	p.audience, err = getRequiredStringParam(params, "audience")
	if err != nil {
		return idJagParams{}, err
	}

	p.idpClientAuthMethod = getStringParam(params, "idpClientAuthMethod")
	if p.idpClientAuthMethod == "" {
		p.idpClientAuthMethod = ClientAuthMethodPost
	}
	if p.idpClientAuthMethod != ClientAuthMethodBasic && p.idpClientAuthMethod != ClientAuthMethodPost {
		return idJagParams{}, fmt.Errorf("'idpClientAuthMethod' must be one of %q, %q", ClientAuthMethodBasic, ClientAuthMethodPost)
	}

	subjectTokenTypeShort := getStringParamOrDefault(params, "subjectTokenType", "access_token")
	urn, ok := subjectTokenTypeURN[subjectTokenTypeShort]
	if !ok {
		return idJagParams{}, fmt.Errorf("'subjectTokenType' must be one of \"access_token\", \"id_token\"")
	}
	p.subjectTokenType = urn

	p.idpScopes = getStringParam(params, "idpScopes")
	p.idpResource = getStringParam(params, "idpResource")
	p.idpTokenRequestParams = getStringMapParam(params, "idpTokenRequestParams")
	p.idpTokenRequestHeaders = getStringMapParam(params, "idpTokenRequestHeaders")

	// Step 2: Resource AS params
	p.resourceAsTokenEndpoint, err = getRequiredStringParam(params, "resourceAsTokenEndpoint")
	if err != nil {
		return idJagParams{}, err
	}
	p.resourceAsClientID, err = getRequiredStringParam(params, "resourceAsClientId")
	if err != nil {
		return idJagParams{}, err
	}
	p.resourceAsClientSecret, err = getRequiredStringParam(params, "resourceAsClientSecret")
	if err != nil {
		return idJagParams{}, err
	}

	p.resourceAsClientAuthMethod = getStringParam(params, "resourceAsClientAuthMethod")
	if p.resourceAsClientAuthMethod == "" {
		p.resourceAsClientAuthMethod = ClientAuthMethodPost
	}
	if p.resourceAsClientAuthMethod != ClientAuthMethodBasic && p.resourceAsClientAuthMethod != ClientAuthMethodPost {
		return idJagParams{}, fmt.Errorf("'resourceAsClientAuthMethod' must be one of %q, %q", ClientAuthMethodBasic, ClientAuthMethodPost)
	}

	p.resourceAsScopes = getStringParam(params, "resourceAsScopes")
	p.resourceAsTokenRequestParams = getStringMapParam(params, "resourceAsTokenRequestParams")
	p.resourceAsTokenRequestHeaders = getStringMapParam(params, "resourceAsTokenRequestHeaders")

	// Shared params
	p.assertionHeader = getStringParamOrDefault(params, "assertionHeader", "Authorization")
	if p.assertionHeader == "" {
		p.assertionHeader = "Authorization"
	}
	p.requireAuthContext = getBoolParam(params, "requireAuthContext", true)
	p.userIdClaim = getStringParamOrDefault(params, "userIdClaim", "sub")
	if p.userIdClaim == "" {
		p.userIdClaim = "sub"
	}
	p.challengeResourceMetadata = getStringParam(params, "challengeResourceMetadata")

	p.cacheMaxEntries = getIntParam(params, "cacheMaxEntries", defaultCacheMaxEntries)
	if p.cacheMaxEntries < 1 {
		p.cacheMaxEntries = defaultCacheMaxEntries
	}

	p.headerName = getStringParamOrDefault(params, "headerName", defaultHeaderName)
	if p.headerName == "" {
		p.headerName = defaultHeaderName
	}
	p.valuePrefix = getStringParamOrDefault(params, "valuePrefix", defaultValuePrefix)

	p.tokenRequestTimeout = getPositiveDurationParam(params, "tokenRequestTimeout", defaultTokenRequestTimeout)
	p.defaultTokenTTL = getPositiveDurationParam(params, "defaultTokenTTL", defaultTokenTTLFallback)
	p.expiryBuffer = getDurationParam(params, "expiryBuffer", defaultExpiryBuffer)
	if p.expiryBuffer < 0 {
		p.expiryBuffer = defaultExpiryBuffer
	}
	p.tokenPurgeStatusCodes = getPurgeStatusCodesParam(params, "tokenPurgeStatusCodes", defaultPurgeStatusCodes)

	p.proxyURL = getStringParam(params, "proxyURL")
	p.tlsCaCert = getStringParam(params, "tlsCaCert")
	p.tlsInsecureSkipVerify = getBoolParam(params, "tlsInsecureSkipVerify", false)
	if p.tlsInsecureSkipVerify {
		slog.Warn("OAuth2IDJAG: tlsInsecureSkipVerify is enabled - TLS certificate verification for the token endpoints is disabled; this must never be used against a real identity provider")
	}

	p.tokenRequestMaxRetries = getIntParam(params, "tokenRequestMaxRetries", defaultTokenRequestMaxRetries)

	return p, nil
}

// Mode declares processing per phase. Bodies are never buffered - /mcp streams
// SSE. Response headers are processed only when purging is enabled.
func (p *Policy) Mode() policy.ProcessingMode {
	responseHeaderMode := policy.HeaderModeSkip
	if len(p.params.tokenPurgeStatusCodes) > 0 {
		responseHeaderMode = policy.HeaderModeProcess
	}
	return policy.ProcessingMode{
		RequestHeaderMode:  policy.HeaderModeProcess,
		RequestBodyMode:    policy.BodyModeSkip,
		ResponseHeaderMode: responseHeaderMode,
		ResponseBodyMode:   policy.BodyModeSkip,
	}
}

// OnRequestHeaders performs the two-step ID-JAG exchange (or serves the final
// token from the per-assertion cache) and swaps the inbound credential for the
// upstream access token.
func (p *Policy) OnRequestHeaders(ctx context.Context, req *policy.RequestHeaderContext, _ map[string]interface{}) policy.RequestHeaderAction {
	// 0. Only act on requests that reached us through the inbound auth policy.
	if p.params.requireAuthContext && (req.SharedContext == nil || req.AuthContext == nil || !req.AuthContext.Authenticated) {
		slog.Warn("OAuth2IDJAG: rejecting request - inbound token not validated by an upstream auth policy")
		return p.unauthorized(req, "inbound token not validated", nil)
	}

	// 1. Assertion = the ORIGINAL client token from the pre-mutation snapshot,
	// independent of whether the inbound policy stripped or forwarded it.
	var snapshot *policy.Headers
	if req.Downstream != nil && req.Downstream.Request != nil {
		snapshot = req.Downstream.Request.Headers
	}
	if snapshot == nil {
		slog.Warn("OAuth2IDJAG: downstream request snapshot unavailable")
		return p.unauthorized(req, "missing inbound bearer token", nil)
	}
	assertion := bearerFrom(snapshot.Get(p.params.assertionHeader))
	if assertion == "" {
		return p.unauthorized(req, "missing inbound bearer token", nil)
	}

	key := sha256hex(assertion)
	p.stashCacheKey(req.SharedContext, key)

	// 2. Cache lookup by sha256(assertion) → final Resource AS access token.
	if tok, ok := p.cache.get(key, p.params.expiryBuffer); ok {
		return p.inject(req, tok, true)
	}

	// 3. Two-step exchange, single-flighted per key so N concurrent requests
	// carrying the same assertion produce one exchange sequence.
	tok, err := p.flight.Do(key, func() (*idJagToken, error) {
		return p.exchange(ctx, assertion, key)
	})
	if err != nil {
		return p.classifyAndRespond(req, err, key)
	}
	return p.inject(req, tok, false)
}

// exchange performs the two-step ID-JAG token exchange (with retry per step)
// and caches the final result. TTL is bounded by min(step2_expires_in,
// inbound_token_exp) - the buffer is applied at read time by tokenCache.get.
func (p *Policy) exchange(ctx context.Context, assertion, key string) (*idJagToken, error) {
	// Step 1: RFC 8693 token exchange at IdP → ID-JAG JWT
	idJag, err := p.exchangeForIDJag(ctx, assertion)
	if err != nil {
		return nil, &step1Error{err: err}
	}

	// Step 2: JWT-bearer grant at Resource AS → access token
	tok, err := p.exchangeIDJagForAccessToken(ctx, idJag)
	if err != nil {
		return nil, &step2Error{err: err}
	}

	if tok.Expiry.IsZero() {
		tok.Expiry = time.Now().Add(p.params.defaultTokenTTL)
	}
	if expA, ok := jwtExp(assertion); ok && expA.Before(tok.Expiry) {
		tok.Expiry = expA
	}

	result := &idJagToken{Token: *tok, claims: jwtClaims(tok.AccessToken)}
	p.cache.put(key, result, p.params.cacheMaxEntries)
	slog.Debug("OAuth2IDJAG: token exchanged and cached", "cacheKeyId", key[:8],
		"expiry", result.Expiry.Format(time.RFC3339))
	return result, nil
}

// exchangeForIDJag performs step 1: RFC 8693 token exchange at the IdP.
// POST idpTokenEndpoint with grant_type=token-exchange, subject_token=<inbound>,
// requested_token_type=id-jag, audience=<resource AS identifier>.
// Returns the ID-JAG JWT from the response's access_token field.
func (p *Policy) exchangeForIDJag(ctx context.Context, assertion string) (string, error) {
	form := url.Values{}
	for k, v := range p.params.idpTokenRequestParams {
		form.Set(k, v)
	}
	// Core fields set last so extras can never override them.
	form.Set("grant_type", GrantTypeTokenExchange)
	form.Set("subject_token", assertion)
	form.Set("subject_token_type", p.params.subjectTokenType)
	form.Set("requested_token_type", RequestedTokenTypeIDJAG)
	form.Set("audience", p.params.audience)
	if p.params.idpScopes != "" {
		form.Set("scope", p.params.idpScopes)
	}
	if p.params.idpResource != "" {
		form.Set("resource", p.params.idpResource)
	}

	style := authStyleFor(p.params.idpClientAuthMethod)
	tok, err := fetchWithRetry(ctx, p.params.tokenRequestMaxRetries, func(ctx context.Context) (*Token, error) {
		return doTokenRequest(ctx, p.idpHTTPClient, p.params.idpTokenEndpoint, style,
			p.params.idpClientID, p.params.idpClientSecret, cloneURLValues(form), p.params.idpTokenRequestHeaders)
	})
	if err != nil {
		return "", err
	}

	return tok.AccessToken, nil
}

// exchangeIDJagForAccessToken performs step 2: JWT-bearer grant at the Resource AS.
// POST resourceAsTokenEndpoint with grant_type=jwt-bearer, assertion=<ID-JAG JWT>.
// Returns the final access token.
func (p *Policy) exchangeIDJagForAccessToken(ctx context.Context, idJag string) (*Token, error) {
	form := url.Values{}
	for k, v := range p.params.resourceAsTokenRequestParams {
		form.Set(k, v)
	}
	// Core fields set last so extras can never override them.
	form.Set("grant_type", GrantTypeJWTBearer)
	form.Set("assertion", idJag)
	if p.params.resourceAsScopes != "" {
		form.Set("scope", p.params.resourceAsScopes)
	}

	style := authStyleFor(p.params.resourceAsClientAuthMethod)
	tok, err := fetchWithRetry(ctx, p.params.tokenRequestMaxRetries, func(ctx context.Context) (*Token, error) {
		return doTokenRequest(ctx, p.resourceAsHTTPClient, p.params.resourceAsTokenEndpoint, style,
			p.params.resourceAsClientID, p.params.resourceAsClientSecret, cloneURLValues(form), p.params.resourceAsTokenRequestHeaders)
	})
	if err != nil {
		return nil, err
	}

	return tok, nil
}

// classifyAndRespond maps exchange errors to the appropriate HTTP response:
//   - Step 1 invalid_grant/interaction_required → 401 (user can re-auth)
//   - Step 1 invalid_client → 502 (gateway misconfiguration)
//   - Step 2 any TokenError → 502 (trust/config issue, user can't fix it)
//   - Network/transient failures → 502
func (p *Policy) classifyAndRespond(req *policy.RequestHeaderContext, err error, key string) policy.RequestHeaderAction {
	var s1 *step1Error
	var s2 *step2Error

	if errors.As(err, &s1) {
		var te *TokenError
		if errors.As(s1.err, &te) && isStep1ReauthError(te) {
			slog.Warn("OAuth2IDJAG: step 1 rejected - client must re-authenticate",
				"error", te.ErrorCode, "correlationId", te.CorrelationID,
				"cacheKeyId", key[:8])
			return p.unauthorized(req, te.ErrorDescription, te)
		}
		slog.Error("OAuth2IDJAG: step 1 (IdP token exchange) failed",
			"error", redactURLCredentials(s1.err.Error()),
			"idpTokenEndpoint", sanitizeEndpointForLogging(p.params.idpTokenEndpoint),
			"idpClientId", p.params.idpClientID, "cacheKeyId", key[:8])
		return p.badGateway(req)
	}

	if errors.As(err, &s2) {
		slog.Error("OAuth2IDJAG: step 2 (Resource AS JWT-bearer) failed",
			"error", redactURLCredentials(s2.err.Error()),
			"resourceAsTokenEndpoint", sanitizeEndpointForLogging(p.params.resourceAsTokenEndpoint),
			"resourceAsClientId", p.params.resourceAsClientID, "cacheKeyId", key[:8])
		return p.badGateway(req)
	}

	// Shouldn't happen, but handle gracefully.
	slog.Error("OAuth2IDJAG: credential acquisition failed",
		"error", redactURLCredentials(err.Error()), "cacheKeyId", key[:8])
	return p.badGateway(req)
}

// isStep1ReauthError classifies a step 1 token-endpoint rejection: true means
// the client re-authenticating can fix it (→ 401), false means it is the
// gateway's own configuration (→ 502).
func isStep1ReauthError(te *TokenError) bool {
	switch te.ErrorCode {
	case "invalid_grant", "interaction_required":
		return true
	case "invalid_client":
		return false
	}
	return false
}

// OnResponseHeaders purges only the requesting assertion's cache entry when the
// upstream rejects the exchanged token (default: 401), so the next request for
// that user re-exchanges while other users' entries stay.
func (p *Policy) OnResponseHeaders(ctx context.Context, respCtx *policy.ResponseHeaderContext, _ map[string]interface{}) policy.ResponseHeaderAction {
	if _, purge := p.params.tokenPurgeStatusCodes[respCtx.ResponseStatus]; purge {
		if key := p.stashedCacheKey(respCtx.SharedContext); key != "" {
			slog.Warn("OAuth2IDJAG: upstream rejected the exchanged token, purging its cache entry",
				"status", respCtx.ResponseStatus, "cacheKeyId", key[:8])
			p.cache.delete(key)
		}
	}
	return policy.DownstreamResponseHeaderModifications{}
}

// stashCacheKey records the request's cache key in shared metadata for the
// response phase.
func (p *Policy) stashCacheKey(shared *policy.SharedContext, key string) {
	if shared == nil {
		return
	}
	if shared.Metadata == nil {
		shared.Metadata = map[string]any{}
	}
	shared.Metadata[MetadataKeyCacheKey] = key
}

func (p *Policy) stashedCacheKey(shared *policy.SharedContext) string {
	if shared == nil || shared.Metadata == nil {
		return ""
	}
	key, _ := shared.Metadata[MetadataKeyCacheKey].(string)
	return key
}

// inject swaps the credential: the final access token goes into headerName, and
// the inbound assertion header is removed when it is a different header (when
// both are Authorization, HeadersToSet overwrites - either way the client token
// never goes upstream).
func (p *Policy) inject(req *policy.RequestHeaderContext, tok *idJagToken, cached bool) policy.RequestHeaderAction {
	cacheState := "miss"
	if cached {
		cacheState = "hit"
	}
	p.authSuccess(req, tok, cacheState)

	var remove []string
	if !strings.EqualFold(p.params.assertionHeader, p.params.headerName) {
		remove = []string{p.params.assertionHeader}
	}
	return policy.UpstreamRequestHeaderModifications{
		HeadersToSet: map[string]string{
			p.params.headerName: buildHeaderValue(p.params.valuePrefix, tok.AccessToken),
		},
		HeadersToRemove:   remove,
		AnalyticsMetadata: map[string]any{"id-jag.cache": cacheState},
	}
}

// authSuccess records the exchange in the shared AuthContext using the final
// token's claims, chaining the inbound policy's context via Previous.
func (p *Policy) authSuccess(req *policy.RequestHeaderContext, tok *idJagToken, cacheState string) {
	if req.SharedContext == nil {
		return
	}
	prev := req.AuthContext

	subject := claimString(tok.claims, p.params.userIdClaim)
	if subject == "" && prev != nil {
		subject = prev.Subject
	}
	properties := map[string]string{
		"mode":                    "id-jag",
		"idpTokenEndpoint":        sanitizeEndpointForLogging(p.params.idpTokenEndpoint),
		"resourceAsTokenEndpoint": sanitizeEndpointForLogging(p.params.resourceAsTokenEndpoint),
		"cache":                   cacheState,
	}
	if pu := claimString(tok.claims, "preferred_username"); pu != "" {
		properties["preferred_username"] = pu
	}
	req.SharedContext.AuthContext = &policy.AuthContext{
		Authenticated: true,
		AuthType:      AuthType,
		Subject:       subject,
		Issuer:        claimString(tok.claims, "iss"),
		Audience:      claimStrings(tok.claims, "aud"),
		Scopes:        scopesFromClaims(tok.claims),
		CredentialID:  p.params.idpClientID,
		Properties:    properties,
		Previous:      prev,
	}
}

// unauthorized builds the 401 that tells the client to (re-)authenticate: RFC
// 6750 invalid_token plus, when known, the resource_metadata pointer to the
// gateway's PRM so MCP clients restart discovery in the right place.
func (p *Policy) unauthorized(req *policy.RequestHeaderContext, desc string, cause *TokenError) policy.RequestHeaderAction {
	if req.SharedContext != nil {
		req.SharedContext.AuthContext = &policy.AuthContext{
			Authenticated: false,
			AuthType:      AuthType,
			Previous:      req.AuthContext,
		}
	}

	desc = strings.ReplaceAll(desc, `"`, "'")
	challenge := `Bearer error="invalid_token"`
	if desc != "" {
		challenge += `, error_description="` + desc + `"`
	}
	if ptr := p.challengePointer(req.SharedContext); ptr != "" {
		challenge += `, resource_metadata="` + ptr + `"`
	}

	body, _ := json.Marshal(map[string]string{
		"error":             "invalid_token",
		"error_description": desc,
	})
	return policy.ImmediateResponse{
		StatusCode: http.StatusUnauthorized,
		Headers: map[string]string{
			"Content-Type":     "application/json",
			"WWW-Authenticate": challenge,
		},
		Body: body,
	}
}

// challengePointer resolves the PRM URL for the 401 challenge: the explicit
// parameter wins, then the pointer mcp-auth-passthrough stashed in metadata.
func (p *Policy) challengePointer(shared *policy.SharedContext) string {
	if p.params.challengeResourceMetadata != "" {
		return p.params.challengeResourceMetadata
	}
	if shared != nil && shared.Metadata != nil {
		if v, ok := shared.Metadata[MetadataKeyPrmPointer].(string); ok {
			return v
		}
	}
	return ""
}

// badGateway is the gateway-side-fault response: the client's token was fine,
// the gateway could not mint the upstream credential - a 502 keeps clients from
// looping on sign-in.
func (p *Policy) badGateway(req *policy.RequestHeaderContext) policy.RequestHeaderAction {
	if req.SharedContext != nil {
		req.SharedContext.AuthContext = &policy.AuthContext{
			Authenticated: false,
			AuthType:      AuthType,
			CredentialID:  p.params.idpClientID,
			Properties: map[string]string{
				"mode":                    "id-jag",
				"idpTokenEndpoint":        sanitizeEndpointForLogging(p.params.idpTokenEndpoint),
				"resourceAsTokenEndpoint": sanitizeEndpointForLogging(p.params.resourceAsTokenEndpoint),
			},
			Previous: req.AuthContext,
		}
	}
	body, _ := json.Marshal(map[string]string{
		"error":   "Bad Gateway",
		"message": "failed to authenticate request to upstream service",
	})
	return policy.ImmediateResponse{
		StatusCode: http.StatusBadGateway,
		Headers:    map[string]string{"Content-Type": "application/json"},
		Body:       body,
	}
}

// bearerFrom extracts the bare token from the header values: first non-empty
// value, "Bearer " scheme stripped case-insensitively, defensively rejecting
// values with embedded whitespace or implausibly short ones.
func bearerFrom(vals []string) string {
	var raw string
	for _, v := range vals {
		if strings.TrimSpace(v) != "" {
			raw = strings.TrimSpace(v)
			break
		}
	}
	if raw == "" {
		return ""
	}
	if len(raw) > len("bearer ") && strings.EqualFold(raw[:len("bearer ")], "bearer ") {
		raw = strings.TrimSpace(raw[len("bearer "):])
	}
	if len(raw) < minAssertionLength || strings.ContainsAny(raw, " \t") {
		return ""
	}
	return raw
}

// jwtPayload base64url-decodes a JWT's payload segment without any signature
// check - the inbound policy already validated the assertion, and the final
// token comes straight from the token endpoint over TLS.
func jwtPayload(token string) (map[string]any, bool) {
	parts := strings.Split(token, ".")
	if len(parts) < 2 {
		return nil, false
	}
	data, err := base64.RawURLEncoding.DecodeString(strings.TrimRight(parts[1], "="))
	if err != nil {
		return nil, false
	}
	var claims map[string]any
	if err := json.Unmarshal(data, &claims); err != nil {
		return nil, false
	}
	return claims, true
}

// jwtExp reads the exp claim of a JWT; ok=false on any parse failure (the
// caller falls back to expires_in).
func jwtExp(token string) (time.Time, bool) {
	claims, ok := jwtPayload(token)
	if !ok {
		return time.Time{}, false
	}
	exp, ok := claims["exp"].(float64)
	if !ok {
		return time.Time{}, false
	}
	return time.Unix(int64(exp), 0), true
}

// jwtClaims returns the decoded payload, or an empty map when the token is not
// parseable as a JWT (AuthContext then simply carries no claim-derived fields).
func jwtClaims(token string) map[string]any {
	claims, ok := jwtPayload(token)
	if !ok {
		return map[string]any{}
	}
	return claims
}

func claimString(claims map[string]any, name string) string {
	if v, ok := claims[name].(string); ok {
		return v
	}
	return ""
}

// claimStrings reads a claim that may be a string or an array of strings (aud).
func claimStrings(claims map[string]any, name string) []string {
	switch v := claims[name].(type) {
	case string:
		return []string{v}
	case []any:
		out := make([]string, 0, len(v))
		for _, item := range v {
			if s, ok := item.(string); ok {
				out = append(out, s)
			}
		}
		return out
	}
	return nil
}

// scopesFromClaims reads scopes from scp (space-separated string, or an array)
// or scope, into the AuthContext.Scopes shape.
func scopesFromClaims(claims map[string]any) map[string]bool {
	var raw []string
	for _, name := range []string{"scp", "scope"} {
		switch v := claims[name].(type) {
		case string:
			raw = strings.Fields(v)
		case []any:
			for _, item := range v {
				if s, ok := item.(string); ok {
					raw = append(raw, s)
				}
			}
		}
		if len(raw) > 0 {
			break
		}
	}
	if len(raw) == 0 {
		return nil
	}
	scopes := make(map[string]bool, len(raw))
	for _, s := range raw {
		scopes[s] = true
	}
	return scopes
}

// cloneURLValues copies form values so a retry never observes a mutated map.
func cloneURLValues(v url.Values) url.Values {
	out := make(url.Values, len(v))
	for k, vals := range v {
		out[k] = append([]string(nil), vals...)
	}
	return out
}
