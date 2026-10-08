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

// Package mcpauthidjag implements the gateway-to-upstream half of MCP
// authentication: once the MCP Authentication policy has validated the
// client's gateway token, this policy obtains a per-user access token for the
// upstream MCP server through the Identity Assertion JWT Authorization Grant
// (ID-JAG) profile, draft-ietf-oauth-identity-assertion-authz-grant:
//
//	step 0 (refresh_token mode only)
//	        RFC 8693 token exchange at the IdP: inbound access token in,
//	        access token + refresh token out. The refresh token is bound to
//	        the gateway's IdP client, as the profile requires of a refresh
//	        token presented as the identity assertion.
//	step 1  RFC 8693 token exchange at the IdP: identity assertion (ID token
//	        or that refresh token) in, ID-JAG out, for the Resource AS named
//	        by `audience`.
//	step 2  RFC 7523 JWT-bearer grant at the Resource AS: ID-JAG in, access
//	        token out.
//	step 3  (refresh_token mode, when idpRevocationEndpoint is set)
//	        RFC 7009 revocation of the step-0 refresh token, best effort.
//
// The step-2 access token replaces the inbound credential before the request
// is forwarded. Nothing but that access token is ever retained, and only when
// cacheResourceAccessToken is on. Client credentials come from named sets in
// the gateway configuration, never from policy parameters. The policy has no
// client-facing behaviour: it never runs unless the request is already
// authenticated, and it does not touch the auth context that authentication
// established.
package mcpauthidjag

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
	// GrantTypeTokenExchange is the RFC 8693 token exchange grant (steps 0 and 1).
	GrantTypeTokenExchange = "urn:ietf:params:oauth:grant-type:token-exchange"

	// GrantTypeJWTBearer is the RFC 7523 JWT-bearer grant (step 2).
	GrantTypeJWTBearer = "urn:ietf:params:oauth:grant-type:jwt-bearer"

	// TokenTypeIDJAG is the requested_token_type of step 1 and the issued_token_type its
	// response must carry.
	TokenTypeIDJAG = "urn:ietf:params:oauth:token-type:id-jag"

	// TokenTypeIDToken is the subject_token_type for an ID token assertion.
	TokenTypeIDToken = "urn:ietf:params:oauth:token-type:id_token"

	// TokenTypeRefreshToken is the subject_token_type for a refresh token assertion.
	TokenTypeRefreshToken = "urn:ietf:params:oauth:token-type:refresh_token"

	// TokenTypeAccessToken is the requested_token_type of step 0, and one of the
	// subject_token_type values an IdP may expect for the inbound access token there.
	TokenTypeAccessToken = "urn:ietf:params:oauth:token-type:access_token"

	// TokenTypeJWT is the other subject_token_type an IdP may expect for the inbound access
	// token in step 0.
	TokenTypeJWT = "urn:ietf:params:oauth:token-type:jwt"

	// IDJAGJWTType is the required `typ` header of an ID-JAG.
	IDJAGJWTType = "oauth-id-jag+jwt"

	// AssertionTypeIDToken / AssertionTypeRefreshToken are the assertionType parameter values.
	AssertionTypeIDToken      = "id_token"
	AssertionTypeRefreshToken = "refresh_token"

	// MetadataKeyCacheKey carries the request's cache key from the request phase to the
	// response phase, so an upstream rejection purges only that entry.
	MetadataKeyCacheKey = "mcpauthidjag.cacheKey"

	// MetadataKeyPhase records this policy's progress for the current request, so the body
	// phase knows whether the header phase deferred the exchange, finished it, or never ran.
	MetadataKeyPhase = "mcpauthidjag.phase"
	phaseDeferred    = "deferred"
	phaseDone        = "done"

	// ClientAuthMethodBasic (client_secret_basic) sends client ID/secret via HTTP Basic auth.
	ClientAuthMethodBasic = "client_secret_basic"

	// ClientAuthMethodPost (client_secret_post) sends client ID/secret as form fields.
	ClientAuthMethodPost = "client_secret_post"

	// defaultIDTokenHeader is where the ID token is read from in id_token mode.
	defaultIDTokenHeader = "X-ID-Token"

	// defaultAccessTokenHeader is where the access token is read from in refresh_token mode.
	defaultAccessTokenHeader = "Authorization"

	// defaultExpiryBuffer is how far ahead of expiry a cached token is treated as stale.
	defaultExpiryBuffer = 2 * time.Minute

	// defaultCacheMaxEntries bounds the access-token cache.
	defaultCacheMaxEntries = 10000

	// minAssertionLength rejects obviously-not-a-token header values defensively.
	minAssertionLength = 20

	logPrefix = "MCPAuthIDJAG: "
)

// exchangeSubjectTokenTypeURN maps the exchangeSubjectTokenType enum to the URN sent in step 0.
var exchangeSubjectTokenTypeURN = map[string]string{
	"jwt":          TokenTypeJWT,
	"access_token": TokenTypeAccessToken,
}

// policyParams bundles all extracted, validated policy params.
type policyParams struct {
	// Assertion source
	assertionType     string
	idTokenHeader     string
	accessTokenHeader string
	credentialRef     string
	creds             credentialSet

	// IdP
	idpTokenEndpoint         string
	idpClientAuthMethod      string
	audience                 string
	idpScopes                string
	idpResource              string
	idpTokenRequestParams    map[string]string
	idpTokenRequestHeaders   map[string]string
	exchangeSubjectTokenType string // URN
	exchangeScopes           string
	idpRevocationEndpoint    string

	// Resource AS
	resourceAsTokenEndpoint       string
	resourceAsClientAuthMethod    string
	resourceAsScopes              string
	resourceAsTokenRequestParams  map[string]string
	resourceAsTokenRequestHeaders map[string]string

	// Cache
	cacheResourceAccessToken bool
	cacheMaxEntries          int
	expiryBuffer             time.Duration
	tokenPurgeStatusCodes    map[int]struct{}

	// Injection and transport
	headerName             string
	valuePrefix            string
	tokenRequestTimeout    time.Duration
	defaultTokenTTL        time.Duration
	tokenRequestMaxRetries int
	proxyURL               string
	tlsCaCert              string
	tlsInsecureSkipVerify  bool
}

// inboundHeader is the header the assertion (or the access token it is derived from) is read
// from for the configured assertionType.
func (p policyParams) inboundHeader() string {
	if p.assertionType == AssertionTypeRefreshToken {
		return p.accessTokenHeader
	}
	return p.idTokenHeader
}

// Policy performs the ID-JAG exchange per request and injects the Resource AS access token.
type Policy struct {
	params     policyParams
	idpCred    clientCredential
	rasCred    clientCredential
	httpClient *http.Client
	cache      *tokenCache
	flight     *flightGroup
}

// stepError tags an error with the step it came from so classifyAndRespond can map it.
type stepError struct {
	step int
	err  error
}

func (e *stepError) Error() string {
	return fmt.Sprintf("step %d (%s): %v", e.step, stepName(e.step), e.err)
}
func (e *stepError) Unwrap() error { return e.err }

func stepName(step int) string {
	switch step {
	case 0:
		return "IdP access-token exchange for refresh token"
	case 1:
		return "IdP ID-JAG token exchange"
	case 2:
		return "Resource AS JWT-bearer grant"
	}
	return "unknown"
}

// GetPolicy is the v1alpha2 factory entry point (loaded by v1alpha2 kernels).
func GetPolicy(metadata policy.PolicyMetadata, params map[string]interface{}) (policy.Policy, error) {
	p, err := validateAndExtractParams(params)
	if err != nil {
		return nil, fmt.Errorf("invalid params: %w", err)
	}

	transport, err := getOrCreateTokenEndpointTransport(tokenEndpointTransportKey{
		proxyURL: p.proxyURL, tlsCACert: p.tlsCaCert, tlsInsecureSkipVerify: p.tlsInsecureSkipVerify,
	})
	if err != nil {
		return nil, fmt.Errorf("invalid token endpoint transport config: %w", err)
	}

	pol := &Policy{
		params:     p,
		idpCred:    clientCredential{id: p.creds.idpClientID, secret: p.creds.idpClientSecret, style: authStyleFor(p.idpClientAuthMethod)},
		rasCred:    clientCredential{id: p.creds.resourceAsClientID, secret: p.creds.resourceAsClientSecret, style: authStyleFor(p.resourceAsClientAuthMethod)},
		httpClient: &http.Client{Timeout: p.tokenRequestTimeout, Transport: transport},
		cache:      newTokenCache(),
		flight:     newFlightGroup(),
	}

	if p.creds.idpClientID != p.creds.resourceAsClientID {
		// The profile (§4.4.1) has the Resource AS reject an ID-JAG whose client_id claim is not
		// the client authenticating the JWT-bearer request. Different ids can still work when the
		// IdP issues the ID-JAG with the Resource AS's notion of the client id, so warn, don't fail.
		slog.Warn(logPrefix+"credential set uses different client ids at the IdP and the Resource AS; the Resource AS will reject the ID-JAG unless its client_id claim matches the Resource AS client",
			"credentialRef", p.credentialRef, "idpClientId", p.creds.idpClientID, "resourceAsClientId", p.creds.resourceAsClientID)
	}

	slog.Info(logPrefix+"policy initialized",
		"assertionType", p.assertionType, "inboundHeader", p.inboundHeader(),
		"credentialRef", p.credentialRef,
		"idpTokenEndpoint", sanitizeEndpointForLogging(p.idpTokenEndpoint),
		"resourceAsTokenEndpoint", sanitizeEndpointForLogging(p.resourceAsTokenEndpoint),
		"audience", p.audience,
		"revokeRefreshToken", p.idpRevocationEndpoint != "",
		"cacheResourceAccessToken", p.cacheResourceAccessToken)

	return pol, nil
}

// validateAndExtractParams validates and extracts all policy params.
func validateAndExtractParams(params map[string]interface{}) (policyParams, error) {
	var p policyParams
	var err error

	// Assertion source
	if p.assertionType, err = getEnumParam(params, "assertionType", "", AssertionTypeIDToken, AssertionTypeRefreshToken); err != nil {
		return policyParams{}, err
	}
	p.idTokenHeader = getStringParamOrDefault(params, "idTokenHeader", defaultIDTokenHeader)
	if p.idTokenHeader == "" {
		p.idTokenHeader = defaultIDTokenHeader
	}
	p.accessTokenHeader = getStringParamOrDefault(params, "accessTokenHeader", defaultAccessTokenHeader)
	if p.accessTokenHeader == "" {
		p.accessTokenHeader = defaultAccessTokenHeader
	}
	if p.credentialRef, err = getRequiredStringParam(params, "credentialRef"); err != nil {
		return policyParams{}, err
	}
	if p.creds, err = resolveCredentialSet(params, p.credentialRef); err != nil {
		return policyParams{}, err
	}

	// IdP
	if p.idpTokenEndpoint, err = getRequiredStringParam(params, "idpTokenEndpoint"); err != nil {
		return policyParams{}, err
	}
	if p.idpClientAuthMethod, err = getEnumParam(params, "idpClientAuthMethod", ClientAuthMethodPost, ClientAuthMethodBasic, ClientAuthMethodPost); err != nil {
		return policyParams{}, err
	}
	if p.audience, err = getRequiredStringParam(params, "audience"); err != nil {
		return policyParams{}, err
	}
	p.idpScopes = getStringParam(params, "idpScopes")
	p.idpResource = getStringParam(params, "idpResource")
	p.idpTokenRequestParams = getStringMapParam(params, "idpTokenRequestParams")
	p.idpTokenRequestHeaders = getStringMapParam(params, "idpTokenRequestHeaders")
	short, err := getEnumParam(params, "exchangeSubjectTokenType", "jwt", "jwt", "access_token")
	if err != nil {
		return policyParams{}, err
	}
	p.exchangeSubjectTokenType = exchangeSubjectTokenTypeURN[short]
	p.exchangeScopes = getStringParam(params, "exchangeScopes")
	p.idpRevocationEndpoint = getStringParam(params, "idpRevocationEndpoint")

	// Resource AS
	if p.resourceAsTokenEndpoint, err = getRequiredStringParam(params, "resourceAsTokenEndpoint"); err != nil {
		return policyParams{}, err
	}
	if p.resourceAsClientAuthMethod, err = getEnumParam(params, "resourceAsClientAuthMethod", ClientAuthMethodPost, ClientAuthMethodBasic, ClientAuthMethodPost); err != nil {
		return policyParams{}, err
	}
	p.resourceAsScopes = getStringParam(params, "resourceAsScopes")
	p.resourceAsTokenRequestParams = getStringMapParam(params, "resourceAsTokenRequestParams")
	p.resourceAsTokenRequestHeaders = getStringMapParam(params, "resourceAsTokenRequestHeaders")

	// Cache
	p.cacheResourceAccessToken = getBoolParam(params, "cacheResourceAccessToken", false)
	p.cacheMaxEntries = getIntParam(params, "cacheMaxEntries", defaultCacheMaxEntries)
	if p.cacheMaxEntries < 1 {
		p.cacheMaxEntries = defaultCacheMaxEntries
	}
	p.expiryBuffer = getDurationParam(params, "expiryBuffer", defaultExpiryBuffer)
	if p.expiryBuffer < 0 {
		p.expiryBuffer = defaultExpiryBuffer
	}
	p.tokenPurgeStatusCodes = getPurgeStatusCodesParam(params, "tokenPurgeStatusCodes", defaultPurgeStatusCodes)

	// Injection and transport
	p.headerName = getStringParamOrDefault(params, "headerName", defaultHeaderName)
	if p.headerName == "" {
		p.headerName = defaultHeaderName
	}
	p.valuePrefix = getStringParamOrDefault(params, "valuePrefix", defaultValuePrefix)
	p.tokenRequestTimeout = getPositiveDurationParam(params, "tokenRequestTimeout", defaultTokenRequestTimeout)
	p.defaultTokenTTL = getPositiveDurationParam(params, "defaultTokenTTL", defaultTokenTTLFallback)
	p.tokenRequestMaxRetries = getIntParam(params, "tokenRequestMaxRetries", defaultTokenRequestMaxRetries)
	p.proxyURL = getStringParam(params, "proxyURL")
	p.tlsCaCert = getStringParam(params, "tlsCaCert")
	p.tlsInsecureSkipVerify = getBoolParam(params, "tlsInsecureSkipVerify", false)
	if p.tlsInsecureSkipVerify {
		slog.Warn(logPrefix + "tlsInsecureSkipVerify is enabled - TLS certificate verification for the token endpoints is disabled; never use this against a real identity provider")
	}

	return p, nil
}

// Mode declares processing per phase. The request body is buffered because the MCP
// Authentication policy validates POST /mcp only in the body phase (it needs the JSON-RPC
// method to apply its exemptions), so the auth context this policy depends on does not exist
// yet when request headers are processed. The exchange then runs in OnRequestBody, right
// after that validation. Transport requests (GET/DELETE) are validated in the header phase
// and handled there. Response headers are processed only when a cached token could need
// purging.
func (p *Policy) Mode() policy.ProcessingMode {
	responseHeaderMode := policy.HeaderModeSkip
	if p.params.cacheResourceAccessToken && len(p.params.tokenPurgeStatusCodes) > 0 {
		responseHeaderMode = policy.HeaderModeProcess
	}
	return policy.ProcessingMode{
		RequestHeaderMode:  policy.HeaderModeProcess,
		RequestBodyMode:    policy.BodyModeBuffer,
		ResponseHeaderMode: responseHeaderMode,
		ResponseBodyMode:   policy.BodyModeSkip,
	}
}

// OnRequestHeaders runs the exchange when MCP Authentication has already validated the
// request (transport requests). Otherwise it defers to OnRequestBody.
func (p *Policy) OnRequestHeaders(ctx context.Context, req *policy.RequestHeaderContext, _ map[string]interface{}) policy.RequestHeaderAction {
	shared := req.SharedContext
	if !isAuthenticated(shared) {
		markPhase(shared, phaseDeferred)
		return policy.UpstreamRequestHeaderModifications{}
	}

	tok, cacheState, resp := p.acquire(ctx, shared, downstreamSnapshot(req.Downstream))
	if resp != nil {
		return *resp
	}
	markPhase(shared, phaseDone)
	set, remove, analytics := p.headerMods(tok, cacheState)
	return policy.UpstreamRequestHeaderModifications{HeadersToSet: set, HeadersToRemove: remove, AnalyticsMetadata: analytics}
}

// OnRequestBody completes an exchange the header phase deferred. Reaching it without an
// authenticated context means no auth policy claimed the request (an auth failure would have
// ended the chain with its own response), so the request is rejected rather than forwarded
// with an unexchanged credential.
func (p *Policy) OnRequestBody(ctx context.Context, req *policy.RequestContext, _ map[string]interface{}) policy.RequestAction {
	shared := req.SharedContext
	if phaseOf(shared) != phaseDeferred {
		return policy.UpstreamRequestModifications{}
	}
	if !isAuthenticated(shared) {
		slog.Warn(logPrefix + "rejecting request - not authenticated by the MCP Authentication policy")
		return unauthorized("request not authenticated")
	}

	tok, cacheState, resp := p.acquire(ctx, shared, downstreamSnapshot(req.Downstream))
	if resp != nil {
		return *resp
	}
	markPhase(shared, phaseDone)
	set, remove, analytics := p.headerMods(tok, cacheState)
	return policy.UpstreamRequestModifications{HeadersToSet: set, HeadersToRemove: remove, AnalyticsMetadata: analytics}
}

// acquire reads the inbound credential from the downstream snapshot and serves the cache or
// runs the exchange. It is phase-agnostic; a non-nil response is the failure to return
// verbatim.
func (p *Policy) acquire(ctx context.Context, shared *policy.SharedContext, snapshot *policy.Headers) (*exchangedToken, string, *policy.ImmediateResponse) {
	fail := func(r policy.ImmediateResponse) (*exchangedToken, string, *policy.ImmediateResponse) {
		return nil, "", &r
	}

	// The assertion (ID token) or its source (access token) comes from the pre-mutation
	// snapshot, independent of whether MCP Authentication stripped or forwarded it.
	if snapshot == nil {
		slog.Warn(logPrefix + "downstream request snapshot unavailable")
		return fail(unauthorized("missing inbound token"))
	}
	header := p.params.inboundHeader()
	inbound := bearerFrom(snapshot.Get(header))
	if inbound == "" {
		slog.Warn(logPrefix+"inbound token missing", "assertionType", p.params.assertionType, "header", header)
		return fail(unauthorized(fmt.Sprintf("missing %s in %s header", p.params.assertionType, header)))
	}
	if p.params.assertionType == AssertionTypeIDToken && !looksLikeJWT(inbound) {
		slog.Warn(logPrefix+"inbound ID token is not a JWT", "header", header)
		return fail(unauthorized(fmt.Sprintf("%s header does not carry an ID token", header)))
	}

	key := sha256hex(inbound)

	if p.params.cacheResourceAccessToken {
		p.stashCacheKey(shared, key)
		if tok, ok := p.cache.get(key, p.params.expiryBuffer); ok {
			return tok, "hit", nil
		}
	}

	// Single-flighted per key so N concurrent requests carrying the same assertion produce one
	// exchange sequence - with caching off this is the only thing that stops an MCP client's
	// initialize/tools/list burst from fanning out into parallel exchanges.
	tok, err := p.flight.Do(key, func() (*exchangedToken, error) {
		return p.exchange(ctx, inbound, key)
	})
	if err != nil {
		return fail(p.classifyAndRespond(err, key))
	}
	cacheState := "disabled"
	if p.params.cacheResourceAccessToken {
		cacheState = "miss"
	}
	return tok, cacheState, nil
}

// downstreamSnapshot returns the pre-mutation request headers, or nil.
func downstreamSnapshot(ds *policy.DownstreamContext) *policy.Headers {
	if ds == nil || ds.Request == nil {
		return nil
	}
	return ds.Request.Headers
}

// isAuthenticated reports whether an earlier policy validated the request.
func isAuthenticated(shared *policy.SharedContext) bool {
	return shared != nil && shared.AuthContext != nil && shared.AuthContext.Authenticated
}

func markPhase(shared *policy.SharedContext, phase string) {
	if shared == nil {
		return
	}
	if shared.Metadata == nil {
		shared.Metadata = map[string]any{}
	}
	shared.Metadata[MetadataKeyPhase] = phase
}

func phaseOf(shared *policy.SharedContext) string {
	if shared == nil || shared.Metadata == nil {
		return ""
	}
	v, _ := shared.Metadata[MetadataKeyPhase].(string)
	return v
}

// exchange runs steps 0-3 for one inbound credential. Only the step-2 access token leaves this
// function; the refresh token and the ID-JAG live in its locals and nowhere else.
func (p *Policy) exchange(ctx context.Context, inbound, key string) (*exchangedToken, error) {
	subject, subjectType := inbound, TokenTypeIDToken

	if p.params.assertionType == AssertionTypeRefreshToken {
		refreshToken, err := p.obtainRefreshToken(ctx, inbound)
		if err != nil {
			return nil, &stepError{step: 0, err: err}
		}
		subject, subjectType = refreshToken, TokenTypeRefreshToken
		if p.params.idpRevocationEndpoint != "" {
			// Runs whether or not step 2 succeeds: once step 1 has consumed the refresh token
			// there is no reason for it to stay valid at the IdP.
			defer p.revokeRefreshToken(ctx, refreshToken, key)
		}
	}

	idJag, idJagScopes, err := p.requestIDJAG(ctx, subject, subjectType, key)
	if err != nil {
		return nil, &stepError{step: 1, err: err}
	}

	tok, err := p.redeemIDJAG(ctx, idJag, idJagScopes)
	if err != nil {
		return nil, &stepError{step: 2, err: err}
	}

	result := &exchangedToken{Token: *tok, grantedScope: tok.Scope}
	if result.grantedScope == "" {
		result.grantedScope = strings.Join(scopeList(jwtClaims(tok.AccessToken)), " ")
	}

	if p.params.cacheResourceAccessToken {
		// TTL is bounded by min(expires_in, inbound credential's exp); the buffer is applied at
		// read time by tokenCache.get.
		if result.Expiry.IsZero() {
			result.Expiry = time.Now().Add(p.params.defaultTokenTTL)
		}
		if expIn, ok := jwtExp(inbound); ok && expIn.Before(result.Expiry) {
			result.Expiry = expIn
		}
		p.cache.put(key, result, p.params.cacheMaxEntries)
	}

	slog.Debug(logPrefix+"exchange complete", "cacheKeyId", key[:8], "assertionType", p.params.assertionType,
		"grantedScope", result.grantedScope, "cached", p.params.cacheResourceAccessToken)
	return result, nil
}

// obtainRefreshToken is step 0: RFC 8693 token exchange at the IdP that turns the inbound
// access token into an access token + refresh token for the gateway's own IdP client. Only the
// refresh token is kept, and only until step 1 has used it. An IdP that answers without a
// refresh token is a hard failure - the policy never falls back to a non-compliant assertion.
func (p *Policy) obtainRefreshToken(ctx context.Context, accessToken string) (string, error) {
	form := url.Values{}
	form.Set("grant_type", GrantTypeTokenExchange)
	form.Set("subject_token", accessToken)
	form.Set("subject_token_type", p.params.exchangeSubjectTokenType)
	form.Set("requested_token_type", TokenTypeAccessToken)
	if p.params.exchangeScopes != "" {
		form.Set("scope", p.params.exchangeScopes)
	}

	tok, err := fetchWithRetry(ctx, p.params.tokenRequestMaxRetries, func(ctx context.Context) (*Token, error) {
		return doTokenRequest(ctx, p.httpClient, p.params.idpTokenEndpoint, p.idpCred, cloneURLValues(form), p.params.idpTokenRequestHeaders)
	})
	if err != nil {
		return "", err
	}
	if tok.RefreshToken == "" {
		return "", &nonRetryableTokenError{err: fmt.Errorf("IdP token exchange response carried no refresh_token: the IdP must issue a refresh token to client %q from an access-token exchange for refresh_token assertions to work", p.idpCred.id)}
	}
	return tok.RefreshToken, nil
}

// requestIDJAG is step 1: RFC 8693 token exchange at the IdP with the identity assertion as the
// subject token, requesting an ID-JAG for `audience`. The response is checked against the
// profile (issued_token_type, typ, aud, exp) before the ID-JAG is handed to step 2, so a
// misconfiguration fails here with a precise message rather than as an opaque Resource AS
// rejection. Returns the ID-JAG and the scopes it carries.
func (p *Policy) requestIDJAG(ctx context.Context, subject, subjectType, key string) (string, []string, error) {
	form := url.Values{}
	for k, v := range p.params.idpTokenRequestParams {
		form.Set(k, v)
	}
	// Core fields set last so extras can never override them.
	form.Set("grant_type", GrantTypeTokenExchange)
	form.Set("subject_token", subject)
	form.Set("subject_token_type", subjectType)
	form.Set("requested_token_type", TokenTypeIDJAG)
	form.Set("audience", p.params.audience)
	if p.params.idpScopes != "" {
		form.Set("scope", p.params.idpScopes)
	}
	if p.params.idpResource != "" {
		form.Set("resource", p.params.idpResource)
	}

	tok, err := fetchWithRetry(ctx, p.params.tokenRequestMaxRetries, func(ctx context.Context) (*Token, error) {
		return doTokenRequest(ctx, p.httpClient, p.params.idpTokenEndpoint, p.idpCred, cloneURLValues(form), p.params.idpTokenRequestHeaders)
	})
	if err != nil {
		return "", nil, err
	}

	switch tok.IssuedTokenType {
	case TokenTypeIDJAG:
	case "":
		slog.Warn(logPrefix+"ID-JAG response omits issued_token_type (the profile requires it)", "cacheKeyId", key[:8])
	default:
		return "", nil, &nonRetryableTokenError{err: fmt.Errorf("IdP returned issued_token_type %q, expected %q", tok.IssuedTokenType, TokenTypeIDJAG)}
	}
	if tok.RefreshToken != "" {
		slog.Warn(logPrefix+"ID-JAG response carried a refresh_token, which the profile says it should not; discarded", "cacheKeyId", key[:8])
	}

	scopes, err := validateIDJAG(tok.AccessToken, p.params.audience, p.idpCred.id, key)
	if err != nil {
		return "", nil, &nonRetryableTokenError{err: err}
	}
	if len(scopes) == 0 && tok.Scope != "" {
		scopes = strings.Fields(tok.Scope)
	}
	return tok.AccessToken, scopes, nil
}

// validateIDJAG checks the ID-JAG's header and claims against the profile's requirements for
// what the Resource AS will verify: typ oauth-id-jag+jwt, aud naming the Resource AS, an
// unexpired exp. Required claims that are merely absent are logged, since the Resource AS is
// the authority on them. Returns the scopes the ID-JAG carries.
func validateIDJAG(idJag, audience, clientID, key string) ([]string, error) {
	header, ok := jwtSegment(idJag, 0)
	if !ok {
		return nil, fmt.Errorf("ID-JAG is not a JWT")
	}
	claims, ok := jwtSegment(idJag, 1)
	if !ok {
		return nil, fmt.Errorf("ID-JAG payload is not decodable")
	}

	if typ := claimString(header, "typ"); !strings.EqualFold(typ, IDJAGJWTType) {
		return nil, fmt.Errorf("ID-JAG typ header is %q, expected %q", typ, IDJAGJWTType)
	}

	auds := claimStrings(claims, "aud")
	if len(auds) == 0 {
		return nil, fmt.Errorf("ID-JAG has no aud claim")
	}
	if len(auds) > 1 {
		return nil, fmt.Errorf("ID-JAG aud has %d values, the profile allows exactly one", len(auds))
	}
	if auds[0] != audience {
		return nil, fmt.Errorf("ID-JAG aud %q does not match the configured audience %q", auds[0], audience)
	}

	exp, ok := claims["exp"].(float64)
	if !ok {
		return nil, fmt.Errorf("ID-JAG has no exp claim")
	}
	if !time.Unix(int64(exp), 0).After(time.Now()) {
		return nil, fmt.Errorf("ID-JAG is already expired")
	}

	for _, name := range []string{"iss", "sub", "jti", "iat", "client_id"} {
		if _, present := claims[name]; !present {
			slog.Warn(logPrefix+"ID-JAG lacks a claim the profile requires", "claim", name, "cacheKeyId", key[:8])
		}
	}
	if cid := claimString(claims, "client_id"); cid != "" && cid != clientID {
		slog.Warn(logPrefix+"ID-JAG client_id differs from the IdP client that requested it", "client_id", cid, "idpClientId", clientID, "cacheKeyId", key[:8])
	}

	return scopeList(claims), nil
}

// redeemIDJAG is step 2: RFC 7523 JWT-bearer grant at the Resource AS. resourceAsScopes, when
// set, must sit within the ID-JAG's scopes - the Resource AS may only narrow, never widen, so
// asking for more is a configuration error caught here.
func (p *Policy) redeemIDJAG(ctx context.Context, idJag string, idJagScopes []string) (*Token, error) {
	if p.params.resourceAsScopes != "" && len(idJagScopes) > 0 {
		if outside := scopesOutside(strings.Fields(p.params.resourceAsScopes), idJagScopes); len(outside) > 0 {
			return nil, &nonRetryableTokenError{err: fmt.Errorf("resourceAsScopes %v are not within the ID-JAG's scope %v", outside, idJagScopes)}
		}
	}

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

	return fetchWithRetry(ctx, p.params.tokenRequestMaxRetries, func(ctx context.Context) (*Token, error) {
		return doTokenRequest(ctx, p.httpClient, p.params.resourceAsTokenEndpoint, p.rasCred, cloneURLValues(form), p.params.resourceAsTokenRequestHeaders)
	})
}

// revokeRefreshToken is step 3: best-effort RFC 7009 revocation of the step-0 refresh token.
// Detached from the request context so a client disconnect mid-exchange still revokes.
func (p *Policy) revokeRefreshToken(ctx context.Context, refreshToken, key string) {
	rctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), revocationTimeout)
	defer cancel()
	err := doRevocationRequest(rctx, p.httpClient, p.params.idpRevocationEndpoint, p.idpCred, refreshToken, "refresh_token", p.params.idpTokenRequestHeaders)
	if err != nil {
		slog.Warn(logPrefix+"refresh token revocation failed; the token stays valid at the IdP until it expires",
			"error", redactURLCredentials(err.Error()),
			"idpRevocationEndpoint", sanitizeEndpointForLogging(p.params.idpRevocationEndpoint), "cacheKeyId", key[:8])
		return
	}
	slog.Debug(logPrefix+"refresh token revoked", "cacheKeyId", key[:8])
}

// classifyAndRespond maps exchange errors to the HTTP response:
//   - step 0 or 1 invalid_grant / interaction_required -> 401 (the IdP no longer accepts the
//     user's credential; the client must sign in again)
//   - anything else, including every step 2 rejection -> 502 (trust or configuration; the user
//     cannot fix it, and a 401 would only make the client loop on sign-in)
func (p *Policy) classifyAndRespond(err error, key string) policy.ImmediateResponse {
	var se *stepError
	if !errors.As(err, &se) {
		slog.Error(logPrefix+"credential acquisition failed", "error", redactURLCredentials(err.Error()), "cacheKeyId", key[:8])
		return badGateway()
	}

	var te *TokenError
	if se.step < 2 && errors.As(se.err, &te) && isReauthError(te) {
		slog.Warn(logPrefix+"IdP rejected the assertion - client must re-authenticate",
			"step", se.step, "error", te.ErrorCode, "errorDescription", te.ErrorDescription,
			"correlationId", te.CorrelationID, "cacheKeyId", key[:8])
		return unauthorized(te.ErrorDescription)
	}

	endpoint := p.params.idpTokenEndpoint
	clientID := p.idpCred.id
	if se.step == 2 {
		endpoint = p.params.resourceAsTokenEndpoint
		clientID = p.rasCred.id
	}
	slog.Error(logPrefix+stepName(se.step)+" failed",
		"step", se.step, "error", redactURLCredentials(se.err.Error()),
		"endpoint", sanitizeEndpointForLogging(endpoint), "clientId", clientID,
		"credentialRef", p.params.credentialRef, "cacheKeyId", key[:8])
	return badGateway()
}

// isReauthError classifies an IdP rejection: true means the client re-authenticating can fix
// it (-> 401), false means it is the gateway's own configuration (-> 502).
func isReauthError(te *TokenError) bool {
	switch te.ErrorCode {
	case "invalid_grant", "interaction_required":
		return true
	}
	return false
}

// OnResponseHeaders purges only the requesting user's cached access token when the upstream
// rejects it (default: 401), so the next request for that user re-exchanges while other users'
// entries stay. Only reached when caching is on (see Mode).
func (p *Policy) OnResponseHeaders(ctx context.Context, respCtx *policy.ResponseHeaderContext, _ map[string]interface{}) policy.ResponseHeaderAction {
	if _, purge := p.params.tokenPurgeStatusCodes[respCtx.ResponseStatus]; purge {
		if key := p.stashedCacheKey(respCtx.SharedContext); key != "" {
			slog.Warn(logPrefix+"upstream rejected the exchanged token, purging its cache entry",
				"status", respCtx.ResponseStatus, "cacheKeyId", key[:8])
			p.cache.delete(key)
		}
	}
	return policy.DownstreamResponseHeaderModifications{}
}

// stashCacheKey records the request's cache key in shared metadata for the response phase.
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

// headerMods computes the credential swap: the Resource AS access token goes into headerName,
// and the inbound header is removed when it is a different header (when both are
// Authorization, HeadersToSet overwrites - either way the inbound credential never goes
// upstream). Shared by both request phases.
func (p *Policy) headerMods(tok *exchangedToken, cacheState string) (set map[string]string, remove []string, analytics map[string]any) {
	if inbound := p.params.inboundHeader(); !strings.EqualFold(inbound, p.params.headerName) {
		remove = []string{inbound}
	}
	set = map[string]string{
		p.params.headerName: buildHeaderValue(p.params.valuePrefix, tok.AccessToken),
	}
	analytics = map[string]any{
		"id-jag.cache":         cacheState,
		"id-jag.assertionType": p.params.assertionType,
		"id-jag.grantedScope":  tok.grantedScope,
	}
	return set, remove, analytics
}

// unauthorized is the response when the user's credential cannot be exchanged any more (the
// IdP rejected it) or is missing from the request. RFC 6750 §3 requires WWW-Authenticate on a
// 401; the client's discovery already happened through MCP Authentication, so no pointer is
// carried.
func unauthorized(desc string) policy.ImmediateResponse {
	desc = strings.ReplaceAll(desc, `"`, "'")
	challenge := `Bearer error="invalid_token"`
	if desc != "" {
		challenge += `, error_description="` + desc + `"`
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

// badGateway is the gateway-side-fault response: the client's token was fine, the gateway
// could not mint the upstream credential - a 502 keeps clients from looping on sign-in.
func badGateway() policy.ImmediateResponse {
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

// ─── Token and claim helpers ──────────────────────────────────────────────────

// bearerFrom extracts the bare token from the header values: first non-empty value, "Bearer "
// scheme stripped case-insensitively, defensively rejecting values with embedded whitespace or
// implausibly short ones.
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

// looksLikeJWT is a cheap structural check: three dot-separated segments with a decodable payload.
func looksLikeJWT(token string) bool {
	if strings.Count(token, ".") != 2 {
		return false
	}
	_, ok := jwtSegment(token, 1)
	return ok
}

// jwtSegment base64url-decodes segment i (0 header, 1 payload) of a JWT into a JSON object,
// without any signature check - the IdP validates assertions, and the tokens the policy
// inspects come straight from token endpoints over TLS.
func jwtSegment(token string, i int) (map[string]any, bool) {
	parts := strings.Split(token, ".")
	if len(parts) < 2 || i >= len(parts) {
		return nil, false
	}
	data, err := base64.RawURLEncoding.DecodeString(strings.TrimRight(parts[i], "="))
	if err != nil {
		return nil, false
	}
	var obj map[string]any
	if err := json.Unmarshal(data, &obj); err != nil {
		return nil, false
	}
	return obj, true
}

// jwtExp reads the exp claim of a JWT; ok=false on any parse failure (the caller falls back
// to expires_in). An opaque token simply has no exp.
func jwtExp(token string) (time.Time, bool) {
	claims, ok := jwtSegment(token, 1)
	if !ok {
		return time.Time{}, false
	}
	exp, ok := claims["exp"].(float64)
	if !ok {
		return time.Time{}, false
	}
	return time.Unix(int64(exp), 0), true
}

// jwtClaims returns the decoded payload, or an empty map when the token is not a JWT.
func jwtClaims(token string) map[string]any {
	claims, ok := jwtSegment(token, 1)
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

// scopeList reads scopes from scope (space-separated string, or an array) or scp.
func scopeList(claims map[string]any) []string {
	for _, name := range []string{"scope", "scp"} {
		switch v := claims[name].(type) {
		case string:
			if f := strings.Fields(v); len(f) > 0 {
				return f
			}
		case []any:
			var out []string
			for _, item := range v {
				if s, ok := item.(string); ok {
					out = append(out, s)
				}
			}
			if len(out) > 0 {
				return out
			}
		}
	}
	return nil
}

// scopesOutside returns the members of requested that are not in granted.
func scopesOutside(requested, granted []string) []string {
	set := make(map[string]struct{}, len(granted))
	for _, g := range granted {
		set[g] = struct{}{}
	}
	var out []string
	for _, r := range requested {
		if _, ok := set[r]; !ok {
			out = append(out, r)
		}
	}
	return out
}
