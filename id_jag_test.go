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

package mcpauthidjag

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	policy "github.com/wso2/api-platform/sdk/core/policy/v1alpha2"
)

// ─── Fakes ────────────────────────────────────────────────────────────────────

// fakeIdP records every token-endpoint and revocation call it receives and answers each
// grant from its configurable handlers.
type fakeIdP struct {
	srv *httptest.Server

	mu          sync.Mutex
	exchanges   []url.Values // step 0 and step 1 calls, in order
	revocations []url.Values

	// Behaviour knobs
	refreshToken     string // step 0 response; "" omits refresh_token
	step0Error       *TokenError
	step1Error       *TokenError
	idJagTyp         string
	idJagAud         any
	idJagScope       string
	idJagExpired     bool
	issuedTokenType  string // "" -> TokenTypeIDJAG; "omit" -> field absent
	idJagRefreshTok  string
	revocationStatus int
	clientID         string
	audience         string
}

func newFakeIdP(t *testing.T, clientID, audience string) *fakeIdP {
	t.Helper()
	f := &fakeIdP{refreshToken: "rt-0123456789abcdef0123", idJagTyp: IDJAGJWTType, clientID: clientID, audience: audience, revocationStatus: 200}
	f.idJagAud = audience
	mux := http.NewServeMux()
	mux.HandleFunc("/token", f.token)
	mux.HandleFunc("/revoke", f.revoke)
	f.srv = httptest.NewServer(mux)
	t.Cleanup(f.srv.Close)
	return f
}

func (f *fakeIdP) token(w http.ResponseWriter, r *http.Request) {
	_ = r.ParseForm()
	f.mu.Lock()
	f.exchanges = append(f.exchanges, r.PostForm)
	f.mu.Unlock()

	if r.PostForm.Get("grant_type") != GrantTypeTokenExchange {
		writeTokenError(w, 400, "unsupported_grant_type", "")
		return
	}
	switch r.PostForm.Get("requested_token_type") {
	case TokenTypeAccessToken: // step 0
		if f.step0Error != nil {
			writeTokenError(w, f.step0Error.StatusCode, f.step0Error.ErrorCode, f.step0Error.ErrorDescription)
			return
		}
		resp := map[string]any{"access_token": "at-fresh-0123456789abcdef", "token_type": "Bearer", "expires_in": 3600,
			"issued_token_type": TokenTypeAccessToken}
		if f.refreshToken != "" {
			resp["refresh_token"] = f.refreshToken
		}
		writeJSON(w, 200, resp)
	case TokenTypeIDJAG: // step 1
		if f.step1Error != nil {
			writeTokenError(w, f.step1Error.StatusCode, f.step1Error.ErrorCode, f.step1Error.ErrorDescription)
			return
		}
		exp := time.Now().Add(5 * time.Minute).Unix()
		if f.idJagExpired {
			exp = time.Now().Add(-time.Minute).Unix()
		}
		claims := map[string]any{"iss": f.srv.URL, "sub": "user-1", "aud": f.idJagAud, "client_id": f.clientID,
			"jti": "jti-1", "iat": time.Now().Unix(), "exp": exp}
		if f.idJagScope != "" {
			claims["scope"] = f.idJagScope
		}
		resp := map[string]any{"access_token": makeJWT(map[string]any{"typ": f.idJagTyp, "alg": "none"}, claims),
			"token_type": "N_A", "expires_in": 300}
		switch f.issuedTokenType {
		case "":
			resp["issued_token_type"] = TokenTypeIDJAG
		case "omit":
		default:
			resp["issued_token_type"] = f.issuedTokenType
		}
		if f.idJagRefreshTok != "" {
			resp["refresh_token"] = f.idJagRefreshTok
		}
		writeJSON(w, 200, resp)
	default:
		writeTokenError(w, 400, "invalid_request", "unexpected requested_token_type")
	}
}

func (f *fakeIdP) revoke(w http.ResponseWriter, r *http.Request) {
	_ = r.ParseForm()
	f.mu.Lock()
	f.revocations = append(f.revocations, r.PostForm)
	f.mu.Unlock()
	w.WriteHeader(f.revocationStatus)
}

func (f *fakeIdP) calls() (step0, step1 []url.Values) {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, e := range f.exchanges {
		if e.Get("requested_token_type") == TokenTypeAccessToken {
			step0 = append(step0, e)
		} else {
			step1 = append(step1, e)
		}
	}
	return
}

func (f *fakeIdP) revoked() []url.Values {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]url.Values(nil), f.revocations...)
}

// fakeResourceAS answers the JWT-bearer grant and records what it was asked.
type fakeResourceAS struct {
	srv *httptest.Server

	mu    sync.Mutex
	calls []url.Values

	accessToken  string
	scope        string
	expiresIn    int
	err          *TokenError
	statusToSend int
}

func newFakeResourceAS(t *testing.T) *fakeResourceAS {
	t.Helper()
	f := &fakeResourceAS{accessToken: "ras-access-0123456789abcdef", expiresIn: 3600}
	f.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		f.mu.Lock()
		f.calls = append(f.calls, r.PostForm)
		f.mu.Unlock()
		if f.err != nil {
			writeTokenError(w, f.err.StatusCode, f.err.ErrorCode, f.err.ErrorDescription)
			return
		}
		resp := map[string]any{"access_token": f.accessToken, "token_type": "Bearer", "expires_in": f.expiresIn}
		if f.scope != "" {
			resp["scope"] = f.scope
		}
		writeJSON(w, 200, resp)
	}))
	t.Cleanup(f.srv.Close)
	return f
}

func (f *fakeResourceAS) received() []url.Values {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]url.Values(nil), f.calls...)
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeTokenError(w http.ResponseWriter, status int, code, desc string) {
	writeJSON(w, status, map[string]string{"error": code, "error_description": desc})
}

// makeJWT builds an unsigned JWT (alg none) - the policy never verifies signatures.
func makeJWT(header, claims map[string]any) string {
	h, _ := json.Marshal(header)
	c, _ := json.Marshal(claims)
	enc := base64.RawURLEncoding.EncodeToString
	return enc(h) + "." + enc(c) + "." + enc([]byte("sig"))
}

func userIDToken(exp time.Time) string {
	return makeJWT(map[string]any{"typ": "JWT", "alg": "none"},
		map[string]any{"iss": "https://idp.example", "sub": "user-1", "aud": "gw-client", "exp": exp.Unix(), "iat": time.Now().Unix()})
}

func userAccessToken(exp time.Time) string {
	return makeJWT(map[string]any{"typ": "at+jwt", "alg": "none"},
		map[string]any{"iss": "https://idp.example", "sub": "user-1", "aud": "gw-client", "exp": exp.Unix(), "scope": "openid"})
}

// ─── Harness ──────────────────────────────────────────────────────────────────

type harness struct {
	t   *testing.T
	idp *fakeIdP
	ras *fakeResourceAS
}

const (
	testAudience   = "https://ras.example"
	testIdPClient  = "gw-client"
	testRASClient  = "gw-client"
	testCredential = "mcp-server-a"
)

func newHarness(t *testing.T) *harness {
	t.Helper()
	return &harness{t: t, idp: newFakeIdP(t, testIdPClient, testAudience), ras: newFakeResourceAS(t)}
}

func (h *harness) params(overrides map[string]any) map[string]any {
	p := map[string]any{
		"assertionType":           AssertionTypeIDToken,
		"credentialRef":           testCredential,
		"idpTokenEndpoint":        h.idp.srv.URL + "/token",
		"audience":                testAudience,
		"resourceAsTokenEndpoint": h.ras.srv.URL,
		"tokenRequestMaxRetries":  0,
		"credentials": []any{
			map[string]any{"name": "other", "idpClientId": "x", "idpClientSecret": "y", "resourceAsClientId": "x", "resourceAsClientSecret": "y"},
			map[string]any{"name": testCredential, "idpClientId": testIdPClient, "idpClientSecret": "idp-secret",
				"resourceAsClientId": testRASClient, "resourceAsClientSecret": "ras-secret"},
		},
	}
	for k, v := range overrides {
		p[k] = v
	}
	return p
}

func (h *harness) policy(overrides map[string]any) *Policy {
	h.t.Helper()
	pol, err := GetPolicy(policy.PolicyMetadata{}, h.params(overrides))
	if err != nil {
		h.t.Fatalf("GetPolicy: %v", err)
	}
	return pol.(*Policy)
}

func request(headers map[string]string, authenticated bool) *policy.RequestHeaderContext {
	hv := map[string][]string{}
	for k, v := range headers {
		hv[k] = []string{v}
	}
	shared := &policy.SharedContext{Metadata: map[string]any{}}
	if authenticated {
		shared.AuthContext = &policy.AuthContext{Authenticated: true, AuthType: "mcp-auth", Subject: "user-1"}
	}
	return &policy.RequestHeaderContext{
		SharedContext: shared,
		Headers:       policy.NewHeaders(hv),
		Downstream:    &policy.DownstreamContext{Request: &policy.DownstreamRequest{Headers: policy.NewHeaders(hv)}},
	}
}

// bodyPhase builds the body-phase context for the same request, sharing its
// SharedContext exactly as the kernel does between phases.
func bodyPhase(req *policy.RequestHeaderContext, body string) *policy.RequestContext {
	return &policy.RequestContext{
		SharedContext: req.SharedContext,
		Headers:       req.Headers,
		Body:          &policy.Body{Content: []byte(body), EndOfStream: true},
		Downstream:    req.Downstream,
	}
}

func mustNoopHeaders(t *testing.T, a policy.RequestHeaderAction) {
	t.Helper()
	m, ok := a.(policy.UpstreamRequestHeaderModifications)
	if !ok || len(m.HeadersToSet) != 0 || len(m.HeadersToRemove) != 0 {
		t.Fatalf("expected a no-op header action, got %#v", a)
	}
}

func mustUpstreamBody(t *testing.T, a policy.RequestAction) policy.UpstreamRequestModifications {
	t.Helper()
	m, ok := a.(policy.UpstreamRequestModifications)
	if !ok {
		if ir, isResp := a.(policy.ImmediateResponse); isResp {
			t.Fatalf("expected upstream modifications, got immediate %d: %s", ir.StatusCode, ir.Body)
		}
		t.Fatalf("expected upstream modifications, got %T", a)
	}
	return m
}

func mustImmediateBody(t *testing.T, a policy.RequestAction, status int) policy.ImmediateResponse {
	t.Helper()
	ir, ok := a.(policy.ImmediateResponse)
	if !ok {
		t.Fatalf("expected immediate response, got %T", a)
	}
	if ir.StatusCode != status {
		t.Fatalf("expected status %d, got %d: %s", status, ir.StatusCode, ir.Body)
	}
	return ir
}

func mustUpstream(t *testing.T, a policy.RequestHeaderAction) policy.UpstreamRequestHeaderModifications {
	t.Helper()
	m, ok := a.(policy.UpstreamRequestHeaderModifications)
	if !ok {
		if ir, isResp := a.(policy.ImmediateResponse); isResp {
			t.Fatalf("expected upstream modifications, got immediate %d: %s", ir.StatusCode, ir.Body)
		}
		t.Fatalf("expected upstream modifications, got %T", a)
	}
	return m
}

func mustImmediate(t *testing.T, a policy.RequestHeaderAction, status int) policy.ImmediateResponse {
	t.Helper()
	ir, ok := a.(policy.ImmediateResponse)
	if !ok {
		t.Fatalf("expected immediate response, got %T", a)
	}
	if ir.StatusCode != status {
		t.Fatalf("expected status %d, got %d: %s", status, ir.StatusCode, ir.Body)
	}
	return ir
}

// ─── Tests: assertion modes ───────────────────────────────────────────────────

func TestIDTokenMode_HappyPath(t *testing.T) {
	h := newHarness(t)
	h.idp.idJagScope = "read:work write:work"
	h.ras.scope = "read:work"
	pol := h.policy(map[string]any{"idpScopes": "read:work write:work"})

	idTok := userIDToken(time.Now().Add(time.Hour))
	req := request(map[string]string{"Authorization": "Bearer " + userAccessToken(time.Now().Add(time.Hour)), "X-ID-Token": idTok}, true)
	mods := mustUpstream(t, pol.OnRequestHeaders(context.Background(), req, nil))

	if got := mods.HeadersToSet["Authorization"]; got != "Bearer "+h.ras.accessToken {
		t.Fatalf("injected header = %q", got)
	}
	if len(mods.HeadersToRemove) != 1 || !strings.EqualFold(mods.HeadersToRemove[0], "X-ID-Token") {
		t.Fatalf("expected the ID token header to be removed, got %v", mods.HeadersToRemove)
	}
	if mods.AnalyticsMetadata["id-jag.cache"] != "disabled" || mods.AnalyticsMetadata["id-jag.grantedScope"] != "read:work" {
		t.Fatalf("analytics = %v", mods.AnalyticsMetadata)
	}

	step0, step1 := h.idp.calls()
	if len(step0) != 0 {
		t.Fatalf("id_token mode must not perform the access-token exchange, saw %d", len(step0))
	}
	if len(step1) != 1 {
		t.Fatalf("expected one ID-JAG exchange, saw %d", len(step1))
	}
	s1 := step1[0]
	for k, want := range map[string]string{
		"grant_type": GrantTypeTokenExchange, "subject_token": idTok, "subject_token_type": TokenTypeIDToken,
		"requested_token_type": TokenTypeIDJAG, "audience": testAudience, "scope": "read:work write:work",
		"client_id": testIdPClient, "client_secret": "idp-secret",
	} {
		if got := s1.Get(k); got != want {
			t.Errorf("step 1 %s = %q, want %q", k, got, want)
		}
	}

	ras := h.ras.received()
	if len(ras) != 1 {
		t.Fatalf("expected one JWT-bearer call, saw %d", len(ras))
	}
	if ras[0].Get("grant_type") != GrantTypeJWTBearer || ras[0].Get("assertion") == "" || ras[0].Get("client_secret") != "ras-secret" {
		t.Fatalf("step 2 form = %v", ras[0])
	}
	if _, has := ras[0]["scope"]; has {
		t.Fatalf("scope must be omitted from step 2 when resourceAsScopes is empty")
	}
	if ac := req.SharedContext.AuthContext; ac == nil || !ac.Authenticated || ac.AuthType != "mcp-auth" {
		t.Fatalf("the auth context MCP Authentication set must be left untouched: %+v", ac)
	}
	if len(h.idp.revoked()) != 0 {
		t.Fatalf("nothing to revoke in id_token mode")
	}
}

func TestRefreshTokenMode_HappyPath_WithRevocation(t *testing.T) {
	h := newHarness(t)
	pol := h.policy(map[string]any{
		"assertionType":         AssertionTypeRefreshToken,
		"idpRevocationEndpoint": h.idp.srv.URL + "/revoke",
		"exchangeScopes":        "openid",
	})

	at := userAccessToken(time.Now().Add(time.Hour))
	req := request(map[string]string{"Authorization": "Bearer " + at}, true)
	mods := mustUpstream(t, pol.OnRequestHeaders(context.Background(), req, nil))

	if got := mods.HeadersToSet["Authorization"]; got != "Bearer "+h.ras.accessToken {
		t.Fatalf("injected header = %q", got)
	}
	if len(mods.HeadersToRemove) != 0 {
		t.Fatalf("Authorization is overwritten, not removed; got %v", mods.HeadersToRemove)
	}

	step0, step1 := h.idp.calls()
	if len(step0) != 1 || len(step1) != 1 {
		t.Fatalf("expected one step-0 and one step-1 call, saw %d / %d", len(step0), len(step1))
	}
	s0 := step0[0]
	for k, want := range map[string]string{
		"grant_type": GrantTypeTokenExchange, "subject_token": at, "subject_token_type": TokenTypeJWT,
		"requested_token_type": TokenTypeAccessToken, "scope": "openid", "client_id": testIdPClient,
	} {
		if got := s0.Get(k); got != want {
			t.Errorf("step 0 %s = %q, want %q", k, got, want)
		}
	}
	s1 := step1[0]
	if s1.Get("subject_token") != h.idp.refreshToken || s1.Get("subject_token_type") != TokenTypeRefreshToken {
		t.Fatalf("step 1 must present the step-0 refresh token as a refresh_token assertion, got %v", s1)
	}
	if s1.Get("client_id") != s0.Get("client_id") {
		t.Fatalf("steps 0 and 1 must use the same IdP client")
	}

	// Revocation is deferred; give it a moment.
	deadline := time.Now().Add(2 * time.Second)
	for len(h.idp.revoked()) == 0 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	rev := h.idp.revoked()
	if len(rev) != 1 || rev[0].Get("token") != h.idp.refreshToken || rev[0].Get("token_type_hint") != "refresh_token" {
		t.Fatalf("expected the refresh token to be revoked, got %v", rev)
	}
}

func TestRefreshTokenMode_AccessTokenSubjectTypeIsConfigurable(t *testing.T) {
	h := newHarness(t)
	pol := h.policy(map[string]any{"assertionType": AssertionTypeRefreshToken, "exchangeSubjectTokenType": "access_token"})
	req := request(map[string]string{"Authorization": "Bearer " + userAccessToken(time.Now().Add(time.Hour))}, true)
	mustUpstream(t, pol.OnRequestHeaders(context.Background(), req, nil))
	step0, _ := h.idp.calls()
	if step0[0].Get("subject_token_type") != TokenTypeAccessToken {
		t.Fatalf("subject_token_type = %q", step0[0].Get("subject_token_type"))
	}
}

func TestRefreshTokenMode_NoRefreshTokenIsHardFailure(t *testing.T) {
	h := newHarness(t)
	h.idp.refreshToken = ""
	pol := h.policy(map[string]any{"assertionType": AssertionTypeRefreshToken})
	req := request(map[string]string{"Authorization": "Bearer " + userAccessToken(time.Now().Add(time.Hour))}, true)

	mustImmediate(t, pol.OnRequestHeaders(context.Background(), req, nil), http.StatusBadGateway)
	_, step1 := h.idp.calls()
	if len(step1) != 0 {
		t.Fatalf("step 1 must not run without a refresh token")
	}
	if len(h.ras.received()) != 0 {
		t.Fatalf("Resource AS must not be contacted")
	}
}

func TestRefreshTokenMode_RevocationFailureDoesNotFailRequest(t *testing.T) {
	h := newHarness(t)
	h.idp.revocationStatus = 503
	pol := h.policy(map[string]any{"assertionType": AssertionTypeRefreshToken, "idpRevocationEndpoint": h.idp.srv.URL + "/revoke"})
	req := request(map[string]string{"Authorization": "Bearer " + userAccessToken(time.Now().Add(time.Hour))}, true)
	mustUpstream(t, pol.OnRequestHeaders(context.Background(), req, nil))
}

// ─── Tests: inbound validation ────────────────────────────────────────────────

func TestRejectsWhenNotAuthenticated(t *testing.T) {
	h := newHarness(t)
	pol := h.policy(nil)
	req := request(map[string]string{"X-ID-Token": userIDToken(time.Now().Add(time.Hour))}, false)
	// Header phase: no auth context yet, so the policy waits for the body phase
	// (where a body-phase auth policy such as MCP Authentication would have run).
	mustNoopHeaders(t, pol.OnRequestHeaders(context.Background(), req, nil))
	if _, step1 := h.idp.calls(); len(step1) != 0 {
		t.Fatalf("no exchange may run before the request is authenticated")
	}
	// Body phase: still nobody authenticated it -> 401.
	ir := mustImmediateBody(t, pol.OnRequestBody(context.Background(), bodyPhase(req, `{"jsonrpc":"2.0","method":"initialize"}`), nil), http.StatusUnauthorized)
	if ch := ir.Headers["WWW-Authenticate"]; !strings.HasPrefix(ch, `Bearer error="invalid_token"`) || strings.Contains(ch, "resource_metadata") {
		t.Fatalf("challenge must be a plain RFC 6750 one with no PRM pointer: %s", ch)
	}
}

// The shipped MCP Authentication policy validates POST /mcp in the body phase.
// This policy must therefore run its exchange after that, from its own body
// phase, and must not have rejected the request in the header phase.
func TestDeferredExchangeAfterBodyPhaseAuth(t *testing.T) {
	h := newHarness(t)
	pol := h.policy(nil)
	idTok := userIDToken(time.Now().Add(time.Hour))
	req := request(map[string]string{"Authorization": "Bearer " + userAccessToken(time.Now().Add(time.Hour)), "X-ID-Token": idTok}, false)

	mustNoopHeaders(t, pol.OnRequestHeaders(context.Background(), req, nil))

	// ... the body-phase auth policy validates the token and sets the context ...
	req.SharedContext.AuthContext = &policy.AuthContext{Authenticated: true, AuthType: "mcp", Subject: "user-1"}

	mods := mustUpstreamBody(t, pol.OnRequestBody(context.Background(), bodyPhase(req, `{"jsonrpc":"2.0","method":"tools/list"}`), nil))
	if got := mods.HeadersToSet["Authorization"]; got != "Bearer "+h.ras.accessToken {
		t.Fatalf("injected header = %q", got)
	}
	if len(mods.HeadersToRemove) != 1 || !strings.EqualFold(mods.HeadersToRemove[0], "X-ID-Token") {
		t.Fatalf("expected the ID token header to be removed, got %v", mods.HeadersToRemove)
	}
	if mods.Body != nil {
		t.Fatalf("the request body must pass through untouched")
	}
	if _, step1 := h.idp.calls(); len(step1) != 1 || len(h.ras.received()) != 1 {
		t.Fatalf("expected exactly one exchange")
	}
	if ac := req.SharedContext.AuthContext; ac == nil || !ac.Authenticated || ac.AuthType != "mcp" {
		t.Fatalf("the auth context MCP Authentication set must be left untouched: %+v", ac)
	}
}

func TestBodyPhaseIsNoopWhenHeaderPhaseAlreadyExchanged(t *testing.T) {
	h := newHarness(t)
	pol := h.policy(nil)
	req := request(map[string]string{"X-ID-Token": userIDToken(time.Now().Add(time.Hour))}, true)
	mustUpstream(t, pol.OnRequestHeaders(context.Background(), req, nil))
	mods := mustUpstreamBody(t, pol.OnRequestBody(context.Background(), bodyPhase(req, `{}`), nil))
	if len(mods.HeadersToSet) != 0 || len(mods.HeadersToRemove) != 0 {
		t.Fatalf("body phase must not redo the header phase's work: %#v", mods)
	}
	if len(h.ras.received()) != 1 {
		t.Fatalf("expected exactly one exchange across both phases, saw %d", len(h.ras.received()))
	}
}

func TestBodyPhaseIsNoopWhenHeaderPhaseNeverRan(t *testing.T) {
	h := newHarness(t)
	pol := h.policy(nil)
	req := request(map[string]string{"X-ID-Token": userIDToken(time.Now().Add(time.Hour))}, true)
	mods := mustUpstreamBody(t, pol.OnRequestBody(context.Background(), bodyPhase(req, `{}`), nil))
	if len(mods.HeadersToSet) != 0 || len(h.ras.received()) != 0 {
		t.Fatalf("body phase must only complete a deferred exchange")
	}
}

func TestModeBuffersRequestBodyForDeferredExchange(t *testing.T) {
	h := newHarness(t)
	if m := h.policy(nil).Mode(); m.RequestHeaderMode != policy.HeaderModeProcess || m.RequestBodyMode != policy.BodyModeBuffer {
		t.Fatalf("mode = %+v", m)
	}
}

func TestMissingIDTokenHeaderIs401(t *testing.T) {
	h := newHarness(t)
	pol := h.policy(nil)
	req := request(map[string]string{"Authorization": "Bearer " + userAccessToken(time.Now().Add(time.Hour))}, true)
	ir := mustImmediate(t, pol.OnRequestHeaders(context.Background(), req, nil), http.StatusUnauthorized)
	if !strings.Contains(string(ir.Body), "X-ID-Token") {
		t.Fatalf("error should name the missing header: %s", ir.Body)
	}
}

func TestIDTokenHeaderIsConfigurableAndBearerPrefixTolerated(t *testing.T) {
	h := newHarness(t)
	pol := h.policy(map[string]any{"idTokenHeader": "X-User-ID-Token"})
	idTok := userIDToken(time.Now().Add(time.Hour))
	req := request(map[string]string{"x-user-id-token": "Bearer " + idTok}, true)
	mustUpstream(t, pol.OnRequestHeaders(context.Background(), req, nil))
	_, step1 := h.idp.calls()
	if step1[0].Get("subject_token") != idTok {
		t.Fatalf("ID token not read from the configured header")
	}
}

func TestNonJWTIDTokenIs401(t *testing.T) {
	h := newHarness(t)
	pol := h.policy(nil)
	req := request(map[string]string{"X-ID-Token": "opaque-value-that-is-long-enough-0123"}, true)
	mustImmediate(t, pol.OnRequestHeaders(context.Background(), req, nil), http.StatusUnauthorized)
	if _, step1 := h.idp.calls(); len(step1) != 0 {
		t.Fatalf("IdP must not be called for a non-JWT ID token")
	}
}

// ─── Tests: error mapping ─────────────────────────────────────────────────────

func TestStep1InvalidGrantIs401WithChallenge(t *testing.T) {
	h := newHarness(t)
	h.idp.step1Error = &TokenError{StatusCode: 400, ErrorCode: "invalid_grant", ErrorDescription: "assertion expired"}
	pol := h.policy(nil)
	req := request(map[string]string{"X-ID-Token": userIDToken(time.Now().Add(time.Hour))}, true)
	ir := mustImmediate(t, pol.OnRequestHeaders(context.Background(), req, nil), http.StatusUnauthorized)
	ch := ir.Headers["WWW-Authenticate"]
	if !strings.HasPrefix(ch, `Bearer error="invalid_token"`) || !strings.Contains(ch, "assertion expired") {
		t.Fatalf("challenge = %s", ch)
	}
}

func TestStep0InvalidGrantIs401(t *testing.T) {
	h := newHarness(t)
	h.idp.step0Error = &TokenError{StatusCode: 400, ErrorCode: "invalid_grant", ErrorDescription: "token revoked"}
	pol := h.policy(map[string]any{"assertionType": AssertionTypeRefreshToken})
	req := request(map[string]string{"Authorization": "Bearer " + userAccessToken(time.Now().Add(time.Hour))}, true)
	mustImmediate(t, pol.OnRequestHeaders(context.Background(), req, nil), http.StatusUnauthorized)
}

func TestStep1InvalidClientIs502(t *testing.T) {
	h := newHarness(t)
	h.idp.step1Error = &TokenError{StatusCode: 401, ErrorCode: "invalid_client"}
	pol := h.policy(nil)
	req := request(map[string]string{"X-ID-Token": userIDToken(time.Now().Add(time.Hour))}, true)
	mustImmediate(t, pol.OnRequestHeaders(context.Background(), req, nil), http.StatusBadGateway)
}

func TestStep2RejectionIs502EvenForInvalidGrant(t *testing.T) {
	h := newHarness(t)
	h.ras.err = &TokenError{StatusCode: 400, ErrorCode: "invalid_grant", ErrorDescription: "client_id mismatch"}
	pol := h.policy(nil)
	req := request(map[string]string{"X-ID-Token": userIDToken(time.Now().Add(time.Hour))}, true)
	mustImmediate(t, pol.OnRequestHeaders(context.Background(), req, nil), http.StatusBadGateway)
}

// ─── Tests: ID-JAG validation ─────────────────────────────────────────────────

func TestIDJAGValidation(t *testing.T) {
	cases := []struct {
		name  string
		setup func(f *fakeIdP)
	}{
		{"wrong typ", func(f *fakeIdP) { f.idJagTyp = "JWT" }},
		{"aud mismatch", func(f *fakeIdP) { f.idJagAud = "https://someone-else.example" }},
		{"aud with two values", func(f *fakeIdP) { f.idJagAud = []string{testAudience, "https://other.example"} }},
		{"expired", func(f *fakeIdP) { f.idJagExpired = true }},
		{"wrong issued_token_type", func(f *fakeIdP) { f.issuedTokenType = TokenTypeAccessToken }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h := newHarness(t)
			tc.setup(h.idp)
			pol := h.policy(nil)
			req := request(map[string]string{"X-ID-Token": userIDToken(time.Now().Add(time.Hour))}, true)
			mustImmediate(t, pol.OnRequestHeaders(context.Background(), req, nil), http.StatusBadGateway)
			if len(h.ras.received()) != 0 {
				t.Fatalf("an ID-JAG that fails validation must never reach the Resource AS")
			}
		})
	}
}

func TestIDJAGToleratesMissingIssuedTokenTypeAndDiscardsRefreshToken(t *testing.T) {
	h := newHarness(t)
	h.idp.issuedTokenType = "omit"
	h.idp.idJagRefreshTok = "should-be-ignored-0123456789"
	pol := h.policy(nil)
	req := request(map[string]string{"X-ID-Token": userIDToken(time.Now().Add(time.Hour))}, true)
	mustUpstream(t, pol.OnRequestHeaders(context.Background(), req, nil))
}

// ─── Tests: scopes ────────────────────────────────────────────────────────────

func TestResourceAsScopesMustBeSubsetOfIDJAGScope(t *testing.T) {
	h := newHarness(t)
	h.idp.idJagScope = "read:work"
	pol := h.policy(map[string]any{"resourceAsScopes": "read:work write:work"})
	req := request(map[string]string{"X-ID-Token": userIDToken(time.Now().Add(time.Hour))}, true)
	mustImmediate(t, pol.OnRequestHeaders(context.Background(), req, nil), http.StatusBadGateway)
	if len(h.ras.received()) != 0 {
		t.Fatalf("Resource AS must not be asked for scopes outside the ID-JAG")
	}
}

func TestResourceAsScopesSubsetIsForwarded(t *testing.T) {
	h := newHarness(t)
	h.idp.idJagScope = "read:work write:work"
	pol := h.policy(map[string]any{"resourceAsScopes": "read:work"})
	req := request(map[string]string{"X-ID-Token": userIDToken(time.Now().Add(time.Hour))}, true)
	mustUpstream(t, pol.OnRequestHeaders(context.Background(), req, nil))
	if got := h.ras.received()[0].Get("scope"); got != "read:work" {
		t.Fatalf("step 2 scope = %q", got)
	}
}

func TestResourceAsScopesForwardedWhenIDJAGHasNoScope(t *testing.T) {
	h := newHarness(t)
	pol := h.policy(map[string]any{"resourceAsScopes": "read:work"})
	req := request(map[string]string{"X-ID-Token": userIDToken(time.Now().Add(time.Hour))}, true)
	mustUpstream(t, pol.OnRequestHeaders(context.Background(), req, nil))
	if got := h.ras.received()[0].Get("scope"); got != "read:work" {
		t.Fatalf("step 2 scope = %q", got)
	}
}

// ─── Tests: caching ───────────────────────────────────────────────────────────

func TestCacheOff_EveryRequestExchanges(t *testing.T) {
	h := newHarness(t)
	pol := h.policy(nil)
	idTok := userIDToken(time.Now().Add(time.Hour))
	for i := 0; i < 3; i++ {
		req := request(map[string]string{"X-ID-Token": idTok}, true)
		mods := mustUpstream(t, pol.OnRequestHeaders(context.Background(), req, nil))
		if mods.AnalyticsMetadata["id-jag.cache"] != "disabled" {
			t.Fatalf("cache state = %v", mods.AnalyticsMetadata["id-jag.cache"])
		}
		if _, stashed := req.SharedContext.Metadata[MetadataKeyCacheKey]; stashed {
			t.Fatalf("no cache key should be stashed when caching is off")
		}
	}
	if n := len(h.ras.received()); n != 3 {
		t.Fatalf("expected 3 exchanges, saw %d", n)
	}
	if pol.cache.len() != 0 {
		t.Fatalf("cache must stay empty when caching is off")
	}
	if pol.Mode().ResponseHeaderMode != policy.HeaderModeSkip {
		t.Fatalf("response headers need no processing when caching is off")
	}
}

func TestCacheOn_HitThenPurgeOnUpstream401(t *testing.T) {
	h := newHarness(t)
	pol := h.policy(map[string]any{"cacheResourceAccessToken": true})
	if pol.Mode().ResponseHeaderMode != policy.HeaderModeProcess {
		t.Fatalf("response headers must be processed for purging when caching is on")
	}
	idTok := userIDToken(time.Now().Add(time.Hour))

	first := request(map[string]string{"X-ID-Token": idTok}, true)
	m1 := mustUpstream(t, pol.OnRequestHeaders(context.Background(), first, nil))
	second := request(map[string]string{"X-ID-Token": idTok}, true)
	m2 := mustUpstream(t, pol.OnRequestHeaders(context.Background(), second, nil))
	if m1.AnalyticsMetadata["id-jag.cache"] != "miss" || m2.AnalyticsMetadata["id-jag.cache"] != "hit" {
		t.Fatalf("cache states = %v / %v", m1.AnalyticsMetadata["id-jag.cache"], m2.AnalyticsMetadata["id-jag.cache"])
	}
	if n := len(h.ras.received()); n != 1 {
		t.Fatalf("expected one exchange across two requests, saw %d", n)
	}

	// Upstream rejects the token on the second request: purge, then the third re-exchanges.
	pol.OnResponseHeaders(context.Background(), &policy.ResponseHeaderContext{SharedContext: second.SharedContext, ResponseStatus: 401}, nil)
	third := request(map[string]string{"X-ID-Token": idTok}, true)
	m3 := mustUpstream(t, pol.OnRequestHeaders(context.Background(), third, nil))
	if m3.AnalyticsMetadata["id-jag.cache"] != "miss" || len(h.ras.received()) != 2 {
		t.Fatalf("expected a re-exchange after purge; state=%v calls=%d", m3.AnalyticsMetadata["id-jag.cache"], len(h.ras.received()))
	}

	// A 200 must not purge.
	pol.OnResponseHeaders(context.Background(), &policy.ResponseHeaderContext{SharedContext: third.SharedContext, ResponseStatus: 200}, nil)
	if pol.cache.len() != 1 {
		t.Fatalf("200 must leave the entry in place")
	}
}

func TestCacheOn_TTLBoundedByInboundAssertionExpiry(t *testing.T) {
	h := newHarness(t)
	pol := h.policy(map[string]any{"cacheResourceAccessToken": true, "expiryBuffer": "0s"})
	soon := time.Now().Add(30 * time.Second)
	req := request(map[string]string{"X-ID-Token": userIDToken(soon)}, true)
	mustUpstream(t, pol.OnRequestHeaders(context.Background(), req, nil))
	key := req.SharedContext.Metadata[MetadataKeyCacheKey].(string)
	tok, ok := pol.cache.get(key, 0)
	if !ok {
		t.Fatalf("expected a cached entry")
	}
	if tok.Expiry.After(soon.Add(time.Second)) {
		t.Fatalf("cache expiry %v must not outlive the ID token's exp %v", tok.Expiry, soon)
	}
}

func TestCacheIsPerAssertion(t *testing.T) {
	h := newHarness(t)
	pol := h.policy(map[string]any{"cacheResourceAccessToken": true})
	a := request(map[string]string{"X-ID-Token": userIDToken(time.Now().Add(time.Hour))}, true)
	b := request(map[string]string{"X-ID-Token": userIDToken(time.Now().Add(2 * time.Hour))}, true)
	mustUpstream(t, pol.OnRequestHeaders(context.Background(), a, nil))
	mustUpstream(t, pol.OnRequestHeaders(context.Background(), b, nil))
	if len(h.ras.received()) != 2 || pol.cache.len() != 2 {
		t.Fatalf("different assertions must not share a cache entry")
	}
}

func TestConcurrentRequestsAreSingleFlighted(t *testing.T) {
	h := newHarness(t)
	pol := h.policy(nil)
	idTok := userIDToken(time.Now().Add(time.Hour))
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			mustUpstream(t, pol.OnRequestHeaders(context.Background(), request(map[string]string{"X-ID-Token": idTok}, true), nil))
		}()
	}
	wg.Wait()
	if n := len(h.ras.received()); n > 3 {
		// Exactly 1 is not guaranteed (a goroutine may start after the leader finished), but a
		// burst must collapse to far fewer exchanges than requests.
		t.Fatalf("expected the burst to be single-flighted, saw %d exchanges", n)
	}
}

// ─── Tests: configuration ─────────────────────────────────────────────────────

func TestCredentialRefResolution(t *testing.T) {
	h := newHarness(t)
	cases := map[string]map[string]any{
		"unknown ref":   {"credentialRef": "nope"},
		"missing ref":   {"credentialRef": ""},
		"no sets":       {"credentials": nil},
		"wrong shape":   {"credentials": "not-a-list"},
		"empty secret":  {"credentials": []any{map[string]any{"name": testCredential, "idpClientId": "a", "idpClientSecret": "", "resourceAsClientId": "a", "resourceAsClientSecret": "b"}}},
		"entry no name": {"credentials": []any{map[string]any{"idpClientId": "a"}}},
	}
	for name, overrides := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := GetPolicy(policy.PolicyMetadata{}, h.params(overrides)); err == nil {
				t.Fatalf("expected an error")
			} else if strings.Contains(err.Error(), "idp-secret") || strings.Contains(err.Error(), "ras-secret") {
				t.Fatalf("error must not leak a secret: %v", err)
			}
		})
	}
}

func TestSecretsAreNotUIParameters(t *testing.T) {
	h := newHarness(t)
	// Secrets passed as ordinary params are ignored - only the credential set counts.
	pol := h.policy(map[string]any{"idpClientSecret": "ui-secret", "resourceAsClientSecret": "ui-secret"})
	req := request(map[string]string{"X-ID-Token": userIDToken(time.Now().Add(time.Hour))}, true)
	mustUpstream(t, pol.OnRequestHeaders(context.Background(), req, nil))
	_, step1 := h.idp.calls()
	if step1[0].Get("client_secret") != "idp-secret" || h.ras.received()[0].Get("client_secret") != "ras-secret" {
		t.Fatalf("secrets must come from the credential set")
	}
}

func TestInvalidParams(t *testing.T) {
	h := newHarness(t)
	cases := map[string]map[string]any{
		"bad assertionType":     {"assertionType": "saml2"},
		"missing assertionType": {"assertionType": ""},
		"missing audience":      {"audience": ""},
		"missing idp endpoint":  {"idpTokenEndpoint": ""},
		"missing ras endpoint":  {"resourceAsTokenEndpoint": ""},
		"bad auth method":       {"idpClientAuthMethod": "private_key_jwt"},
		"bad exchange subject":  {"exchangeSubjectTokenType": "id_token"},
	}
	for name, overrides := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := GetPolicy(policy.PolicyMetadata{}, h.params(overrides)); err == nil {
				t.Fatalf("expected an error")
			}
		})
	}
}

func TestClientSecretBasic(t *testing.T) {
	h := newHarness(t)
	var sawBasic bool
	h.idp.srv.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if u, p, ok := r.BasicAuth(); ok && u == testIdPClient && p == "idp-secret" {
			sawBasic = true
		}
		_ = r.ParseForm()
		if r.PostForm.Get("client_secret") != "" {
			t.Errorf("client_secret must not be in the form with client_secret_basic")
		}
		h.idp.token(w, r)
	})
	pol := h.policy(map[string]any{"idpClientAuthMethod": ClientAuthMethodBasic})
	req := request(map[string]string{"X-ID-Token": userIDToken(time.Now().Add(time.Hour))}, true)
	mustUpstream(t, pol.OnRequestHeaders(context.Background(), req, nil))
	if !sawBasic {
		t.Fatalf("expected HTTP Basic client authentication")
	}
}

func TestHeaderNameAndPrefix(t *testing.T) {
	h := newHarness(t)
	pol := h.policy(map[string]any{"headerName": "X-Upstream-Token", "valuePrefix": ""})
	req := request(map[string]string{"X-ID-Token": userIDToken(time.Now().Add(time.Hour))}, true)
	mods := mustUpstream(t, pol.OnRequestHeaders(context.Background(), req, nil))
	if mods.HeadersToSet["X-Upstream-Token"] != h.ras.accessToken {
		t.Fatalf("headers = %v", mods.HeadersToSet)
	}
}
