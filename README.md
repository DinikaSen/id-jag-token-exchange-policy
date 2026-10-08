# gateway-id-jag — ID-JAG token exchange policy for WSO2 AI Gateway

A custom policy for the [WSO2 API Platform](https://wso2.com/api-platform/) AI
Gateway that exchanges a validated inbound user token for a **per-user upstream
access token** using the two-step **Identity Assertion JWT Authorization Grant**
(ID-JAG, [draft-ietf-oauth-identity-assertion-authz-grant](https://datatracker.ietf.org/doc/draft-ietf-oauth-identity-assertion-authz-grant/)):

1. **RFC 8693 token exchange** at the identity provider (IdP) → an ID-JAG JWT.
2. **JWT-bearer grant** (`urn:ietf:params:oauth:grant-type:jwt-bearer`) at the
   resource authorization server (Resource AS) → an access token.

The final access token replaces the client's credential in the request before
it is forwarded upstream. The client never has to know the upstream exists, and
the upstream never sees the client's gateway token.

Typical use: an MCP proxy on the gateway fronting a third-party MCP server
(Atlassian, Figma, …) whose authorization server trusts your enterprise IdP via
ID-JAG. The user signs in once to the IdP; the gateway obtains a user-scoped
token for the third party on every call, transparently.

Written in Go against `github.com/wso2/api-platform/sdk/core` v0.3.5 and
compiled into the gateway image with the `ap` CLI. Policy version `v0.1.0`.

---

## Flow

Two assertion types are supported. In both, MCP Authentication validates the
client's gateway token first; this policy then runs the exchange toward the
upstream. WSO2 Identity Server and Atlassian are this PoC's instances of the
IdP and Resource AS; any pair that implements ID-JAG works.

### ID token as the assertion (`assertionType: id_token`)

The client sends the user's ID token on a configurable header alongside the
gateway access token.

![ID-JAG flow with an ID token assertion](docs/id-jag-flow-id-token.png)

### Refresh token as the assertion (`assertionType: refresh_token`)

The client sends only the gateway access token. The gateway first exchanges it
for a refresh token bound to its own IdP client, presents that as the
assertion, and revokes it afterwards.

![ID-JAG flow with a refresh token assertion](docs/id-jag-flow-refresh-token.png)

Both diagrams are generated from the Mermaid sources next to them in `docs/`.

## What the policy does

**Request phase** (`OnRequestHeaders`)

| Step | Behaviour |
|---|---|
| Fail closed | If `requireAuthContext` is true (default) and no earlier policy set `AuthContext.Authenticated`, respond 401. The policy never exchanges an unvalidated assertion. |
| Read the assertion | From the **downstream request snapshot** (`assertionHeader`, default `Authorization`), so it works regardless of whether the inbound auth policy stripped or forwarded the header. `Bearer ` is stripped case-insensitively; values shorter than 20 chars or containing whitespace are rejected. |
| Cache lookup | Key = `sha256(assertion)`. A hit within `expiryBuffer` of expiry counts as a miss. |
| Single-flight | N concurrent requests with the same assertion trigger exactly one exchange sequence. MCP clients fire `initialize` and `tools/list` back to back on connect, so this matters. |
| Step 1 | RFC 8693 exchange at `idpTokenEndpoint`. Extra form fields / headers from `idpTokenRequestParams` / `idpTokenRequestHeaders`; core fields are set last and cannot be overridden. |
| Step 2 | JWT-bearer grant at `resourceAsTokenEndpoint` with the ID-JAG as `assertion`. |
| Retry | Each step independently: up to `tokenRequestMaxRetries` retries on network errors, 429 and 5xx, with jittered exponential backoff (100 ms base, 2 s cap). Malformed responses and 4xx rejections are not retried. |
| Cache TTL | `min(step-2 expires_in, inbound JWT exp)`; `defaultTokenTTL` when `expires_in` is absent. At most `cacheMaxEntries` entries; the earliest-expiring entry is evicted first. In-memory only. |
| Inject | Sets `headerName` to `valuePrefix + " " + access_token`; removes `assertionHeader` when it differs from `headerName`. |
| AuthContext | Replaces the shared `AuthContext` with one derived from the **final** token's claims (`sub` via `userIdClaim`, `iss`, `aud`, `scp`/`scope`), with the inbound policy's context chained in `Previous`. `AuthType` is `oauth2-id-jag`. |
| Analytics | Emits `id-jag.cache: hit|miss` as analytics metadata. |

**Error classification**

| Condition | Response | Rationale |
|---|---|---|
| Step 1 returns `invalid_grant` or `interaction_required` | **401** `Bearer error="invalid_token"` with `resource_metadata` pointer | A fresh sign-in by the user fixes it; MCP clients restart discovery. |
| Step 1 returns `invalid_client` or any other error | **502** | Gateway misconfiguration; re-auth would loop. |
| Step 2 returns any token error | **502** | Trust/config problem between IdP and Resource AS; the user cannot fix it. |
| Network / transient failure after retries | **502** | |

The `resource_metadata` pointer in 401s comes from `challengeResourceMetadata`
if set, otherwise from the `mcpauth.prmPointer` key that WSO2's MCP auth
policies place in shared request metadata. With neither, the challenge carries
no pointer.

**Response phase** (`OnResponseHeaders`)

If the upstream status is in `tokenPurgeStatusCodes` (default `[401]`), only
the requesting assertion's cache entry is purged. Other users' entries survive.
Set the list to `[]` to disable purging; the response-header hook is then
skipped entirely.

Bodies are never buffered in either direction, so `/mcp` SSE streams pass
through untouched.

## Prerequisites

- A WSO2 API Platform gateway distribution (1.2.x line) and the `ap` CLI, since
  policies are compiled into the gateway image.
- An **inbound authentication policy** ahead of this one that validates the
  client's bearer token and sets `AuthContext.Authenticated` (for example the
  shipped `mcp-auth` or `jwt-auth`, or a fork of them).
- An **IdP** that implements RFC 8693 with
  `requested_token_type=urn:ietf:params:oauth:token-type:id-jag`. WSO2 Identity
  Server does this with the ID-JAG token-exchange grant connector; WSO2 Thunder
  supports it natively.
- A **Resource AS** that accepts the IdP's ID-JAG via the JWT-bearer grant and
  has the gateway registered as a confidential client.
- A confidential client registration for the gateway at **both** the IdP and
  the Resource AS.

## Building it into a gateway image

1. Copy this repository into the gateway distribution as
   `./policies/gateway-id-jag` (a git submodule works well).
2. Add a `filePath` entry to `build.yaml` — see [`examples/build.yaml`](examples/build.yaml).
   `filePath` is relative to `build.yaml`, not to the current directory.
3. Bump `gateway.version` so the previous image remains a rollback target, then:

   ```bash
   ap gateway image build --config build.yaml --name my-gateway
   ```

4. Point **both** `image:` lines in `docker-compose.yaml` (controller and
   runtime) at the new tag and run `docker compose up -d`.
   `restart` is not enough; it reuses the old container.

Things that bite:

- The build reports a **local policy count**. If it says `0`, a `filePath` is
  wrong, and the build still succeeds, producing an image with nothing added.
- The **builder image** decides what the policy engine contains, not
  `gateway.version` and not the base images. Use a builder from the same patch
  line as your runtime/controller bases.
- A deployment that references this policy on a gateway whose image does not
  contain it fails with
  `policy 'gateway-id-jag' major version 'v0' not found in loaded policy definitions`.

## Attaching it to an API

See [`examples/policy-attachment.yaml`](examples/policy-attachment.yaml) for a
full placeholder example. The essentials:

```yaml
globalPolicies:
  - name: mcp-auth            # 1. validate the inbound token first
    version: v1
    params: { ... }
  - name: gateway-id-jag      # 2. then exchange it
    version: v0
    params:
      idpTokenEndpoint: https://idp.example.com/oauth2/token
      idpClientId: <client id at IdP>
      idpClientSecret: <stored secret reference>
      audience: https://auth.resource.example.com
      subjectTokenType: id_token
      resourceAsTokenEndpoint: https://auth.resource.example.com/oauth/token
      resourceAsClientId: <client id at Resource AS>
      resourceAsClientSecret: <stored secret reference>
```

Reference stored secrets for `idpClientSecret`, `resourceAsClientSecret` and
`tlsCaCert`. Never put literal secrets in an API artifact.

## Parameters

Required parameters are marked ✱. Everything else is an advanced parameter
with a default.

### Step 1 — identity provider

| Parameter | Type | Default | Description |
|---|---|---|---|
| `idpTokenEndpoint` ✱ | string | | IdP token endpoint for the RFC 8693 exchange. |
| `idpClientId` ✱ | string | | Gateway's client ID at the IdP. |
| `idpClientSecret` ✱ | string | | Paired secret. Reference a stored secret. |
| `idpClientAuthMethod` | `client_secret_basic` \| `client_secret_post` | `client_secret_post` | How client credentials are sent. |
| `audience` ✱ | string | | Resource AS identifier sent as `audience`. |
| `subjectTokenType` | `access_token` \| `id_token` | `access_token` | Mapped to the full `urn:ietf:params:oauth:token-type:*` URN. |
| `idpScopes` | string | `""` | Space-separated `scope`; omitted when empty. |
| `idpResource` | string | `""` | `resource` parameter; omitted when empty. |
| `idpTokenRequestParams` | map | | Extra form fields. Cannot override the core fields. |
| `idpTokenRequestHeaders` | map | | Extra headers. `Authorization` and `Content-Type` are ignored. |

### Step 2 — resource authorization server

| Parameter | Type | Default | Description |
|---|---|---|---|
| `resourceAsTokenEndpoint` ✱ | string | | Resource AS token endpoint for the JWT-bearer grant. |
| `resourceAsClientId` ✱ | string | | Gateway's client ID at the Resource AS. |
| `resourceAsClientSecret` ✱ | string | | Paired secret. Reference a stored secret. |
| `resourceAsClientAuthMethod` | `client_secret_basic` \| `client_secret_post` | `client_secret_post` | How client credentials are sent. |
| `resourceAsScopes` | string | `""` | Space-separated `scope`; omitted when empty. |
| `resourceAsTokenRequestParams` | map | | Extra form fields. Cannot override `grant_type`, `assertion`, `scope`. |
| `resourceAsTokenRequestHeaders` | map | | Extra headers. `Authorization` and `Content-Type` are ignored. |

### Shared

| Parameter | Type | Default | Description |
|---|---|---|---|
| `assertionHeader` | string | `Authorization` | Header in the downstream snapshot the inbound token is read from. |
| `requireAuthContext` | boolean | `true` | Fail closed with 401 when no earlier policy authenticated the request. Disable only for testing. |
| `headerName` | string | `Authorization` | Header the exchanged token is injected into. |
| `valuePrefix` | string | `Bearer` | Prefix for the injected value. Empty string = no prefix. |
| `userIdClaim` | string | `sub` | Claim of the final token copied into `AuthContext.Subject`. |
| `challengeResourceMetadata` | string | `""` | PRM URL for 401 challenges. Falls back to `mcpauth.prmPointer` metadata. |
| `cacheMaxEntries` | integer | `10000` | Upper bound on cached entries. |
| `tokenRequestTimeout` | duration | `10s` | Per token-endpoint call, both steps. |
| `tokenRequestMaxRetries` | integer | `2` | Retries per step on transient failure. `0` disables. |
| `defaultTokenTTL` | duration | `1h` | Used when `expires_in` is absent. |
| `expiryBuffer` | duration | `2m` | Re-exchange this long before expiry. `0` is allowed. |
| `tokenPurgeStatusCodes` | int[] | `[401]` | Upstream statuses that purge the requesting entry. `[]` disables. |
| `proxyURL` | string | `""` | Proxy for token-endpoint calls. Defaults to `HTTP(S)_PROXY` env. |
| `tlsCaCert` | string (PEM) | `""` | CA to trust for token endpoints. Replaces, not extends, the system pool. |
| `tlsInsecureSkipVerify` | boolean | `false` | Disable TLS verification. Non-production only; logged as a warning. |

Durations are Go duration strings (`10s`, `2m`, `1h`).

## Operational notes

- **`subjectTokenType` must match what the IdP accepts.** WSO2 Identity Server's
  ID-JAG grant expects `id_token` (`urn:ietf:params:oauth:token-type:id_token`),
  not `access_token`. Getting this wrong yields a step 1 rejection and a 502.
- **Pick one client authentication method.** WSO2 Identity Server, correctly per
  RFC 6749 §2.3, rejects requests carrying `client_id`/`client_secret` in the
  body **and** an `Authorization: Basic` header. Use `client_secret_basic`
  there. Basic credentials are form-urlencoded before encoding, per RFC 6749
  Appendix B.
- **Reading the issuer.** The inbound auth policy compares the token's `iss`
  against its configured issuer. Always take the issuer from the IdP's
  `/.well-known/openid-configuration` rather than inferring it from the token
  endpoint; providers differ.
- **401 vs 502 is deliberate.** Only failures the *user* can fix by signing in
  again become 401. Everything else is 502 so MCP clients do not loop on sign-in
  when the gateway is misconfigured.
- **Logs never contain tokens.** Cache keys are SHA-256 digests and only the
  first 8 hex characters are logged. Endpoint URLs are reduced to
  scheme+host+path, and any `user:pass@` in error strings is redacted.
- **Cache is per gateway replica and in memory.** A restart simply re-exchanges.
  Rotated inbound tokens get a fresh exchange by design, since consent or
  authorization state may have changed.
- **Transports are shared process-wide** per proxy/TLS configuration, so many
  policy instances with the same settings reuse one connection pool.

## Repository layout

```
.
├── policy-definition.yaml   # name, version, parameter schema (JSON Schema)
├── id_jag.go                # policy entry point, two-step exchange, error mapping
├── id_jag_cache.go          # per-assertion cache + single-flight group
├── token_request.go         # token-endpoint HTTP, retry, transport registry, helpers
├── go.mod / go.sum
├── examples/
│   ├── build.yaml           # how to add the policy to a gateway build
│   └── policy-attachment.yaml
├── docs/id-jag-flow.png
├── CHANGELOG.md
└── LICENSE                  # Apache 2.0
```

The Go module path (`github.com/wso2/gateway-controllers/policies/gateway-id-jag`)
follows the gateway's convention for local `filePath` policies and does not need
to resolve; the gateway builder compiles the directory in place.

## Development

```bash
go vet ./...      # the module pins go 1.26.5; GOTOOLCHAIN=auto fetches it
gofmt -l .
```

There are no unit tests yet. Contributions adding table-driven tests for
`bearerFrom`, `classifyAndRespond`, `tokenCache` and `fetchWithRetry` are
welcome.

## Lineage

Forked from an On-Behalf-Of token exchange policy (`gateway-obo-token`, itself a
fork of the shipped `oauth2-generator`), replacing the single Entra OBO call with
the two ID-JAG steps. The token-endpoint plumbing, retry classification and
transport registry are unchanged from that lineage.

## License

Apache License 2.0. See [LICENSE](LICENSE).
