# Changelog

## v0.1.0

Initial public release of the `gateway-id-jag` policy.

- Two-step Identity Assertion JWT Authorization Grant (ID-JAG) exchange:
  RFC 8693 token exchange at the identity provider, then
  `urn:ietf:params:oauth:grant-type:jwt-bearer` at the resource authorization server.
- Per-inbound-token cache keyed by `sha256(assertion)`, TTL bounded by both
  the upstream token's `expires_in` and the inbound JWT's `exp`.
- Single-flight exchange per cache key.
- Bounded retry with jittered exponential backoff on transient token-endpoint
  failures (network error, 429, 5xx), applied to each step independently.
- Error classification: step 1 `invalid_grant` / `interaction_required` become
  401 with an RFC 9728 `resource_metadata` pointer; everything else is 502.
- Response-phase cache purge when the upstream rejects the exchanged token
  (default: 401).
- Shared proxy / TLS transport registry; log hygiene (endpoint sanitising,
  URL credential redaction, truncated cache key ids).
