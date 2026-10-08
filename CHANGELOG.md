# Changelog

## v0.2.0

Renamed to `mcp-auth-id-jag` and reworked to follow the ID-JAG profile. This
is the version deployed and exercised on the PoC gateway.

- **Compliant assertions.** The identity assertion is an OpenID Connect ID
  token (`assertionType: id_token`, read from a configurable inbound header)
  or a refresh token (`assertionType: refresh_token`). In the refresh token
  flow the policy first exchanges the inbound access token at the IdP, as its
  own client, for an access token plus refresh token, and presents that
  refresh token; a response without one is a 502. The previous version sent
  the inbound access token as the subject, which the profile does not allow.
- **ID-JAG checked before use:** `issued_token_type`, `typ oauth-id-jag+jwt`,
  a single `aud` equal to the configured audience, unexpired `exp`;
  `resourceAsScopes` must sit within the ID-JAG's scope.
- **Optional revocation** (`idpRevocationEndpoint`) of the refresh token after
  the ID-JAG is issued.
- **Client credentials moved out of the UI.** Secrets are no longer policy
  parameters. Named credential sets are declared in the gateway's
  `config.toml`, read from the environment, and selected per policy instance
  with `credentialRef`, so one gateway fronts any number of Resource ASes.
- **Nothing stored except, optionally, the Resource AS access token.** The
  ID-JAG and the refresh token are never cached. The access-token cache is now
  opt-in (`cacheResourceAccessToken`, default off).
- **Runs behind MCP Authentication only.** The `requireAuthContext` switch,
  the `resource_metadata` challenge and `challengeResourceMetadata`, and the
  auth-context rewriting (`userIdClaim`) are gone. The policy defers its
  exchange to the request body phase when MCP Authentication validates there
  (POST /mcp) and handles transport requests in the header phase.
- Vendor names removed from code, schema and parameters.
- Unit suite added (`id_jag_test.go`) against fake IdP and Resource AS servers.

Removed parameters: `idpClientId`, `idpClientSecret`, `resourceAsClientId`,
`resourceAsClientSecret`, `subjectTokenType`, `assertionHeader`,
`requireAuthContext`, `challengeResourceMetadata`, `userIdClaim`.
Added: `assertionType`, `idTokenHeader`, `accessTokenHeader`, `credentialRef`,
`exchangeSubjectTokenType`, `exchangeScopes`, `idpRevocationEndpoint`,
`cacheResourceAccessToken`.

## v0.1.0

Initial release as `gateway-id-jag`: two-step ID-JAG exchange with the inbound
access token as the subject, per-token cache, single-flight, bounded retry,
401/502 error classification with an RFC 9728 `resource_metadata` pointer,
response-phase cache purge, shared proxy/TLS transport registry.
