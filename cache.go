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
	"crypto/sha256"
	"encoding/hex"
	"sync"
	"time"
)

// maxSweepPerPut bounds how many map entries a single put examines while
// opportunistically dropping expired ones. Go map iteration starts at a random
// position, so repeated puts sample different regions.
const maxSweepPerPut = 64

// exchangedToken is the outcome of a full exchange: the Resource AS access
// token and the scope the Resource AS granted. Only this token is ever cached - the ID-JAG
// and any refresh token used to obtain it are dropped as soon as they have
// served their purpose.
type exchangedToken struct {
	Token
	grantedScope string
}

// tokenCache maps sha256(inbound assertion) -> Resource AS access token. It is
// used only when cacheResourceAccessToken is on. Per-assertion keying is
// deliberate: the same user presenting a rotated assertion gets a fresh
// exchange, since consent or authorization state may have changed.
// In-memory only - a gateway restart just re-exchanges.
type tokenCache struct {
	mu sync.Mutex
	m  map[string]*exchangedToken
}

func newTokenCache() *tokenCache {
	return &tokenCache{m: make(map[string]*exchangedToken)}
}

// get returns the cached token for key, treating an entry within buffer of its
// expiry as a miss so a request never goes upstream with a credential expiring
// mid-flight.
func (c *tokenCache) get(key string, buffer time.Duration) (*exchangedToken, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	tok, ok := c.m[key]
	if !ok || !tokenFreshEnough(&tok.Token, buffer) {
		return nil, false
	}
	return tok, true
}

// put stores tok under key, first dropping a bounded sample of expired entries,
// then evicting the earliest-expiring entry if the cache is at max.
func (c *tokenCache) put(key string, tok *exchangedToken, max int) {
	c.mu.Lock()
	defer c.mu.Unlock()

	examined := 0
	now := time.Now()
	for k, v := range c.m {
		if examined >= maxSweepPerPut {
			break
		}
		examined++
		if !v.Expiry.IsZero() && !v.Expiry.After(now) {
			delete(c.m, k)
		}
	}

	if _, exists := c.m[key]; !exists {
		for len(c.m) >= max {
			c.evictEarliestLocked()
		}
	}
	c.m[key] = tok
}

// evictEarliestLocked removes the entry with the earliest expiry. Caller holds mu.
func (c *tokenCache) evictEarliestLocked() {
	var earliestKey string
	var earliest time.Time
	first := true
	for k, v := range c.m {
		if first || v.Expiry.Before(earliest) {
			earliestKey, earliest, first = k, v.Expiry, false
		}
	}
	if !first {
		delete(c.m, earliestKey)
	}
}

func (c *tokenCache) delete(key string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	delete(c.m, key)
}

func (c *tokenCache) len() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.m)
}

// tokenFreshEnough reports whether tok is present and far enough from its own
// expiry to still be trusted. A zero Expiry is treated as "never expires".
func tokenFreshEnough(tok *Token, buffer time.Duration) bool {
	if tok == nil || tok.AccessToken == "" {
		return false
	}
	if tok.Expiry.IsZero() {
		return true
	}
	return tok.Expiry.Add(-buffer).After(time.Now())
}

// sha256hex is the cache / single-flight key for an assertion: the token itself
// never appears as a map key, in logs (only the first 8 hex chars are logged),
// or in metadata.
func sha256hex(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}

// ─── Single-flight ────────────────────────────────────────────────────────────

// flightGroup single-flights the exchange per key: N concurrent requests
// carrying the same assertion make one token-endpoint call sequence and share
// its result. MCP clients fire initialize and tools/list back-to-back on first
// connect, so this matters even when caching is off.
type flightGroup struct {
	mu    sync.Mutex
	calls map[string]*flightCall
}

type flightCall struct {
	wg  sync.WaitGroup
	tok *exchangedToken
	err error
}

func newFlightGroup() *flightGroup {
	return &flightGroup{calls: make(map[string]*flightCall)}
}

// Do runs fn once per key at a time; callers that arrive while a call for the
// same key is in flight wait for and share its result. The shared fn runs on
// the leader's context.
func (g *flightGroup) Do(key string, fn func() (*exchangedToken, error)) (*exchangedToken, error) {
	g.mu.Lock()
	if c, ok := g.calls[key]; ok {
		g.mu.Unlock()
		c.wg.Wait()
		return c.tok, c.err
	}
	c := &flightCall{}
	c.wg.Add(1)
	g.calls[key] = c
	g.mu.Unlock()

	c.tok, c.err = fn()

	g.mu.Lock()
	delete(g.calls, key)
	g.mu.Unlock()
	c.wg.Done()

	return c.tok, c.err
}
