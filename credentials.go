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
	"fmt"
	"sort"
	"strings"
)

// credentialsParam is the system parameter (never a UI parameter) that carries
// the named credential sets. It resolves from
// policy_configurations.mcp_auth_id_jag_v0.credentials in config.toml, whose
// secret-bearing keys in turn read the environment.
const credentialsParam = "credentials"

// credentialSet pairs the gateway's confidential client at the IdP with its
// confidential client at one Resource AS. A policy instance picks a set by
// name through credentialRef, so the per-API configuration never carries a
// secret and one gateway can front any number of Resource ASes.
type credentialSet struct {
	name                   string
	idpClientID            string
	idpClientSecret        string
	resourceAsClientID     string
	resourceAsClientSecret string
}

// resolveCredentialSet finds the set named ref among the configured sets.
// Every failure names what is missing precisely, since this is the first thing
// an operator wiring a new MCP server hits, and the message never includes a
// secret value.
func resolveCredentialSet(params map[string]interface{}, ref string) (credentialSet, error) {
	raw, ok := params[credentialsParam]
	if !ok || raw == nil {
		return credentialSet{}, fmt.Errorf("no credential sets are configured: [[policy_configurations.mcp_auth_id_jag_v0.credentials]] is missing from the gateway config.toml")
	}
	list, ok := raw.([]interface{})
	if !ok {
		return credentialSet{}, fmt.Errorf("policy_configurations.mcp_auth_id_jag_v0.credentials must be an array of tables, got %T", raw)
	}

	var names []string
	for i, item := range list {
		entry := asStringMap(item)
		if entry == nil {
			return credentialSet{}, fmt.Errorf("credentials[%d] must be a table, got %T", i, item)
		}
		name := strings.TrimSpace(entry["name"])
		if name == "" {
			return credentialSet{}, fmt.Errorf("credentials[%d] has no name", i)
		}
		names = append(names, name)
		if name != ref {
			continue
		}

		cs := credentialSet{
			name:                   name,
			idpClientID:            strings.TrimSpace(entry["idpClientId"]),
			idpClientSecret:        strings.TrimSpace(entry["idpClientSecret"]),
			resourceAsClientID:     strings.TrimSpace(entry["resourceAsClientId"]),
			resourceAsClientSecret: strings.TrimSpace(entry["resourceAsClientSecret"]),
		}
		for field, value := range map[string]string{
			"idpClientId":            cs.idpClientID,
			"idpClientSecret":        cs.idpClientSecret,
			"resourceAsClientId":     cs.resourceAsClientID,
			"resourceAsClientSecret": cs.resourceAsClientSecret,
		} {
			if value == "" {
				return credentialSet{}, fmt.Errorf("credential set %q: %s is empty - check the environment variable it reads in config.toml", name, field)
			}
		}
		return cs, nil
	}

	sort.Strings(names)
	return credentialSet{}, fmt.Errorf("credentialRef %q does not match any configured credential set (configured: %s)", ref, strings.Join(names, ", "))
}

// asStringMap flattens a decoded TOML/JSON table into string values, tolerating
// the two map shapes the kernel may hand over. Non-string values are dropped.
func asStringMap(v interface{}) map[string]string {
	switch m := v.(type) {
	case map[string]interface{}:
		out := make(map[string]string, len(m))
		for k, val := range m {
			if s, ok := val.(string); ok {
				out[k] = s
			}
		}
		return out
	case map[string]string:
		return m
	}
	return nil
}
