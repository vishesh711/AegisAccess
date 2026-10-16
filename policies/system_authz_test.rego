package system.authz_test

import data.system.authz

rt := {"env": {"AEGIS_OPA_TOKEN": "test-token-0123456789abcdef"}}

good := "test-token-0123456789abcdef"

test_health_open if authz.allow with input as {"method": "GET", "path": ["health"]} with opa.runtime as rt

test_pep_can_query_decision if {
	authz.allow with input as {"method": "POST", "path": ["v1", "data", "aegis", "authz", "allow"], "identity": good}
		with opa.runtime as rt
}

test_decision_needs_token if {
	not authz.allow with input as {"method": "POST", "path": ["v1", "data", "aegis", "authz", "allow"]}
		with opa.runtime as rt
	not authz.allow with input as {"method": "POST", "path": ["v1", "data", "aegis", "authz", "allow"], "identity": "wrong"}
		with opa.runtime as rt
}

test_cannot_replace_policy if {
	not authz.allow with input as {"method": "PUT", "path": ["v1", "policies", "authz"], "identity": good}
		with opa.runtime as rt
	not authz.allow with input as {"method": "PUT", "path": ["v1", "data", "aegis"], "identity": good}
		with opa.runtime as rt
	not authz.allow with input as {"method": "DELETE", "path": ["v1", "policies", "authz"], "identity": good}
		with opa.runtime as rt
}

test_cannot_read_raw_data if {
	not authz.allow with input as {"method": "GET", "path": ["v1", "data", "aegis", "roles"], "identity": good}
		with opa.runtime as rt
	not authz.allow with input as {"method": "POST", "path": ["v1", "data", "aegis", "roles"], "identity": good}
		with opa.runtime as rt
}

test_unset_token_denies_everything_but_health if {
	not authz.allow with input as {"method": "POST", "path": ["v1", "data", "aegis", "authz", "allow"], "identity": ""}
		with opa.runtime as {"env": {}}
}
