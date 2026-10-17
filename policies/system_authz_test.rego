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

# ------------------------------------------------------------- mutual TLS mode (hardened profile)
tls_rt := {"env": {"AEGIS_OPA_AUTH_MODE": "tls", "AEGIS_OPA_PEP_IDENTITY": "CN=aegis-pep,O=AegisAccess demo"}}

decision := {"method": "POST", "path": ["v1", "data", "aegis", "authz", "allow"]}

test_tls_mode_accepts_pep_certificate_subject if {
	authz.allow with input as object.union(decision, {"identity": "CN=aegis-pep,O=AegisAccess demo"})
		with opa.runtime as tls_rt
}

test_tls_mode_rejects_other_subjects_and_tokens if {
	not authz.allow with input as object.union(decision, {"identity": "CN=intruder,O=AegisAccess demo"})
		with opa.runtime as tls_rt
	not authz.allow with input as object.union(decision, {"identity": "CN=aegis-pep"})
		with opa.runtime as tls_rt
	not authz.allow with input as object.union(decision, {"identity": good})
		with opa.runtime as object.union(tls_rt, {"env": {"AEGIS_OPA_TOKEN": good}})
}

test_tls_mode_still_cannot_replace_policy if {
	not authz.allow with input as {"method": "PUT", "path": ["v1", "policies", "authz"], "identity": "CN=aegis-pep,O=AegisAccess demo"}
		with opa.runtime as tls_rt
}

test_token_mode_ignores_a_bearer_that_looks_like_a_subject if {
	# token mode with the PEP identity configured too: a bearer "CN=..." string is just a wrong token
	not authz.allow with input as object.union(decision, {"identity": "CN=aegis-pep,O=AegisAccess demo"})
		with opa.runtime as {"env": {"AEGIS_OPA_TOKEN": good, "AEGIS_OPA_PEP_IDENTITY": "CN=aegis-pep,O=AegisAccess demo"}}
}

test_unknown_mode_authenticates_nobody if {
	not authz.allow with input as object.union(decision, {"identity": good})
		with opa.runtime as {"env": {"AEGIS_OPA_AUTH_MODE": "none", "AEGIS_OPA_TOKEN": good}}
	not authz.allow with input as object.union(decision, {"identity": "CN=aegis-pep,O=AegisAccess demo"})
		with opa.runtime as {"env": {"AEGIS_OPA_AUTH_MODE": "TLS", "AEGIS_OPA_PEP_IDENTITY": "CN=aegis-pep,O=AegisAccess demo"}}
}
