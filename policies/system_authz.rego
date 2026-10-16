# OPA server API authorization (opa run --authentication=token --authorization=basic).
# Only the PEP (holding AEGIS_OPA_TOKEN) may query decisions; nobody may PUT/DELETE policies
# or data over the REST API. Health is open so container health checks work.
package system.authz

default allow := false

pep_token := opa.runtime().env.AEGIS_OPA_TOKEN

authenticated if {
	is_string(pep_token)
	count(pep_token) >= 16
	input.identity == pep_token
}

decision_path if {
	count(input.path) >= 4
	input.path[0] == "v1"
	input.path[1] == "data"
	input.path[2] == "aegis"
	input.path[3] == "authz"
}

allow if {
	input.method == "GET"
	input.path == ["health"]
}

allow if {
	authenticated
	input.method == "POST"
	decision_path
}

allow if {
	authenticated
	input.method == "GET"
	input.path == ["v1", "data", "aegis", "authz", "policy_version"]
}
