# OPA server API authorization (opa run --authorization=basic).
# Only the policy enforcement points may query decisions; nobody may PUT/DELETE policies or data over
# the REST API. Health is open so container health checks work.
#
# Two authentication modes, chosen explicitly by AEGIS_OPA_AUTH_MODE (anything else authenticates
# nobody):
#   token (default, local demo): --authentication=token; input.identity is the bearer token, which
#         must equal AEGIS_OPA_TOKEN.
#   tls   (hardened profile):    --authentication=tls; input.identity is the verified client
#         certificate subject, which must equal AEGIS_OPA_PEP_IDENTITY.
# The mode is never inferred from the request, so in token mode a bearer token that LOOKS like a
# certificate subject is just a wrong token.
package system.authz

default allow := false

env := opa.runtime().env

auth_mode := object.get(env, "AEGIS_OPA_AUTH_MODE", "token")

authenticated if {
	auth_mode == "token"
	pep_token := env.AEGIS_OPA_TOKEN
	is_string(pep_token)
	count(pep_token) >= 16
	input.identity == pep_token
}

authenticated if {
	auth_mode == "tls"
	pep_identity := env.AEGIS_OPA_PEP_IDENTITY
	is_string(pep_identity)
	startswith(pep_identity, "CN=")
	input.identity == pep_identity
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
