# AegisAccess authorization policy (PDP). Default deny.
#
# ALLOWED = valid input AND active subject AND same tenant AND subject grant
#           AND (for agent calls: active same-tenant agent AND agent grant AND valid delegation
#                AND task grants action AND task lists the document)
#           AND no contextual deny.
# Contextual rules can only remove access, never add it.
package aegis.authz

default allow := false

policy_version := data.aegis.policy_version

known_actions := {a | some a in data.aegis.actions}

principal_types := {"human", "workload", "agent"}

resource_kinds := {"document", "report", "audit_log", "policy"}

classifications := {"public", "internal", "confidential", "restricted"}

origin := input.context.request_origin

agent := object.get(input, "agent", null)

delegation := object.get(input, "delegation", null)

# ---------------------------------------------------------------- input validation

non_empty_string(x) if {
	is_string(x)
	x != ""
}

valid_principal(p) if {
	non_empty_string(p.id)
	non_empty_string(p.tenant_id)
	p.type in principal_types
	is_array(p.roles)
	is_boolean(p.active)
}

valid_resource(r) if {
	non_empty_string(r.id)
	non_empty_string(r.tenant_id)
	r.kind in resource_kinds
	r.classification in classifications
	non_empty_string(r.department)
}

valid_delegation(d) if {
	non_empty_string(d.task_id)
	is_boolean(d.valid)
	non_empty_string(d.user_id)
	non_empty_string(d.agent_id)
	is_array(d.actions)
	is_array(d.resource_ids)
}

origin_shape_ok if {
	origin == "api"
	agent == null
	delegation == null
}

origin_shape_ok if {
	origin == "mcp"
	valid_principal(agent)
	valid_delegation(delegation)
}

input_valid if {
	input.policy_version == policy_version
	input.action in known_actions
	valid_principal(input.subject)
	valid_resource(input.resource)
	non_empty_string(input.context.environment)
	origin_shape_ok
}

# ---------------------------------------------------------------- grants

# A role only confers grants on the principal types it is defined for, so a mis-assigned
# agent role on a human (or vice versa) grants nothing.
grants_for(p) := [g |
	some role in p.roles
	def := data.aegis.roles[role]
	p.type in def.principal_types
	some g in def.grants
]

department_ok(g, _) if g.departments == ["*"]

department_ok(g, r) if r.department in g.departments

permits(p, action, r) if {
	some g in grants_for(p)
	g.action == action
	r.kind in g.kinds
	r.classification in g.classifications
	department_ok(g, r)
}

# ---------------------------------------------------------------- building blocks

subject_active if input.subject.active == true

same_tenant if input.subject.tenant_id == input.resource.tenant_id

subject_permitted if permits(input.subject, input.action, input.resource)

agent_identity_ok if {
	agent.type == "agent"
	agent.active == true
	agent.tenant_id == input.subject.tenant_id
	agent.tenant_id == input.resource.tenant_id
	input.subject.type == "human"
}

agent_permitted if permits(agent, input.action, input.resource)

delegation_bound if {
	delegation.valid == true
	delegation.agent_id == agent.id
	delegation.user_id == input.subject.id
}

task_resource_ok if input.resource.kind != "document"

task_resource_ok if {
	input.resource.kind == "document"
	input.resource.id in delegation.resource_ids
}

task_permits if {
	input.action in delegation.actions
	task_resource_ok
}

agent_path_ok if {
	origin == "api"
}

agent_path_ok if {
	origin == "mcp"
	agent_identity_ok
	agent_permitted
	delegation_bound
	task_permits
}

# ---------------------------------------------------------------- contextual restrictions (deny-only)

contextual_deny contains "RESTRICTED_VIA_AGENT" if {
	origin == "mcp"
	input.resource.classification == "restricted"
}

contextual_deny contains "ENVIRONMENT_NOT_ALLOWED" if {
	not input.context.environment in {e | some e in data.aegis.allowed_environments}
}

# ---------------------------------------------------------------- decision

allow if {
	input_valid
	subject_active
	same_tenant
	subject_permitted
	agent_path_ok
	count(contextual_deny) == 0
}

# Explanations for audit (never consulted to grant access).
deny_reasons contains "INVALID_INPUT" if not input_valid

deny_reasons contains "POLICY_VERSION_MISMATCH" if input.policy_version != policy_version

deny_reasons contains "UNKNOWN_ACTION" if not input.action in known_actions

deny_reasons contains "SUBJECT_INACTIVE" if not subject_active

deny_reasons contains "TENANT_MISMATCH" if not same_tenant

deny_reasons contains "SUBJECT_NOT_GRANTED" if not subject_permitted

deny_reasons contains "AGENT_IDENTITY_INVALID" if {
	origin == "mcp"
	not agent_identity_ok
}

deny_reasons contains "AGENT_NOT_GRANTED" if {
	origin == "mcp"
	not agent_permitted
}

deny_reasons contains "DELEGATION_INVALID" if {
	origin == "mcp"
	not delegation_bound
}

deny_reasons contains "TASK_SCOPE_EXCEEDED" if {
	origin == "mcp"
	not task_permits
}

deny_reasons contains r if some r in contextual_deny
