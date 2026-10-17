package aegis.authz_test

import data.aegis.authz

alice := {"id": "alice", "type": "human", "tenant_id": "alpha", "roles": ["engineer"], "active": true}

bob := {"id": "bob", "type": "human", "tenant_id": "alpha", "roles": ["finance-analyst"], "active": true}

carol := {"id": "carol", "type": "human", "tenant_id": "beta", "roles": ["engineer"], "active": true}

secadmin := {"id": "secadmin", "type": "human", "tenant_id": "alpha", "roles": ["security-admin"], "active": true}

svc := {"id": "svc-reporter", "type": "workload", "tenant_id": "alpha", "roles": ["workload-reporter"], "active": true}

agent_alpha := {"id": "agent-alpha", "type": "agent", "tenant_id": "alpha", "roles": ["agent-document-assistant"], "active": true}

agent_beta := {"id": "agent-beta", "type": "agent", "tenant_id": "beta", "roles": ["agent-document-assistant"], "active": true}

eng_doc := {"id": "doc-alpha-eng", "tenant_id": "alpha", "kind": "document", "classification": "internal", "department": "engineering"}

eng_notes := {"id": "doc-alpha-eng-notes", "tenant_id": "alpha", "kind": "document", "classification": "internal", "department": "engineering"}

payroll := {"id": "doc-alpha-payroll", "tenant_id": "alpha", "kind": "document", "classification": "restricted", "department": "finance"}

fin_notes := {"id": "doc-alpha-finance-notes", "tenant_id": "alpha", "kind": "document", "classification": "internal", "department": "finance"}

beta_doc := {"id": "doc-beta-eng", "tenant_id": "beta", "kind": "document", "classification": "internal", "department": "engineering"}

report_alpha := {"id": "report:new", "tenant_id": "alpha", "kind": "report", "classification": "internal", "department": "*"}

api_ctx := {"environment": "local", "request_origin": "api"}

mcp_ctx := {"environment": "local", "request_origin": "mcp"}

api_input(subject, action, resource) := {
	"subject": subject, "action": action, "resource": resource,
	"context": api_ctx, "policy_version": "policy-v2",
}

deleg(user, ag, actions, rids) := {
	"task_id": "t-1", "valid": true, "user_id": user.id, "agent_id": ag.id,
	"actions": actions, "resource_ids": rids,
}

mcp_input(subject, ag, d, action, resource) := {
	"subject": subject, "agent": ag, "delegation": d, "action": action, "resource": resource,
	"context": mcp_ctx, "policy_version": "policy-v2",
}

alice_task := deleg(alice, agent_alpha, ["documents:read", "reports:create"], ["doc-alpha-eng", "doc-alpha-eng-notes"])

bob_task := deleg(bob, agent_alpha, ["documents:read", "reports:create"], ["doc-alpha-finance-notes"])

# ------------------------------------------------------------- direct (API) access

test_t01_alice_reads_eng if authz.allow with input as api_input(alice, "documents:read", eng_doc)

test_t02_alice_denied_payroll if {
	not authz.allow with input as api_input(alice, "documents:read", payroll)
	"SUBJECT_NOT_GRANTED" in authz.deny_reasons with input as api_input(alice, "documents:read", payroll)
}

test_t03_alice_denied_cross_tenant if {
	not authz.allow with input as api_input(alice, "documents:read", beta_doc)
	"TENANT_MISMATCH" in authz.deny_reasons with input as api_input(alice, "documents:read", beta_doc)
}

test_bob_reads_payroll if authz.allow with input as api_input(bob, "documents:read", payroll)

test_bob_denied_eng if not authz.allow with input as api_input(bob, "documents:read", eng_doc)

test_carol_reads_beta if authz.allow with input as api_input(carol, "documents:read", beta_doc)

test_workload_reads_eng if authz.allow with input as api_input(svc, "documents:read", eng_doc)

test_workload_denied_payroll if not authz.allow with input as api_input(svc, "documents:read", payroll)

test_inactive_subject_denied if {
	inactive := object.union(alice, {"active": false})
	not authz.allow with input as api_input(inactive, "documents:read", eng_doc)
	"SUBJECT_INACTIVE" in authz.deny_reasons with input as api_input(inactive, "documents:read", eng_doc)
}

test_unknown_action_denied if {
	not authz.allow with input as api_input(alice, "documents:delete", eng_doc)
	"UNKNOWN_ACTION" in authz.deny_reasons with input as api_input(alice, "documents:delete", eng_doc)
}

test_unknown_role_grants_nothing if {
	x := object.union(alice, {"roles": ["superuser", "admin"]})
	not authz.allow with input as api_input(x, "documents:read", eng_doc)
}

test_agent_role_on_human_grants_nothing if {
	x := object.union(alice, {"roles": ["agent-document-assistant"]})
	not authz.allow with input as api_input(x, "documents:read", fin_notes)
}

test_policy_version_mismatch_denied if {
	i := object.union(api_input(alice, "documents:read", eng_doc), {"policy_version": "policy-v0"})
	not authz.allow with input as i
	"POLICY_VERSION_MISMATCH" in authz.deny_reasons with input as i
}

test_missing_fields_denied if {
	not authz.allow with input as {}
	not authz.allow with input as {"subject": alice, "action": "documents:read"}
	not authz.allow with input as object.remove(api_input(alice, "documents:read", eng_doc), ["context"])
	"INVALID_INPUT" in authz.deny_reasons with input as {}
}

test_wrong_types_denied if {
	i := api_input(object.union(alice, {"active": "true"}), "documents:read", eng_doc)
	not authz.allow with input as i
}

test_environment_not_allowed if {
	i := object.union(api_input(alice, "documents:read", eng_doc), {"context": {"environment": "prod", "request_origin": "api"}})
	not authz.allow with input as i
	"ENVIRONMENT_NOT_ALLOWED" in authz.deny_reasons with input as i
}

test_api_origin_with_agent_is_invalid if {
	i := object.union(api_input(alice, "documents:read", eng_doc), {"agent": agent_alpha})
	not authz.allow with input as i
}

test_secadmin_audit if {
	audit := {"id": "audit-log:alpha", "tenant_id": "alpha", "kind": "audit_log", "classification": "confidential", "department": "security"}
	authz.allow with input as api_input(secadmin, "audit:read", audit)
	not authz.allow with input as api_input(alice, "audit:read", audit)
	not authz.allow with input as api_input(secadmin, "audit:read", object.union(audit, {"tenant_id": "beta"}))
}

test_secadmin_cannot_read_documents if not authz.allow with input as api_input(secadmin, "documents:read", payroll)

test_nobody_may_export if {
	not authz.allow with input as api_input(bob, "exports:simulate", payroll)
	not authz.allow with input as api_input(alice, "exports:simulate", eng_doc)
}

# ------------------------------------------------------------- agent (MCP) access

test_t08_agent_reads_in_scope if authz.allow with input as mcp_input(alice, agent_alpha, alice_task, "documents:read", eng_doc)

test_t09_agent_denied_payroll_alice if {
	i := mcp_input(alice, agent_alpha, alice_task, "documents:read", payroll)
	not authz.allow with input as i
	"TASK_SCOPE_EXCEEDED" in authz.deny_reasons with input as i
}

# Bob CAN read payroll directly, but his agent cannot: task scope, agent grant and the
# restricted-via-agent contextual rule all deny independently.
test_agent_never_exceeds_task_even_if_user_could if {
	i := mcp_input(bob, agent_alpha, bob_task, "documents:read", payroll)
	not authz.allow with input as i
	"TASK_SCOPE_EXCEEDED" in authz.deny_reasons with input as i
	"AGENT_NOT_GRANTED" in authz.deny_reasons with input as i
	"RESTRICTED_VIA_AGENT" in authz.deny_reasons with input as i
}

test_restricted_denied_via_agent_even_if_task_lists_it if {
	d := deleg(bob, agent_alpha, ["documents:read"], ["doc-alpha-payroll"])
	broad_agent := object.union(agent_alpha, {"roles": ["agent-document-assistant"]})
	i := mcp_input(bob, broad_agent, d, "documents:read", payroll)
	not authz.allow with input as i
	"RESTRICTED_VIA_AGENT" in authz.deny_reasons with input as i
}

test_agent_never_exceeds_user if {
	# Task lists a finance doc that Alice (engineer) cannot read: denied.
	d := deleg(alice, agent_alpha, ["documents:read"], ["doc-alpha-finance-notes"])
	i := mcp_input(alice, agent_alpha, d, "documents:read", fin_notes)
	not authz.allow with input as i
	"SUBJECT_NOT_GRANTED" in authz.deny_reasons with input as i
}

test_t07_invalid_delegation_denied if {
	d := object.union(alice_task, {"valid": false})
	i := mcp_input(alice, agent_alpha, d, "documents:read", eng_doc)
	not authz.allow with input as i
	"DELEGATION_INVALID" in authz.deny_reasons with input as i
}

test_delegation_for_other_agent_denied if {
	d := object.union(alice_task, {"agent_id": "agent-other"})
	not authz.allow with input as mcp_input(alice, agent_alpha, d, "documents:read", eng_doc)
}

test_delegation_for_other_user_denied if {
	d := object.union(alice_task, {"user_id": "bob"})
	not authz.allow with input as mcp_input(alice, agent_alpha, d, "documents:read", eng_doc)
}

test_mcp_without_delegation_denied if {
	i := object.remove(mcp_input(alice, agent_alpha, alice_task, "documents:read", eng_doc), ["delegation"])
	not authz.allow with input as i
}

test_action_not_in_task_denied if {
	not authz.allow with input as mcp_input(alice, agent_alpha, alice_task, "documents:search", eng_doc)
}

test_cross_tenant_agent_denied if {
	not authz.allow with input as mcp_input(alice, agent_beta, deleg(alice, agent_beta, ["documents:read"], ["doc-alpha-eng"]), "documents:read", eng_doc)
}

test_inactive_agent_denied if {
	a := object.union(agent_alpha, {"active": false})
	not authz.allow with input as mcp_input(alice, a, deleg(alice, a, ["documents:read"], ["doc-alpha-eng"]), "documents:read", eng_doc)
}

test_agent_cannot_act_for_workload if {
	d := deleg(svc, agent_alpha, ["documents:read"], ["doc-alpha-eng"])
	not authz.allow with input as mcp_input(svc, agent_alpha, d, "documents:read", eng_doc)
}

test_agent_report_create if {
	authz.allow with input as mcp_input(alice, agent_alpha, alice_task, "reports:create", report_alpha)
	no_reports := deleg(alice, agent_alpha, ["documents:read"], ["doc-alpha-eng"])
	not authz.allow with input as mcp_input(alice, agent_alpha, no_reports, "reports:create", report_alpha)
}

test_agent_export_denied_even_if_task_lists_it if {
	d := deleg(bob, agent_alpha, ["exports:simulate"], ["doc-alpha-finance-notes"])
	not authz.allow with input as mcp_input(bob, agent_alpha, d, "exports:simulate", fin_notes)
}

# ------------------------------------------------------------- explanation consistency

consistency_inputs := [
	api_input(alice, "documents:read", eng_doc),
	api_input(alice, "documents:read", payroll),
	api_input(alice, "documents:read", beta_doc),
	api_input(bob, "documents:read", payroll),
	api_input(svc, "documents:read", eng_doc),
	mcp_input(alice, agent_alpha, alice_task, "documents:read", eng_doc),
	mcp_input(alice, agent_alpha, alice_task, "documents:read", payroll),
	mcp_input(bob, agent_alpha, bob_task, "documents:read", payroll),
	mcp_input(bob, agent_alpha, bob_task, "documents:read", fin_notes),
	mcp_input(alice, agent_alpha, alice_task, "reports:create", report_alpha),
]

test_allow_iff_no_deny_reasons if {
	every i in consistency_inputs {
		a := authz.allow with input as i
		r := authz.deny_reasons with input as i
		no_reasons := count(r) == 0
		a == no_reasons
	}
}

# ------------------------------------------------------------- approvals for sensitive agent writes

confidential_report := {"id": "report:t-1", "tenant_id": "alpha", "kind": "report", "classification": "confidential", "department": "*"}

bob_report_task := deleg(bob, agent_alpha, ["documents:read", "reports:create"], ["doc-alpha-forecast"])

test_confidential_agent_report_needs_approval if {
	i := mcp_input(bob, agent_alpha, bob_report_task, "reports:create", confidential_report)
	not authz.allow with input as i
	authz.deny_reasons == {"APPROVAL_REQUIRED"} with input as i
}

test_confidential_agent_report_allowed_with_valid_approval if {
	i := object.union(mcp_input(bob, agent_alpha, bob_report_task, "reports:create", confidential_report), {"approval": {"valid": true}})
	authz.allow with input as i
}

test_invalid_approval_still_denied if {
	i := object.union(mcp_input(bob, agent_alpha, bob_report_task, "reports:create", confidential_report), {"approval": {"valid": false}})
	not authz.allow with input as i
	"APPROVAL_REQUIRED" in authz.deny_reasons with input as i
}

test_approval_never_expands_grants if {
	# Alice (engineer) cannot create confidential reports; an approval does not change that.
	d := deleg(alice, agent_alpha, ["reports:create"], [])
	i := object.union(mcp_input(alice, agent_alpha, d, "reports:create", confidential_report), {"approval": {"valid": true}})
	not authz.allow with input as i
	"SUBJECT_NOT_GRANTED" in authz.deny_reasons with input as i
}

test_malformed_approval_is_invalid_input if {
	i := object.union(mcp_input(bob, agent_alpha, bob_report_task, "reports:create", confidential_report), {"approval": {"valid": "true"}})
	not authz.allow with input as i
	"INVALID_INPUT" in authz.deny_reasons with input as i
}

test_internal_agent_report_needs_no_approval if {
	authz.allow with input as mcp_input(alice, agent_alpha, alice_task, "reports:create", report_alpha)
}
