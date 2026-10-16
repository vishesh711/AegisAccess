DROP TABLE IF EXISTS detection_events, scenario_results, resource_side_effects, audit_events,
    policy_versions, reports, delegations, tasks, resources, agent_identities, principal_roles,
    roles, principals, tenants CASCADE;
DROP FUNCTION IF EXISTS audit_events_block_mutation();
