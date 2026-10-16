-- Least privilege for the runtime role + row-level security for tenant data.
-- The runtime connection sets the GUC aegis.tenant_id per transaction (SET LOCAL semantics).

REVOKE ALL ON ALL TABLES IN SCHEMA public FROM PUBLIC;
REVOKE CREATE ON SCHEMA public FROM PUBLIC;
GRANT USAGE ON SCHEMA public TO aegis_app;

-- Identity / policy facts: read-only for the app.
GRANT SELECT ON tenants, principals, roles, principal_roles, agent_identities, policy_versions TO aegis_app;

-- Tenant data.
GRANT SELECT ON resources TO aegis_app;
GRANT SELECT, INSERT, UPDATE ON tasks, delegations TO aegis_app;
GRANT SELECT, INSERT ON reports TO aegis_app;

-- Audit: append-only for the app (no UPDATE/DELETE/TRUNCATE grants; triggers also block them).
GRANT SELECT, INSERT ON audit_events TO aegis_app;

-- Side-effect instrumentation: insert-only for the app.
GRANT INSERT ON resource_side_effects TO aegis_app;
GRANT USAGE ON SEQUENCE resource_side_effects_id_seq TO aegis_app;

CREATE FUNCTION current_tenant() RETURNS text
LANGUAGE sql STABLE AS $$ SELECT nullif(current_setting('aegis.tenant_id', true), '') $$;

ALTER TABLE resources   ENABLE ROW LEVEL SECURITY;
ALTER TABLE tasks       ENABLE ROW LEVEL SECURITY;
ALTER TABLE delegations ENABLE ROW LEVEL SECURITY;
ALTER TABLE reports     ENABLE ROW LEVEL SECURITY;

-- No tenant set => current_tenant() IS NULL => no rows (fail closed).
CREATE POLICY resources_tenant ON resources FOR SELECT TO aegis_app
    USING (tenant_id = current_tenant());
CREATE POLICY tasks_tenant ON tasks FOR ALL TO aegis_app
    USING (tenant_id = current_tenant()) WITH CHECK (tenant_id = current_tenant());
CREATE POLICY delegations_tenant ON delegations FOR ALL TO aegis_app
    USING (tenant_id = current_tenant()) WITH CHECK (tenant_id = current_tenant());
CREATE POLICY reports_tenant ON reports FOR ALL TO aegis_app
    USING (tenant_id = current_tenant()) WITH CHECK (tenant_id = current_tenant());

-- Non-sensitive resource attributes for the PEP, across tenants, so that the PDP (not a
-- missing row) makes the tenant decision. Never returns title or body.
CREATE FUNCTION resource_metadata(p_id text)
RETURNS TABLE (id text, tenant_id text, kind text, classification text, department text)
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = public, pg_temp AS $$
    SELECT r.id, r.tenant_id, r.kind, r.classification, r.department FROM resources r WHERE r.id = p_id
$$;
REVOKE ALL ON FUNCTION resource_metadata(text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION resource_metadata(text) TO aegis_app;
GRANT EXECUTE ON FUNCTION current_tenant() TO aegis_app;
