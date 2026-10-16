-- AegisAccess schema. Runs as aegis_owner. The runtime role aegis_app gets least privilege.

CREATE TABLE tenants (
    id          text PRIMARY KEY CHECK (id ~ '^[a-z][a-z0-9-]{1,31}$'),
    name        text NOT NULL
);

CREATE TABLE principals (
    id           text PRIMARY KEY CHECK (id ~ '^[a-z][a-z0-9-]{1,63}$'),
    tenant_id    text NOT NULL REFERENCES tenants(id),
    type         text NOT NULL CHECK (type IN ('human', 'workload', 'agent')),
    oidc_issuer  text NOT NULL,
    oidc_sub     text NOT NULL,
    client_id    text,
    display_name text NOT NULL,
    active       boolean NOT NULL DEFAULT true,
    UNIQUE (oidc_issuer, oidc_sub),
    UNIQUE (id, tenant_id),
    -- workloads and agents are bound to exactly one OAuth client
    CHECK ((type = 'human') OR client_id IS NOT NULL)
);

CREATE TABLE roles (
    id          text PRIMARY KEY,
    description text NOT NULL
);

CREATE TABLE principal_roles (
    principal_id text NOT NULL,
    tenant_id    text NOT NULL,
    role_id      text NOT NULL REFERENCES roles(id),
    PRIMARY KEY (principal_id, role_id),
    FOREIGN KEY (principal_id, tenant_id) REFERENCES principals(id, tenant_id) ON DELETE CASCADE
);

CREATE TABLE agent_identities (
    id           text PRIMARY KEY,
    principal_id text NOT NULL UNIQUE,
    tenant_id    text NOT NULL,
    description  text NOT NULL,
    active       boolean NOT NULL DEFAULT true,
    FOREIGN KEY (principal_id, tenant_id) REFERENCES principals(id, tenant_id)
);

CREATE TABLE resources (
    id             text PRIMARY KEY CHECK (id ~ '^[a-z][a-z0-9-]{1,63}$'),
    tenant_id      text NOT NULL REFERENCES tenants(id),
    kind           text NOT NULL CHECK (kind IN ('document')),
    classification text NOT NULL CHECK (classification IN ('public', 'internal', 'confidential', 'restricted')),
    department     text NOT NULL,
    owner_id       text NOT NULL,
    title          text NOT NULL,
    body           text NOT NULL,
    UNIQUE (id, tenant_id),
    FOREIGN KEY (owner_id, tenant_id) REFERENCES principals(id, tenant_id)
);
CREATE INDEX resources_tenant_idx ON resources (tenant_id);

CREATE TABLE tasks (
    id                 uuid PRIMARY KEY,
    tenant_id          text NOT NULL,
    owner_principal_id text NOT NULL,
    agent_principal_id text NOT NULL,
    purpose            text NOT NULL CHECK (length(purpose) <= 200),
    status             text NOT NULL CHECK (status IN ('active', 'completed', 'revoked')),
    created_at         timestamptz NOT NULL DEFAULT now(),
    UNIQUE (id, tenant_id),
    FOREIGN KEY (owner_principal_id, tenant_id) REFERENCES principals(id, tenant_id),
    FOREIGN KEY (agent_principal_id, tenant_id) REFERENCES principals(id, tenant_id)
);

CREATE TABLE delegations (
    id                 uuid PRIMARY KEY,
    task_id            uuid NOT NULL UNIQUE,
    tenant_id          text NOT NULL,
    user_principal_id  text NOT NULL,
    agent_principal_id text NOT NULL,
    allowed_actions    text[] NOT NULL,
    allowed_resources  text[] NOT NULL,
    expires_at         timestamptz NOT NULL,
    revoked_at         timestamptz,
    created_at         timestamptz NOT NULL DEFAULT now(),
    FOREIGN KEY (task_id, tenant_id) REFERENCES tasks(id, tenant_id),
    FOREIGN KEY (user_principal_id, tenant_id) REFERENCES principals(id, tenant_id),
    FOREIGN KEY (agent_principal_id, tenant_id) REFERENCES principals(id, tenant_id),
    CHECK (expires_at > created_at)
);

CREATE TABLE reports (
    id                  uuid PRIMARY KEY,
    tenant_id           text NOT NULL,
    task_id             uuid NOT NULL,
    created_by_agent_id text NOT NULL,
    on_behalf_of_id     text NOT NULL,
    source_document_ids text[] NOT NULL,
    summary_text        text NOT NULL CHECK (length(summary_text) <= 4000),
    created_at          timestamptz NOT NULL DEFAULT now(),
    FOREIGN KEY (task_id, tenant_id) REFERENCES tasks(id, tenant_id)
);

CREATE TABLE policy_versions (
    id         text PRIMARY KEY,
    digest     text NOT NULL,
    status     text NOT NULL CHECK (status IN ('active', 'retired', 'candidate')),
    created_at timestamptz NOT NULL DEFAULT now()
);

-- Append-only security audit trail. No document bodies, prompts, tokens or secrets.
CREATE TABLE audit_events (
    id               uuid PRIMARY KEY,
    event_time       timestamptz NOT NULL DEFAULT clock_timestamp(),
    event_kind       text NOT NULL CHECK (event_kind IN ('decision', 'execution', 'incident', 'authn')),
    correlation_id   uuid NOT NULL,
    request_id       uuid NOT NULL,
    principal_type   text,
    principal_id     text,
    tenant_id        text,
    agent_id         text,
    task_id          uuid,
    tool_name        text,
    action           text,
    resource_id      text,
    policy_version   text,
    decision         text NOT NULL CHECK (decision IN ('allow', 'deny', 'n/a')),
    reason_code      text NOT NULL,
    evaluator_status text NOT NULL,
    outcome          text,
    duration_ms      double precision,
    request_origin   text,
    test_case_id     text
);
CREATE INDEX audit_events_tenant_time_idx ON audit_events (tenant_id, event_time DESC);
CREATE INDEX audit_events_correlation_idx ON audit_events (correlation_id);

CREATE FUNCTION audit_events_block_mutation() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
    RAISE EXCEPTION 'audit_events is append-only';
END;
$$;
CREATE TRIGGER audit_events_no_update BEFORE UPDATE OR DELETE ON audit_events
    FOR EACH ROW EXECUTE FUNCTION audit_events_block_mutation();
CREATE TRIGGER audit_events_no_truncate BEFORE TRUNCATE ON audit_events
    FOR EACH STATEMENT EXECUTE FUNCTION audit_events_block_mutation();

-- Instrumentation: one row per protected operation that ACTUALLY executed. Tests use it to
-- prove denied requests produced zero side effects (not just a 403).
CREATE TABLE resource_side_effects (
    id             bigserial PRIMARY KEY,
    event_time     timestamptz NOT NULL DEFAULT clock_timestamp(),
    kind           text NOT NULL CHECK (kind IN ('document_read', 'report_write', 'export_simulated', 'search')),
    tenant_id      text NOT NULL,
    resource_id    text,
    principal_id   text NOT NULL,
    agent_id       text,
    task_id        uuid,
    correlation_id uuid NOT NULL
);

CREATE TABLE scenario_results (
    id                     bigserial PRIMARY KEY,
    run_id                 uuid NOT NULL,
    scenario_id            text NOT NULL,
    description            text NOT NULL,
    expected_decision      text NOT NULL,
    actual_decision        text NOT NULL,
    expected_side_effects  integer NOT NULL,
    actual_side_effects    integer NOT NULL,
    audit_events_observed  integer NOT NULL,
    ground_truth_is_attack boolean NOT NULL,
    passed                 boolean NOT NULL,
    recorded_at            timestamptz NOT NULL DEFAULT now()
);

-- Analytics fixture (synthetic, labelled). Detection is separate from authorization.
CREATE TABLE detection_events (
    event_id               text PRIMARY KEY,
    event_time             timestamptz NOT NULL,
    principal_id           text NOT NULL,
    principal_type         text NOT NULL,
    subject_tenant         text NOT NULL,
    resource_tenant        text,
    action                 text NOT NULL,
    tool_name              text,
    decision               text NOT NULL CHECK (decision IN ('allow', 'deny')),
    reason_code            text NOT NULL,
    policy_version         text NOT NULL,
    authz_allowed          boolean NOT NULL,
    ground_truth_is_attack boolean NOT NULL
);
