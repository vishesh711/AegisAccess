-- Human approvals for sensitive agent writes: server-stored, bound to the exact action + arguments
-- (sha256 digest), approved only by the delegating human, short-lived and single-use.
CREATE TABLE approvals (
    id                    uuid PRIMARY KEY,
    tenant_id             text NOT NULL,
    task_id               uuid NOT NULL,
    approver_principal_id text NOT NULL,
    agent_principal_id    text NOT NULL,
    action                text NOT NULL,
    args_digest           text NOT NULL CHECK (args_digest ~ '^[0-9a-f]{64}$'),
    description           text NOT NULL CHECK (length(description) <= 300),
    status                text NOT NULL CHECK (status IN ('pending', 'approved', 'rejected')),
    created_at            timestamptz NOT NULL DEFAULT now(),
    expires_at            timestamptz NOT NULL,
    decided_at            timestamptz,
    decided_by            text,
    consumed_at           timestamptz,
    FOREIGN KEY (task_id, tenant_id) REFERENCES tasks(id, tenant_id),
    FOREIGN KEY (approver_principal_id, tenant_id) REFERENCES principals(id, tenant_id),
    FOREIGN KEY (agent_principal_id, tenant_id) REFERENCES principals(id, tenant_id),
    CHECK (consumed_at IS NULL OR status = 'approved'),
    CHECK (decided_by IS NULL OR decided_by = approver_principal_id)
);
CREATE INDEX approvals_lookup_idx ON approvals (task_id, args_digest, status);

ALTER TABLE approvals ENABLE ROW LEVEL SECURITY;
CREATE POLICY approvals_tenant ON approvals FOR ALL TO aegis_app
    USING (tenant_id = current_tenant()) WITH CHECK (tenant_id = current_tenant());

-- The app may create requests and record decisions/consumption, but never change WHAT was approved.
GRANT SELECT, INSERT ON approvals TO aegis_app;
GRANT UPDATE (status, decided_at, decided_by, consumed_at, expires_at) ON approvals TO aegis_app;
