-- Binds one exchanged (user -> agent) access token to exactly one task. Written by the agent host
-- right after the token exchange, while it holds the authenticated task owner's request; read by
-- the MCP server on every tool call. The token id is stored hashed.
CREATE TABLE agent_token_bindings (
    token_id_sha256    text PRIMARY KEY CHECK (token_id_sha256 ~ '^[0-9a-f]{64}$'),
    tenant_id          text NOT NULL,
    task_id            uuid NOT NULL,
    user_principal_id  text NOT NULL,
    agent_principal_id text NOT NULL,
    expires_at         timestamptz NOT NULL,
    created_at         timestamptz NOT NULL DEFAULT now(),
    FOREIGN KEY (task_id, tenant_id) REFERENCES tasks(id, tenant_id),
    FOREIGN KEY (user_principal_id, tenant_id) REFERENCES principals(id, tenant_id),
    FOREIGN KEY (agent_principal_id, tenant_id) REFERENCES principals(id, tenant_id)
);
CREATE INDEX agent_token_bindings_task_idx ON agent_token_bindings (task_id);

ALTER TABLE agent_token_bindings ENABLE ROW LEVEL SECURITY;
CREATE POLICY agent_token_bindings_tenant ON agent_token_bindings FOR ALL TO aegis_app
    USING (tenant_id = current_tenant()) WITH CHECK (tenant_id = current_tenant());
-- Insert + read only: a binding can never be re-pointed at another task.
GRANT SELECT, INSERT ON agent_token_bindings TO aegis_app;
