-- External audit sink support (ADR-8).
--  * audit_shipments: which audit rows the shipper has written to the external WORM store. It is
--    bookkeeping only; integrity comes from the store itself (the verifier never trusts this table).
--  * resource_side_effects.request_id: lets every adapter side effect be matched to the execution
--    audit event of the same request (allow/execution reconciliation). NULL only for older rows.
DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'aegis_audit_shipper')
       OR NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'aegis_auditor') THEN
        RAISE EXCEPTION 'roles aegis_audit_shipper / aegis_auditor missing: the database volume predates them; run make reset';
    END IF;
END
$$;

CREATE TABLE audit_shipments (
    event_id     uuid PRIMARY KEY,
    batch_seq    bigint NOT NULL CHECK (batch_seq > 0),
    event_sha256 text NOT NULL CHECK (event_sha256 ~ '^[0-9a-f]{64}$'),
    shipped_at   timestamptz NOT NULL DEFAULT now()
);

ALTER TABLE resource_side_effects ADD COLUMN request_id uuid;
CREATE INDEX resource_side_effects_request_idx ON resource_side_effects (request_id);
CREATE INDEX audit_events_request_idx ON audit_events (request_id);

GRANT USAGE ON SCHEMA public TO aegis_audit_shipper, aegis_auditor;
-- Shipper: read audit rows, append its own shipment records. Nothing else.
GRANT SELECT ON audit_events TO aegis_audit_shipper;
GRANT SELECT, INSERT ON audit_shipments TO aegis_audit_shipper;
-- Auditor: read-only, for reconciliation.
GRANT SELECT ON audit_events, audit_shipments, resource_side_effects TO aegis_auditor;
