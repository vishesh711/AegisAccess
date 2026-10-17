REVOKE ALL ON audit_events, audit_shipments, resource_side_effects FROM aegis_auditor;
REVOKE ALL ON audit_events FROM aegis_audit_shipper;
REVOKE USAGE ON SCHEMA public FROM aegis_audit_shipper, aegis_auditor;
DROP INDEX IF EXISTS audit_events_request_idx;
DROP INDEX IF EXISTS resource_side_effects_request_idx;
ALTER TABLE resource_side_effects DROP COLUMN request_id;
DROP TABLE audit_shipments;
