DROP VIEW IF EXISTS detection_candidate;
DROP VIEW IF EXISTS detection_flags;
DELETE FROM detection_events WHERE dataset <> 'fixture';
ALTER TABLE detection_events DROP COLUMN dataset;
-- restore the 0003 views
CREATE VIEW detection_flags AS
WITH w AS (
    SELECT e.*,
           count(*) FILTER (WHERE e.decision = 'deny') OVER (
               PARTITION BY e.principal_id ORDER BY e.event_time
               RANGE BETWEEN interval '5 minutes' PRECEDING AND CURRENT ROW
           ) AS denies_last_5m
    FROM detection_events e
)
SELECT
    event_id, event_time, principal_id, principal_type, policy_version, decision, reason_code,
    authz_allowed, ground_truth_is_attack,
    -- Baseline detector: alert on every deny.
    (decision = 'deny') AS r0_any_deny,
    -- Candidate rules.
    (resource_tenant IS NOT NULL AND resource_tenant <> subject_tenant) AS r1_cross_tenant,
    (principal_type = 'agent' AND decision = 'deny'
        AND reason_code ~ '(TASK_SCOPE_EXCEEDED|UNKNOWN_TOOL|RESTRICTED_VIA_AGENT)') AS r2_agent_out_of_scope,
    (action = 'authn' AND reason_code IN
        ('INVALID_SIGNATURE', 'DISALLOWED_ALGORITHM', 'UNKNOWN_SIGNING_KEY', 'WRONG_AUDIENCE', 'MALFORMED_TOKEN'))
        AS r3_token_forgery,
    (decision = 'deny' AND denies_last_5m >= 3) AS r4_deny_burst
FROM w;

CREATE VIEW detection_candidate AS
SELECT *, (r1_cross_tenant OR r2_agent_out_of_scope OR r3_token_forgery OR r4_deny_burst) AS candidate_flag
FROM detection_flags;
GRANT SELECT ON detection_flags, detection_candidate TO aegis_app;
