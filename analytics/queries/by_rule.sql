-- Per-rule contribution (a rule's FN is not meaningful alone; rules are OR-ed).
SELECT rule,
       count(*) FILTER (WHERE flagged AND ground_truth_is_attack)     AS tp,
       count(*) FILTER (WHERE flagged AND NOT ground_truth_is_attack) AS fp,
       round((count(*) FILTER (WHERE flagged AND ground_truth_is_attack))::numeric
             / NULLIF(count(*) FILTER (WHERE flagged), 0), 4)         AS precision
FROM detection_flags
CROSS JOIN LATERAL (VALUES
    ('r1_cross_tenant', r1_cross_tenant),
    ('r2_agent_out_of_scope', r2_agent_out_of_scope),
    ('r3_token_forgery', r3_token_forgery),
    ('r4_deny_burst', r4_deny_burst)
) AS v(rule, flagged)
GROUP BY rule ORDER BY rule;
