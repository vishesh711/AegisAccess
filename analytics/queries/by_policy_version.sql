-- Candidate detector by policy version, plus attacks the PDP itself allowed (authz misses).
SELECT policy_version,
       count(*) FILTER (WHERE ground_truth_is_attack AND candidate_flag)         AS tp,
       count(*) FILTER (WHERE NOT ground_truth_is_attack AND candidate_flag)     AS fp,
       count(*) FILTER (WHERE ground_truth_is_attack AND NOT candidate_flag)     AS fn,
       count(*) FILTER (WHERE NOT ground_truth_is_attack AND NOT candidate_flag) AS tn,
       count(*) FILTER (WHERE ground_truth_is_attack AND authz_allowed)          AS attacks_allowed_by_pdp
FROM detection_candidate GROUP BY policy_version ORDER BY policy_version;
