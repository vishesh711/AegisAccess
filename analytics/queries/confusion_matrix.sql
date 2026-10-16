-- Baseline vs candidate on the SAME labelled fixture. Precision/recall are NULL (not error)
-- when their denominator is zero.
WITH scored AS (
    SELECT 'baseline_any_deny' AS detector, ground_truth_is_attack AS gt, r0_any_deny AS flagged FROM detection_candidate
    UNION ALL
    SELECT 'candidate_rules', ground_truth_is_attack, candidate_flag FROM detection_candidate
), m AS (
    SELECT detector,
           count(*) FILTER (WHERE gt AND flagged)         AS tp,
           count(*) FILTER (WHERE NOT gt AND flagged)     AS fp,
           count(*) FILTER (WHERE gt AND NOT flagged)     AS fn,
           count(*) FILTER (WHERE NOT gt AND NOT flagged) AS tn
    FROM scored GROUP BY detector
)
SELECT detector, tp, fp, fn, tn,
       round(tp::numeric / NULLIF(tp + fp, 0), 4) AS precision,
       round(tp::numeric / NULLIF(tp + fn, 0), 4) AS recall
FROM m ORDER BY detector;
