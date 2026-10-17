# SQL detection evaluation (synthetic fixture)

Generated 2026-10-17T00:07:11+00:00 at git `8484e27` by `make sql-eval`.
Dataset: `analytics/detection_fixture.csv` (hand-labelled, synthetic). These metrics describe this
fixture only and are not a claim about real-world detection performance.

Rows: 1921 (attacks: 156, benign: 1765)

## confusion_matrix.sql

| dataset | detector | tp | fp | fn | tn | precision | recall |
|---|---|---|---|---|---|---|---|
| fixture | baseline_any_deny | 11 | 10 | 2 | 10 | 0.5238 | 0.8462 |
| fixture | candidate_rules | 10 | 2 | 3 | 18 | 0.8333 | 0.7692 |
| large | baseline_any_deny | 110 | 175 | 33 | 1570 | 0.3860 | 0.7692 |
| large | candidate_rules | 95 | 48 | 48 | 1697 | 0.6643 | 0.6643 |

## by_rule.sql

| dataset | rule | tp | fp | precision |
|---|---|---|---|---|
| fixture | r1_cross_tenant | 4 | 0 | 1.0000 |
| fixture | r2_agent_out_of_scope | 3 | 0 | 1.0000 |
| fixture | r3_token_forgery | 3 | 0 | 1.0000 |
| fixture | r4_deny_burst | 4 | 2 | 0.6667 |
| large | r1_cross_tenant | 40 | 0 | 1.0000 |
| large | r2_agent_out_of_scope | 20 | 30 | 0.4000 |
| large | r3_token_forgery | 35 | 0 | 1.0000 |
| large | r4_deny_burst | 18 | 20 | 0.4737 |

## by_policy_version.sql

| dataset | policy_version | tp | fp | fn | tn | attacks_allowed_by_pdp |
|---|---|---|---|---|---|---|
| fixture | policy-v0 | 1 | 0 | 1 | 3 | 1 |
| fixture | policy-v1 | 9 | 2 | 2 | 15 | 1 |
| large | policy-v0 | 8 | 0 | 33 | 36 | 33 |
| large | policy-v1 | 87 | 48 | 15 | 1661 | 0 |
