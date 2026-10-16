# SQL detection evaluation (synthetic fixture)

Generated 2026-10-16T19:55:23+00:00 at git `34854dd` by `make sql-eval`.
Dataset: `analytics/detection_fixture.csv` (hand-labelled, synthetic). These metrics describe this
fixture only and are not a claim about real-world detection performance.

Rows: 33 (attacks: 13, benign: 20)

## confusion_matrix.sql

| detector | tp | fp | fn | tn | precision | recall |
|---|---|---|---|---|---|---|
| baseline_any_deny | 11 | 10 | 2 | 10 | 0.5238 | 0.8462 |
| candidate_rules | 10 | 2 | 3 | 18 | 0.8333 | 0.7692 |

## by_rule.sql

| rule | tp | fp | precision |
|---|---|---|---|
| r1_cross_tenant | 4 | 0 | 1.0000 |
| r2_agent_out_of_scope | 3 | 0 | 1.0000 |
| r3_token_forgery | 3 | 0 | 1.0000 |
| r4_deny_burst | 4 | 2 | 0.6667 |

## by_policy_version.sql

| policy_version | tp | fp | fn | tn | attacks_allowed_by_pdp |
|---|---|---|---|---|---|
| policy-v0 | 1 | 0 | 1 | 3 | 1 |
| policy-v1 | 9 | 2 | 2 | 15 | 1 |
