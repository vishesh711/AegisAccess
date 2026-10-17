# Detection analytics datasets

Two labelled synthetic datasets are loaded side by side (`detection_events.dataset`):

* `detection_fixture.csv` (`fixture`, 33 rows): hand-labelled and small enough that every count is checked
  by hand in `tests/integration/test_analytics.py`.
* `detection_large.csv` (`large`, 1,888 rows, 143 attacks): one generated day of traffic from
  `scripts/gen_detection_dataset.py` (seeded, byte-for-byte reproducible). Labels come from the scenario that
  produced each row, never from the rules. SQL results are checked against an independent Python
  implementation of the same rules.

The hand-labelled fixture contains:

* benign allows, benign denies (expired tokens, an OPA outage, a deactivated user retrying,
  search filtering) and attacks (cross-tenant ID guessing, agent prompt-injection attempts, forged
  tokens, an insider probe, and two attacks that were *allowed* — one by a stolen workload
  credential, one under the older `policy-v0`);
* `ground_truth_is_attack` (label), `decision`/`authz_allowed` (what the PDP did) — kept separate
  from the detectors' `rule_flagged` output.

Detection is not authorization: a deny is not necessarily an attack, and an allow can be one.
These numbers describe this fixture only; they are not claims about real-world performance.
