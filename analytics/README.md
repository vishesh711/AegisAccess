# Detection analytics fixture

`detection_fixture.csv` is a **hand-labelled synthetic** event set (33 rows) used to measure SQL
detection rules. It is deliberately small so every count can be checked by hand. It contains:

* benign allows, benign denies (expired tokens, an OPA outage, a deactivated user retrying,
  search filtering) and attacks (cross-tenant ID guessing, agent prompt-injection attempts, forged
  tokens, an insider probe, and two attacks that were *allowed* — one by a stolen workload
  credential, one under the older `policy-v0`);
* `ground_truth_is_attack` (label), `decision`/`authz_allowed` (what the PDP did) — kept separate
  from the detectors' `rule_flagged` output.

Detection is not authorization: a deny is not necessarily an attack, and an allow can be one.
These numbers describe this fixture only; they are not claims about real-world performance.
