# Detector metrics — practice AND held-out evaluation (M-C9)

Two runs of the same detector, with the same rules and the same defaults in
`src/detector.py`. **The rules were tuned only on the 22 public practice
events.** The held-out set was generated once (fixed seed, independent
generator `tools/gen_logs.py` that never imports `src/`), evaluated once,
and not used to change any rule.

## How to reproduce

```sh
# (a) practice set, 22 events (copied unchanged from the organizer toolkit)
python scripts/eval_detector.py --events practice/events.csv \
    --labels practice/labels.csv --approvals practice/approvals.json \
    --title practice --out docs/metrics/practice.json

# (b) held-out set from the independent generator (fixed seed)
python tools/gen_logs.py --out /tmp/heldout_logs --events 12000 --seed 20261126
python scripts/eval_detector.py --events /tmp/heldout_logs/events.csv \
    --labels /tmp/heldout_logs/labels.csv \
    --approvals /tmp/heldout_logs/approvals.json \
    --title held-out --out docs/metrics/heldout.json
```

## Results

| Metric | Practice (22 events) | Held-out (12,000 events) |
|---|---|---|
| Overall F1 | 1.000 | 0.748 |
| Precision | 1.000 | 0.999 |
| Recall | 1.000 | 0.598 |
| Incidents detected | 2 / 2 | 637 / 937 (68%) |
| Median time to alert | 1.2 s | 0.2 s |
| False alerts | 0 | 1 |
| False alerts per 1,000 benign events | 0.0 | 0.1 |
| Processing time | < 5 ms | ~1.5 s, one process |

Per class, held-out (P = precision, R = recall; support = labelled events):

| Label | Support | P | R | F1 |
|---|---|---|---|---|
| unexpected_role_change | 626 | 0.996 | 0.851 | 0.918 |
| review_after_role_change | 456 | 0.995 | 0.860 | 0.923 |
| lateral_movement_candidate | 926 | 0.995 | 0.439 | 0.609 |
| approved_change (non-alert truth) | 1,575 | — | — | — |
| routine (non-alert truth) | 4,061 | — | — | — |
| routine_clock_offset | 2,585 | — | — | — |
| routine_delayed_delivery | 769 | — | — | — |
| routine_denial | 746 | — | — | — |
| isolated_denial | 256 | — | — | — |

Definitions:
- **Time to alert** is the alert's `alert_time` minus the corrected true
  time of the incident's first labelled event (clock offset removed). It
  measures delay on the event timeline, not processing time.
- **False alert** = an alert whose cited event carries no suspicious truth
  label.
- **Incident** = the set of suspicious-labelled events sharing actor +
  session id + correlation id. An incident counts as detected when at
  least one of its events is alerted.

## What the held-out errors show (found AFTER the run; no rule was changed)

1. **Lateral-movement recall is the weak point (0.439).** 300 of the 937
   lateral incidents were missed. The dominant cause: incidents whose
   unknown edges are DENIED requests that follow an effective revocation
   approval are excluded from the burst by design (the practice set labels
   such denials `routine_denial` — alerting them would make every
   post-revocation denial an incident). A deny-heavy probe session by a
   recently-revoked service account therefore stays under the burst
   threshold when its edges are denied. Documented trade-off, not fixed
   after the run.
2. **The single false alert** in 12,000 events was a lateral burst whose
   truth label sat on a different event of the same session (grouping
   boundary), not a wrong rule.
3. Precision stays ~1.0 on 9,992 benign events because the rules require
   context (approval subject/operation/role/time window, documented service
   graph, role scopes) rather than volume thresholds alone.

## Scope

These numbers apply to the organizer's practice set and to synthetic data
from this generator. They are NOT production accuracy claims. The generator
mix, actor population and incident densities are documented in
`tools/gen_logs.py`; both datasets and the full JSON reports are
reproducible from the seed.
