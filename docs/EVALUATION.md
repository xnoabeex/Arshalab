# Evaluation Methodology — Autonomous Attack-Chain Reconstruction

This document specifies exactly how the autonomous attack-chain reconstruction
results are scored. It complements the compact description in the paper, giving
the full mechanics so the numbers can be reproduced from the released code.

**Source of record:** `score_timeline_mode2.py` (scorer),
`retrieve_evidence_v2.py` (Stage 1 retrieval), `reconstruct_timeline.py`
(Stage 2 reconstruction). Line numbers below refer to `score_timeline_mode2.py`
unless stated otherwise.

---

## 1. Pipeline and composite score

Each (model, case, run) produces one reconstructed chain through a two-stage
pipeline:

1. **Stage 1 — evidence retrieval** (`retrieve_evidence_v2.py`): a fixed catalog
   of **98 case-agnostic anchor queries** across ten DFIR domains is issued
   against the case index, bounded to the case and its incident window. Each
   record is compressed to its diagnostic fields. The result is one evidence
   pool (691 records on Hunter, 746 on KDFS, 798 on Magnet), persisted as an
   audit trail.
2. **Stage 2 — reconstruction** (`reconstruct_timeline.py`): the full evidence
   pool plus a structured prompt is given to the model, which emits a
   chronologically ordered chain of 15–30 steps, each with a timestamp, a
   description containing a concrete identifier, a source attribution, and an
   incident phase drawn from a fixed vocabulary. Those phase labels are the
   model's own and are not MITRE ATT&CK tactics. Tactic coverage below is
   scored against the tactics recorded in the reference chain, not against
   the labels the model emits.

The chain is scored by a weighted composite (lines 726–737):

```
composite = 0.30 * step
          + 0.30 * tactic
          + 0.25 * (1 - halluc)
          + 0.15 * ordering
```

The weights encode a forensic priority: coverage of the incident (step, tactic)
and the absence of fabrication (halluc) are the headline contributions; ordering
is reported as a diagnostic (0.15). Source attribution is computed but kept out
of the composite and reported separately.

---

## 2. Ground truth (reference chains)

Each case has a hand-curated reference chain of per-record events. Scoring runs
over the subset marked `es_in_scope: true`; the remainder rest on artifact
families the platform does not parse, or on evidence outside the reach of any
disk-forensic tool, and are held outside the headline figures.

Step coverage is then reported over **milestones** rather than over raw events.
A milestone is a *high-level incident step* (e.g. "persistence established via
service install") operationalised as a small **keyword checklist** aggregated
from one or more of the in-scope events. A model earns a milestone by recovering
that step of the attack from any of the records that report it.

| Case | Reference events | In scope | Milestones in scope |
|------|-----------------:|---------:|--------------------:|
| KDFS_2023 | 100 | 48 | 4 |
| Magnet_CTF_2022 | 18 | 17 | 8 |
| Hunter_4orensics | 49 | 45 | 10 |

The event counts are the length of the `events` array in each
`benchmark/ground_truth/*_attack_chain_gt.json`, and the in-scope counts are the
events whose `es_in_scope` field is `true`. A further thirteen milestones rest on
artifact families the platform does not parse and are excluded, so twenty-two of
thirty-five stand in scope.

Corrected 2026-08-26. The table previously read 48 / 26 / 41, which were
pre-revision figures matching neither the event counts nor the milestone counts
in the shipped ground truth. Previous version kept beside this file as
`EVALUATION.md.bak_before_chainsize_fix_2026-08-26`.

Two ground-truth formats are supported (lines 572–594):

- **Explicit-keyword format** (KDFS, Hunter): the milestone carries an explicit
  `keywords` list, used directly.
- **Event-ID format** (Magnet): the milestone lists narrow GT events; their
  `evidence_keywords` are collected and filtered by `is_specific()` so that only
  discriminative keywords (not generic terms) contribute.

---

## 3. Matching a reconstructed step to a reference event

Coverage and ordering both depend on a **tiered match** between a model step and
a reference event (`_match_gt_to_chain`, lines 187–305; substring keyword test
`_kw_in`, lines 224–226):

| Tier | Rule | Lines |
|------|------|-------|
| 1 | Timestamp within **±1 minute** **and** an overlapping keyword | 241–254 |
| 2 | Same date, timestamp within **±30 minutes** | 256–267 |
| 3 | **Keyword only**, within a **±7-day** window, with date/time tokens removed so a shared calendar date cannot by itself create a match | 269–294 (token exclusion 274–276) |

The tiers are tried in order; the strictest satisfied tier wins.

---

## 4. Metric definitions

### 4.1 Step coverage (primary)

The fraction of **in-scope** reference milestones the chain reaches. A milestone
is **covered** if **any** of its checklist keywords appears anywhere in the
lowercased chain text (line 588).

```
step = covered_in_scope / total_in_scope          (lines 616–619)
```

Milestones whose underlying artifact family the platform does not yet parse are
marked `out_of_scope` and **excluded from the headline denominator** (scope
split, lines 601–606); they are reported separately as a transparency companion
so the headline is not inflated or deflated by unimplemented modules.

This metric measures **breadth of kill-chain reconstruction in the spirit of
DFIR reporting** (did the analyst identify each phase?), not per-record fidelity.

### 4.2 Tactic coverage

The fraction of the **distinct MITRE ATT&CK tactics present in the reference**
that the chain reaches. A tactic counts once **at least one** of its events is
matched (lines 630–635).

```
tactic = covered_tactics / distinct_gt_tactics
```

### 4.3 Hallucination rate

The fraction of **chain steps the evidence does not support**, checked against
the **retrieved evidence pool, not the ground truth** (`_is_grounded`,
lines 472–527; aggregation lines 658–669).

A step is **grounded** only when **both** hold:

1. its **date** appears in the evidence, and — **if a time is stated** — that
   **HH:MM** appears at the same date within **±1 minute** (lines 487–499); and
2. **every** concrete entity it names — file name, Windows Event ID, path, hash,
   domain, SID — appears **verbatim** in the (lowercased) evidence blob
   (lines 500–525; known Event-ID set at line 513).

Edge cases:

- A step with **no testable entity** returns *grounded*
  (`no_factual_entity_to_check`, line 522). It is **counted as grounded**, not
  excluded — the denominator is always the **full** chain length (line 669).
- A missing date or missing minute makes the step **ungrounded** (i.e. counted
  as a hallucination), independent of its entities.

```
halluc = ungrounded_steps / total_chain_steps
```

An invented fact is therefore penalised even when it reads plausibly, while a
correct fact that happens not to be in the curated ground truth is **not**
penalised as long as it is in the evidence.

### 4.4 Ordering accuracy

A **pairwise (Kendall-style) concordance** over matched events
(`_ordering_accuracy`, lines 340–406; timestamp parsing 310–337):

- form every pair `(i, j)` of matched reference events with **distinct**
  timestamps (pairs with identical GT timestamps are skipped, line 385);
- a pair is **concordant** if the chain orders the two events the same way the
  reference does (lines 387, 399–403);
- a pair whose reference timestamps are **less than 60 seconds apart** is treated
  as concordant regardless of direction, because sub-minute order is not
  forensically diagnostic (lines 392–395);
- session-scope / negative-finding events have no instantaneous time and are
  excluded from both numerator and denominator.

```
ordering = concordant_pairs / comparable_pairs
```

---

## 5. Reproducing the scores

```bash
# Stage 1 — build the 98-anchor evidence pool for a case
python retrieve_evidence_v2.py --case magnet      # kdfs | magnet | 4orensics | all

# Stage 2 — reconstruct the chain with a given provider/run
python reconstruct_timeline.py --provider deepseek --case magnet --run 1

# Score the chain against the reference
python score_timeline_mode2.py <chain_path> --case magnet \
    --evidence benchmark_results/mode2_final/opus/magnet/control/evidence_Magnet_CTF_2022.json
```

The same code paths produce both the interactive `reconstruct_attack_chain`
tool output and the benchmark numbers, so the tool and the evaluation are
identical.

---

## 6. Note on the interactive question-answering benchmark

Interactive question answering uses its own, simpler metrics: **recall** is the
fraction of reference key entities present in the answer, and the **fabrication
rate** is the fraction of asserted facts the case index does not corroborate.
Its full methodology is documented separately in
[`QA_BENCHMARK.md`](QA_BENCHMARK.md). The composite above applies only to
attack-chain reconstruction.
