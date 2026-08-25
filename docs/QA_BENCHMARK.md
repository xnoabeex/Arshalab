# Evaluation Methodology — Interactive Question Answering

This document specifies how the interactive question-answering benchmark is
built and scored: how the question sets were constructed, how each question's
ground truth was fixed, and how a model's free-text answer is judged correct.
It complements the compact description in the paper, giving the full mechanics
so the numbers can be reproduced from the released code.

**Source of record:** `benchmark.py` (runner + scorer) and the per-case
question files under `benchmark/questions/`. Line numbers below refer to
`benchmark.py` unless stated otherwise.

---

## 1. Question sets

The benchmark covers three forensic disk images, each a published forensic
challenge:

| Case file | Image | Questions |
|-----------|-------|-----------|
| `benchmark/questions/KDFS_2023.json` | KDFS 2023 | 100 |
| `benchmark/questions/CTF_Magnet_2022.json` | Magnet CTF 2022 | 100 |
| `benchmark/questions/Hunter_4orensics.json` | Hunter / 4orensics | 100 |

That is **300 questions in total, 100 per image**. The questions for one image
range from single-fact retrieval (the primary user account, the OS build, the
most frequently executed programs) through cross-artifact correlation (a USB
insertion followed seconds later by an archive being created) to full-incident
synthesis (a day-by-day timeline, the end-to-end operation). Every question is
answered as a short factual response and scored uniformly by the rules in
Section 3.

Provider-calibrated copies (for example `KDFS_2023_openai.json`) carry the same
questions and ground truth; they exist only to tune the surface form of the
keyword checklist for a given model's phrasing and do not change which facts are
required.

### 1.1 Question record schema

Each question is one record with the following fields (`load_case_questions`,
lines 222–296):

```jsonc
{
  "id": "KDFS15",
  "category": "retrieval",
  "question": "Which USB storage device was connected, and when?",
  "expected_facts": {                     // ground-truth entities for this question
    "device": ["SanDisk Cruzer Blade", "SanDisk"],
    "first_connected": ["2023-09-21 14:50:15", "05:50:15"]
  },
  "expected_answer": "A SanDisk Cruzer Blade ...",   // full reference answer
  "keywords": [ ["SanDisk Cruzer Blade", "SanDisk"], ["2023-09-21 14:50:15", "05:50:15"] ]
}
```

- **`expected_facts`** — the ground-truth key entities for the question. Each
  value is either a single required fact or a **list of acceptable variants**
  (the same fact a model may phrase differently, e.g. `["Windows 10 Pro",
  "Windows 10", "Win10"]` or a timestamp in KST and UTC).
- **`expected_answer`** — a full reference answer. It is consumed **exclusively**
  by the optional LLM-as-judge path (Section 3.5) and plays no role in keyword
  recall or precision.
- **`keywords`** — the matchable checklist. At load time `expected_facts` is
  recursively flattened into this checklist and merged with any explicitly
  authored keywords.

### 1.2 How the checklist is derived from the facts

`extract_keywords_recursive` (lines 187–219) turns `expected_facts` into the
keyword checklist:

- an all-string list of **length > 1** becomes an **any-match group** — the
  group counts as satisfied when any one member is found;
- a bare string, or a single-element list, contributes **one required keyword**;
- obviously non-fact strings are filtered out — strings of length ≥ 80
  characters, strings with characteristic explanatory prefixes/substrings, and
  strings of eight or more words — and the meta-keys `evaluation`,
  `must_acknowledge`, and `must_note` are skipped entirely.

The extracted keywords are concatenated with any explicitly authored `keywords`
and de-duplicated: standalone strings are compared case-insensitively, while
group lists are compared by their literal form (lines 278–285).

---

## 2. Ground truth

Every question has a **predefined ground-truth answer, fixed before any model is
run**. It has two parts: the `expected_facts` map, which lists the specific key
entities a correct answer must contain, and a full reference answer
(`expected_answer`). Model answers are scored against this ground truth, not
against one another.

Each fact in `expected_facts` is a concrete, checkable entity present in the
case's parsed artifacts: a user account, an OS build, an Event ID and its count,
a file name, a device, a timestamp. Facts are expressed as small lists of
acceptable variants rather than a single canonical string, so that any
forensically equivalent phrasing of the same fact is accepted while the fact
itself is still required (for example a timestamp given in either KST or UTC, or
an executable named by its file name or its display name).

---

## 3. Scoring a model answer

Every answer is scored automatically per question and per run. The headline
metrics are recall, precision, F1, and the fabrication (hallucination) rate;
consistency and an optional judge are reported alongside.

### 3.1 Recall (keyword coverage)

Keyword recall is the fraction of a question's ground-truth keyword checklist
that appears in the model's answer, where each checklist entry is matched by
**case-insensitive substring** against a set of generated variants
(`check_keywords_in_response`, lines 830–868; `_get_keyword_variants`,
738–827). The variant set always contains the lowercased keyword plus, depending
on the keyword's form, equivalent **UTC and KST timestamp** renderings,
executable **display-name aliases** (for example `msedge` yields
`microsoft edge`), forensic **semantic synonyms** (for example `copied` yields
`transferred`), and a conditionally appended `.exe` suffix that is suppressed for
timestamps, dates, paths, emails, hashes, non-ASCII tokens, and names already
carrying a recognized extension. A checklist entry may itself be a **group**
expressed as a list of acceptable alternatives, in which case the group is
counted as found when any one member matches. Every entry, whether a single
keyword or a group, contributes exactly one unit to the denominator.

```
recall = found_entries / total_entries
```

### 3.2 Precision

Precision is computed over a **restricted set of automatically extracted,
machine-checkable tokens**: four-digit Windows Event IDs and non-system
executable names (mentions in negated context and common built-in Windows
executables are excluded). Each such token is verified by a count lookup against
the case's Elasticsearch forensic indices, and precision is the fraction of
checked tokens that are found:

```
precision = verified / (verified + fabricated)
```

Tokens whose lookup raises an error are dropped from the denominator. When no
token remains to check (including error responses), precision defaults to 1.0
(lines 1774–1780).

### 3.3 F1

```
F1 = 2 * precision * recall / (precision + recall)
```

The harmonic mean of precision and recall (line 1783).

### 3.4 Fabrication (hallucination) rate

The anti-fabrication check extracts two kinds of machine-verifiable claims from
each answer — four-digit Windows Event IDs and `.exe` file names — and validates
them against the case's Elasticsearch evidence indices, skipping common built-in
Windows executables and ignoring claims that appear in an explicit **negative
context within the preceding 80 characters** (e.g. "no evidence of Event ID X")
(`detect_hallucinations`, lines 924–1130).

- **Event-ID claims** are tested only against the **Event Log** index; an ID with
  no matching records is flagged immediately.
- **`.exe` claims** are checked in turn against the **Prefetch, Shimcache,
  Amcache, LNK, SRUM, and Event Log** indices, and only if none match does a
  fuzzy fallback run (an alias table plus substring matching over Prefetch,
  Shimcache, and Amcache). A successful fuzzy hit is counted as **verified**,
  not fabricated.

A claim matched by no index and no fuzzy fallback is recorded as fabricated:

```
fabrication_rate = fabricated / (verified + fabricated)
```

An invented Event ID or executable is therefore penalised even when it reads
plausibly, while a real fact the curated ground truth happens not to list is not
penalised as long as the evidence contains it.

### 3.5 Consistency across runs

When a question is run N times, consistency is quantified two complementary ways.

- **Factual overlap** reports the fraction of ground-truth keyword entries
  matched in **every** one of the N runs (`always_present / total_keywords`),
  where each entry is a single keyword or a group of alternatives deemed matched
  in a run when at least one member occurs (case-insensitive substring) in that
  run's answer (`compute_consistency`, lines 1137–1172).
- **Semantic similarity** reports the mean pairwise cosine similarity, over all
  unique run pairs, of sentence-transformer (`all-MiniLM-L6-v2`) embeddings of
  the N answers (`compute_semantic_consistency`, lines 1196–1228).

Both measures require at least two runs.

### 3.6 Optional LLM-as-judge

As a supplementary qualitative check, a separate Claude judge can score each
answer against the question's reference answer on accuracy, completeness,
reasoning, and absence of fabrication (1–5 each) (lines 1257–1351). This is
reported separately and is not part of the headline recall/precision figures.

---

## 4. Reproducing the scores

```bash
# Full benchmark for one provider on one image, single run
python benchmark.py --providers deepseek --case-id <case_id> --runs 1

# Repeat runs to measure consistency
python benchmark.py --providers deepseek --case-id <case_id> --runs 3

# Inspect the questions and ground truth without calling any model
python benchmark.py --dry-run
```

Per-question results record the answer, the keywords found and missing, the
verified and fabricated tokens, and the recall/precision/F1/fabrication numbers,
so every score is auditable down to the individual fact.

---

## 5. Note on the attack-chain reconstruction benchmark

The autonomous attack-chain reconstruction task is scored by a different,
step-coverage-based methodology, documented separately in
[`EVALUATION.md`](EVALUATION.md).
