# Changes, 31 July – 1 August 2026

An audit of this release against its own artefacts found six defects. All are fixed here and every
result affected by them has been re-run and re-published. This document also records three things
the first draft of it failed to disclose; they are marked **Disclosure**.

Results of record are in `benchmark_results/mode2_final/` — 36 chains, four models on three cases in
three runs, with a scored `.mode2_score.json` beside each.

---

## 1. Event-ID anchors retrieved by full-text search

`retrieve_evidence_v2.py`

Anchors named after a Windows Event ID resolved it with a full-text query for the digits, so a
record was returned whenever the digit string occurred anywhere within it. Every record is presented
to the model with its `_anchor` label, so the model was handed an authoritative-looking identifier
the record did not support.

Over the published pools, 44 numeric anchors per case: 423 of 889 records (**47.6%**) carried a
different `event_id` than their label announced. Real events were also missed — the Hunter anchor
`app_hangs_1002` returned six unrelated records although the index holds 69 genuine 1002 events.

Numeric event-log queries are now resolved with a `terms` filter on the typed `event_id` field, with
residual text preserved under its original AND/OR semantics. Mislabelled records fall to **3.1%**.

**A consequence that must be stated plainly.** With the false positives gone, a third of the anchor
catalogue matches nothing on these images: empty anchors per case go from 5/4/4 to 30/31/37, and of
the 132 numeric anchor-case cells, 68 now return no record at all. Elasticsearch confirms these cases
genuinely contain zero events for 4740, 4776, 5156, 4689, 7034, 4698, 4699 and 4663. The previous
pool was padded with false positives that made the catalogue look more complete than it is. Whole
domains of it — object-access auditing, firewall-rule lifecycle, scheduled-task lifecycle, Kerberos —
are untested by these three images.

## 2. Incident window dropped from the new retrieval path (introduced and fixed here)

The first version of the typed path filtered on `case_id` only, omitting the incident-window range
and the empty-timestamp guard that both sibling helpers apply. Records outside the declared window
rose to 57.7% on KDFS, against 49.6% in the published pool, with the most frequent date four days
before the window opens. Both guards are restored and the figure is now **28.6%**, better than the
published pool. The residual comes from anchor types that never applied a window, which is
pre-existing behaviour and is not changed here.

## 3. Indices created with a mapping the retrieval layer cannot query

`src/loaders/elasticsearch_loader.py`, `src/parsers/base.py`

Index creation applied the parser-generated mapping, which declares `timestamp` as a date. Parsers
emit `2022-02-04 05:53:33.5831587` — a space separator with seven fractional digits — which
Elasticsearch cannot parse, so under `ignore_malformed` the value was discarded in silence and the
`timestamp.keyword` sub-field that every Mode 2 anchor filters and sorts on did not exist. On such an
index all 19 `BOUNDED_ES` anchors return nothing and 15–21% of the pool disappears without an error.
Fields such as `extension` also became exact keywords, so an anchor querying `"*.ps1"` stopped
matching. Indices are now created with dynamic mapping, which is what produced every published
artefact. `ARSHALAB_EXPLICIT_ES_MAPPING=1` restores the old behaviour.

**Disclosure — this fix does not repair an existing deployment.** `create_index` returns early when
the index already exists and never inspects the mapping. Anyone whose `forensic-*` indices were built
before this change, including the authors' own working instance, still has the date mapping, and
running the released retrieval against it returns zero records for those 19 anchors. **The indices
must be dropped and rebuilt for the fix to take effect.** The results in `mode2_final/` were produced
against rebuilt indices, not against the pre-existing ones.

## 4. CSV reads truncated in silence

`src/parsers/base.py`

`_read_csv` never raised `csv.field_size_limit`. PECmd's `FilesLoaded` column exceeds Python's
131072-byte default, at which point the reader raises mid-iteration, the exception was swallowed, and
a partial list was returned. For Hunter the read stopped after 98 of 174 rows: 216 of 549 prefetch
records (57 of 130 executables) carry `run_count` 0 and empty `prefetch_hash`, `source_file` and
`files_loaded`. KDFS and Magnet were unaffected.

**Disclosure — the fix is in the parser, and the indexed data has not been re-parsed.** The current
`forensic-prefetch` documents were loaded from a SQLite snapshot (`_meta.source: "sqlite_reload"`),
so they still carry the truncated values. Correcting them requires re-parsing from the image, which
was not done. All 100 Hunter questions were checked and none depends on the lost fields, but any
future use of `run_count`, `prefetch_hash`, `source_file` or `files_loaded` on this case needs the
re-parse first.

## 5. Unearned anti-fabrication claims

`src/tools/reconstruct_attack_chain.py`, `src/llm/base_analyzer.py`, `src/mcp/server.py`

Four places asserted that chain entities are restricted to the evidence "by construction" and quoted
an evaluation result as a property of the current run. Nothing computed either claim. The tool now
measures grounding on the chain it has produced and returns a `grounding` block.

## 6. Filename regex could not cross dots in a stem

`score_timeline_mode2.py`

`jdk1.8.0_181_x64.msi` was extracted as `0_181_x64.msi`, and `backdoor.discord.exe` was checked only
as `discord.exe` — an evasion. The stem now allows dots.

---

## 7. `get_full_timeline` carried no case filter (found 5 August)

`src/llm/base_analyzer.py`

Case isolation is applied at one choke point: every tool reaches Elasticsearch through
`_es_search` or `_es_exact_search`, both of which add `case_id.keyword` to the query, and the few
tools that build a body of their own add the same term themselves. `_tool_get_full_timeline` built
its own body and was the one place the term was missing.

The indices are shared across cases and separated by that field, so on an installation holding more
than one case the tool returned whichever records sorted first regardless of which case was active.
With all three of our cases loaded and KDFS active, it returned fifty records and every one of them
belonged to the Magnet case. The published runs are unaffected because they were executed with a
single case loaded, but the guarantee stated in the paper did not hold in general.

The filter is now applied unconditionally, and all eighteen tool methods have been checked: the
other seventeen were already scoped, nine of them through the shared search helper.

---

## New: `score_fabrication_strict.py`

The existing chain scorer decides grounding by substring presence in a flattened dump that includes
the `_anchor` label, and only examines an Event ID when it belongs to a fixed 25-item list. Injection
testing showed the consequence: a fabricated Event ID is never detected, and a chain in which every
event is replaced with invented prose scores 0.00%.

The new scorer matches Event IDs against the typed `event_id` field (including those nested in `_raw`
payloads), excludes the anchor label from the comparison, widens the entity classes, **checks that
the event's date and minute occur in the evidence**, and reports events stating nothing verifiable as
a separate coverage figure rather than counting them as grounded.

Two limits are stated rather than hidden. First, the metric is computed over the events that state
something verifiable, a denominator each model influences: coverage ranges from 28% (Sonnet) to 70%
(GPT-5.1), so a model that writes vaguely is measured on less of its own output. Second, grounding
here means consistency with the retrieved evidence, not truth about the disk image; that requires an
oracle outside retrieval, which this work does not have.

## Results

| | chains | events | stating a verifiable fact | coverage | ungrounded | unsupported timestamp | composite |
|---|---|---|---|---|---|---|---|
| previously published | 36 | 1378 | 769 | 56% | 17 | 0 | 92.17% |
| this release | 36 | 1285 | 693 | 54% | **0** | **0** | 91.67% |

Under the **original** scorer, which is the one the paper reports, the number of cells with zero
hallucination across all three runs rises from **11 of 12 to 12 of 12**.

**Disclosure — the aggregate composite conceals a change of order.** Per model, published → this
release: GPT-5.1 95.21 → 94.41, Opus 4.1 91.07 → 92.03, DeepSeek V3 90.05 → 90.29, Sonnet 4.5
92.35 → 89.94. GPT-5.1 remains first, but Sonnet falls from second to fourth and Opus rises from
third to second. Reporting only the mean, as the first draft of this document did, hides that.

The zero no longer depends on any reclassification rule. `score_fabrication_strict.py` contains a
name-variant rule that treats a mistyped filename as a transcription slip when the correct name
occurs in a record at the same minute; on these 36 chains it fires **zero** times, so the reported
figure is the unmodified strict rate.

## Reference answers

Four reference answers were corrected against the case indices after verifying each against
Elasticsearch. Questions and keyword lists are unchanged.

| id | was | is |
|---|---|---|
| KDFS60 | 18 MetaMask browser records | 20 records, of which 19 carry the extension id and 17 are extension pages |
| HNT10 | 12 artifact types, 480,327 records | 11 types, 490,463 records, with the per-artifact breakdown |
| HNT36 | 549 Prefetch files | 549 Prefetch records from 208 `.pf` files, 174 parsed, 130 distinct executables |
| HNT69 | 45 executions justified by "consistent run_count across timestamps" | 45 from prefetch hash D999B1C2; the 35 index rows are run timestamps, not executions; six Chrome prefetch files exist with counts 6/40/1/7/5/45 |

HNT10's previous answer also failed its own keyword check, scoring 0.50, because the two-line form
named no artifact type.

**Disclosure — 168 reference answers were edited that night, not four.** The other 164 edits removed
first-person assistant phrasing ("Based on my analysis, I can determine…") that had been carried over
from the model transcripts the answers were originally taken from. Every edit passed a deterministic
gate comparing the extracted factual surface — paths, filenames, identifiers, timestamps, counts —
before and after, so no fact was added or lost. Backups are at
`benchmark/questions/_backup_20260731_003347/` and `_backup_20260731_020624_before_gt_text_fix/`.
Removing the phrasing does not change what the answers are: for a substantial share of questions the
reference answer originates in model output, and that is a property of the benchmark that belongs in
the paper, not in a changelog footnote.

## Known and unfixed

- **Per-provider grading keys.** `benchmark.py:226-241` prefers `<case>_<provider>.json` when it
  exists, and only `_openai` twins exist. Those twins remove a requirement in 46 questions and add
  one in none: 204/186/177 requirement slots become 186/173/159. Re-scoring GPT-5.1's saved responses
  against the common keys lowers its recall by **5.76 points** (KDFS −5.58, Magnet −1.50,
  Hunter −10.61). `docs/QA_BENCHMARK.md` states these files "do not change which facts are required",
  which is false. The Mode 1 recall table is not a like-for-like comparison until this is corrected.
- **Question-type labels.** `category` is `"retrieval"` for 600 of 600 records, and
  `benchmark.py:290` defaults a missing label to that value, so the uniform value cannot be
  distinguished from never having been labelled.
- **Keyword echo.** A verbatim restatement of the question already scores full recall on 50/18/28
  questions in the default files and 59/33/39 in the `_openai` files.
- **No tool-call traces.** No result file carries a `tool_calls` field, so the tool-boundary claim has
  no evidence behind it. The Mode 2 Claude path shells out to the CLI with
  `--dangerously-skip-permissions` and no tool restriction, so for those runs the claim that no
  provider-side tools were available cannot be made at all.
- **No run manifest.** No result records a model snapshot ID, sampling settings, library versions or
  a git revision.

## An experiment that was run and rejected

Raising every anchor limit by 1.6 restores the pool to 999–1155 records. It was rejected **on
principle, not on score**. The typed-query change is a defect fix decided from the 47.6% mislabelling
before any model was run; the multiplier was chosen after seeing a dip in the composite, to reach a
target pool size, and has no principled basis — and the target itself was whatever the defective
retrieval had happened to return. It also scored worse, composite 91.4 against 92.0, but that is a
coincidence rather than the reason. Artefacts are in `benchmark_results/mode2_final/`.
