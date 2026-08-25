"""Strict scoring of a reconstructed timeline (JSONL) against docx ground truth.

Matching rule (variant C):
  A ground-truth event is COUNTED AS FOUND only if some LLM event:
    (1) matches its timestamp anchor (same date + HH:MM), AND
    (2) shares >=1 SPECIFIC evidence keyword (generic/blacklisted tokens and
        bare short numbers do not count, except known Windows Event IDs).

Reports: recall (overall / per-phase / per-source), precision, unmatched LLM
events (possible hallucinations or extra-valid), with reasons for misses.

Usage:
  python score_timeline_jsonl.py <timeline.jsonl> <ground_truth.json>
"""
import json
import re
import sys
from collections import defaultdict
from pathlib import Path

# Generic path/word tokens that must NOT alone validate a match
GENERIC = {
    "appdata", "program files", "programdata", "windows", "system32",
    "syswow64", "users", "local", "locallow", "roaming", "temp", "desktop",
    "downloads", "documents", "pictures", "music", "videos", "update.exe",
    "exe", "dll", "txt", "log", "the", "and", "for", "with", "from",
    "google", "chrome", "microsoft", "c:", "file", "folder", "directory",
}

# Bare numbers shorter than 5 digits are ambiguous (file sizes) EXCEPT real
# Windows Event IDs commonly used in these cases.
KNOWN_EVENT_IDS = {
    "1116", "1117", "4104", "4103", "4100", "4625", "4624", "4720", "7045",
    "4672", "4647", "1102", "4688", "4648", "600", "400", "403", "410",
    "7045", "104", "1149", "21", "22", "25", "4634", "4776", "5007",
}


def is_specific(kw):
    """A keyword is 'specific' if it is not generic and not an ambiguous number."""
    k = kw.strip().lower()
    if not k or k in GENERIC:
        return False
    if k.isdigit():
        return kw in KNOWN_EVENT_IDS or len(k) >= 5
    if len(k) < 4:
        return False
    return True


def norm_ts(ts):
    """Return (date 'YYYY-MM-DD', 'HH:MM' or None)."""
    if not ts:
        return (None, None)
    ts = str(ts).replace("T", " ")
    d = re.search(r"(\d{4}-\d{2}-\d{2})", ts)
    t = re.search(r"(\d{2}:\d{2})", ts)
    return (d.group(1) if d else None, t.group(1) if t else None)


def load_jsonl(path):
    events = []
    with open(path, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                events.append(json.loads(line))
            except json.JSONDecodeError:
                continue
    return events


# Mapping anchor-query identifiers back to their artifact families.
# Forensic rationale: anchor IDs are our labels for evidence channels
# (reg_* = registry hives, auth_* = security eventlog, etc); GPT-5.1
# emits them verbatim while other models emit canonical names.
# Normalizing both to the same family enables fair source attribution.
PREFIX_MAP = {
    'reg_': 'registry',
    'auth_': 'eventlog',
    'proc_': 'eventlog',
    'svc_': 'eventlog',
    'tasks_': 'eventlog',
    'ps_': 'eventlog',
    'def_': 'eventlog',
    'fw_': 'eventlog',
    'net_': 'eventlog',
    'audit_': 'eventlog',
    'rdp_': 'eventlog',
    'usb_': 'eventlog',
    'device_': 'eventlog',
    'object_': 'eventlog',
    'file_audit_': 'eventlog',
    'wmi_': 'eventlog',
    'wer_': 'eventlog',
    'app_crashes_': 'eventlog',
    'app_hangs_': 'eventlog',
    'time_changed_': 'eventlog',
    'applocker_': 'eventlog',
    'mft_': 'mft',
    'usnjrnl_': 'mft',
    'prefetch_': 'prefetch',
    'amcache_': 'registry',
    'shimcache_': 'registry',
    'appcompatcache_': 'registry',
    'srum_': 'registry',
    'lnk_': 'lnk',
    'jumplist_': 'jumplist',
    'browser_': 'browser',
    'app_': 'browser',
}


def _normalize_source(s):
    """Map various artifact-source labels to canonical short form.
    Returns the FIRST canonical that matches as a substring; order is
    most-specific first to avoid false generic matches (e.g. 'shimcache'
    before 'cache' so it doesn't collide; 'appcompatcache' before
    'shimcache' since both refer to the same artefact). Phrase-level
    matches preferred over single-token to reduce false positives.

    After substring aliases, also tries PREFIX_MAP on the normalized
    string (e.g. 'reg_persistence_master' -> 'registry') to handle
    anchor-id identifiers emitted by some models (notably GPT-5.1)."""
    s = (s or "").lower().strip()
    aliases = [
        # MFT family (file-system metadata)
        ("$standard_information", "mft"),
        ("mft entry", "mft"),
        ("mft record", "mft"),
        ("ntfs $mft", "mft"),
        ("ntfs", "mft"),
        ("filecreate", "mft"),
        ("file system", "mft"),
        ("mft", "mft"),
        # USN Journal (NTFS change journal) — semantically equivalent to MFT
        # for attribution scoring (both are NTFS file-system metadata).
        ("usn journal", "mft"),
        ("usnjrnl", "mft"),
        ("usn_journal", "mft"),
        ("$usnjrnl", "mft"),
        ("usn:", "mft"),
        # ShimCache / Amcache / Prefetch
        # Hierarchical: shimcache and amcache live IN the registry
        # (AppCompatCache value in SYSTEM hive; Amcache.hve is a registry
        # hive). Map both to 'registry' so a chain that names the broader
        # source 'registry' still matches a GT that names the specific one
        # and vice versa.
        ("appcompatcache", "registry"),
        ("shimcache", "registry"),
        ("amcache.hve", "registry"),
        ("amcache", "registry"),
        ("prefetch", "prefetch"),
        ("jumplist", "jumplist"),
        # Registry hives
        ("ntuser.dat", "registry"),
        ("system hive", "registry"),
        ("software hive", "registry"),
        ("sam hive", "registry"),
        ("opensavepidlmru", "registry"),
        ("userassist", "registry"),
        ("usbstor", "registry"),
        ("hklm\\", "registry"),
        ("hkcu\\", "registry"),
        ("registry run key", "registry"),
        ("registry", "registry"),
        ("regedit", "registry"),
        # EventLog (Windows event logs)
        # Hierarchical: specific Windows event channels (Security, System,
        # Application, Windows Defender, PowerShell Operational) are all
        # subtypes of 'eventlog'. Map every specific channel to 'eventlog'
        # so a chain that says 'security_audit' matches a GT that says
        # 'eventlog' and vice versa.
        ("security audit", "eventlog"),
        ("security_audit", "eventlog"),
        ("security log", "eventlog"),
        ("windows defender", "eventlog"),
        ("microsoft-windows-windows defender", "eventlog"),
        ("powershell operational", "eventlog"),
        ("microsoft-windows-powershell/operational", "eventlog"),
        ("event log", "eventlog"),
        ("eventlog", "eventlog"),
        (".evtx", "eventlog"),
        ("security.evtx", "eventlog"),
        ("system.evtx", "eventlog"),
        ("application.evtx", "eventlog"),
        ("event id", "eventlog"),
        ("event 7045", "eventlog"),
        ("event 4720", "eventlog"),
        ("event 4624", "eventlog"),
        ("event 4625", "eventlog"),
        ("event 4672", "eventlog"),
        ("event 4647", "eventlog"),
        ("event 4634", "eventlog"),
        ("event 1116", "eventlog"),
        ("event 1117", "eventlog"),
        ("event 5007", "eventlog"),
        ("event 4104", "eventlog"),
        ("event 4100", "eventlog"),
        ("event 4103", "eventlog"),
        ("event 1102", "eventlog"),
        # LNK shortcuts
        ("lnk file", "lnk"),
        (" lnk", "lnk"),
        (".lnk", "lnk"),
        # Browser / web
        ("chrome localstorage", "browser"),
        ("chrome browser history", "browser"),
        ("chrome history", "browser"),
        ("browser history", "browser"),
        ("browser download", "browser"),
        ("chromium", "browser"),
        ("chrome", "browser"),
        ("firefox", "browser"),
        ("browser", "browser"),
        # SRUM (System Resource Usage Monitor) — stored in registry-format
        # ESE database (SRUDB.dat); map to 'registry' for hierarchical
        # attribution matching.
        ("srudb", "registry"),
        ("srum", "registry"),
        # PowerShell-specific
        ("powershell history", "powershell"),
        ("psreadline", "powershell"),
        ("powershell.exe", "powershell"),
    ]
    for key, canonical in aliases:
        if key in s:
            return canonical
    # Anchor-id prefix fallback (e.g. 'reg_persistence_master' -> 'registry').
    # Use longest-prefix-first to avoid 'app_' eating 'app_crashes_'/'app_hangs_'.
    for prefix in sorted(PREFIX_MAP, key=len, reverse=True):
        if s.startswith(prefix):
            return PREFIX_MAP[prefix]
    return s.split()[0] if s else "unknown"


def score(jsonl_path, gt_path):
    gt = json.load(open(gt_path, encoding="utf-8"))
    gt_events = gt["events"]
    llm_events = load_jsonl(jsonl_path)

    # index LLM events by date -> list, and (date,hhmm) -> list
    by_date = defaultdict(list)
    by_dt = defaultdict(list)
    for i, e in enumerate(llm_events):
        d, t = norm_ts(e.get("timestamp", ""))
        if d:
            by_date[d].append(i)
            if t:
                by_dt[(d, t)].append(i)

    matched_gt = []
    missed = []
    matched_llm_idx = set()
    # (gt_id, llm_idx) pairs in order of GT iteration, used by ordering
    # accuracy and source attribution metrics.
    match_pairs = []

    for ev in gt_events:
        gid = ev["id"]
        d, t = norm_ts(ev.get("timestamp", ""))
        kws = [k for k in ev.get("evidence_keywords", []) if is_specific(k)]

        if not d:
            missed.append((gid, "gt_no_timestamp"))
            continue

        # candidate LLM events: same date+HH:MM if GT has time, else same date
        if t:
            cands = by_dt.get((d, t), [])
            if not cands:
                # widen ±1 min tolerance
                hh, mm = t.split(":")
                for dm in (-1, 1):
                    tt = f"{int(hh):02d}:{(int(mm)+dm) % 60:02d}"
                    cands += by_dt.get((d, tt), [])
        else:
            cands = by_date.get(d, [])

        if not cands:
            missed.append((gid, "timestamp_not_in_llm_timeline"))
            continue

        # need a specific keyword to appear in a candidate's text
        hit_ci = None
        for ci in cands:
            blob = json.dumps(llm_events[ci], ensure_ascii=False).lower()
            if not kws:
                # no specific kw available -> timestamp match alone (weak) counts
                hit_ci = ci
                break
            if any(k.lower() in blob for k in kws):
                hit_ci = ci
                break

        if hit_ci is not None:
            matched_gt.append(gid)
            matched_llm_idx.add(hit_ci)
            match_pairs.append((gid, hit_ci))
        else:
            missed.append((gid, "timestamp_ok_but_no_specific_keyword"))

    total = len(gt_events)
    recall = len(matched_gt) / total if total else 0

    # per-phase / per-source recall.
    # attack_chain_gt uses 'source_artifact' + 'mitre_tactic'; docx uses
    # 'source' + 'phase'. Accept either.
    phase_tot, phase_hit = defaultdict(int), defaultdict(int)
    src_tot, src_hit = defaultdict(int), defaultdict(int)
    for ev in gt_events:
        ph = ev.get("phase", ev.get("mitre_tactic", "?"))
        sr = ev.get("source", ev.get("source_artifact", "?"))
        phase_tot[ph] += 1
        src_tot[sr] += 1
        if ev["id"] in matched_gt:
            phase_hit[ph] += 1
            src_hit[sr] += 1

    unmatched_llm = [i for i in range(len(llm_events)) if i not in matched_llm_idx]
    precision = len(matched_llm_idx) / len(llm_events) if llm_events else 0

    miss_reasons = defaultdict(int)
    for _, r in missed:
        miss_reasons[r] += 1

    # ------------------ ordering accuracy ------------------
    # For each pair (a, b) of matched GT events with ts(a) < ts(b),
    # check whether the LLM's matched-event timestamps preserve the order.
    # Concordant pairs / total comparable pairs = ordering accuracy.
    # Pairs where GT timestamps are equal (ties) or unparseable are skipped.
    gt_by_id = {e["id"]: e for e in gt_events}
    pair_records = []
    for gid, lidx in match_pairs:
        ge = gt_by_id[gid]
        le = llm_events[lidx]
        gd, gt_ = norm_ts(ge.get("timestamp", ""))
        ld, lt_ = norm_ts(le.get("timestamp", ""))
        # build sortable (date, hh:mm) tuple; missing parts default to '00:00'
        if not gd or not ld:
            continue
        pair_records.append((
            gid, lidx,
            f"{gd} {gt_ or '00:00'}", f"{ld} {lt_ or '00:00'}",
        ))
    concordant = discordant = 0
    for i in range(len(pair_records)):
        for j in range(i + 1, len(pair_records)):
            gi, _, gti, lti = pair_records[i]
            gj, _, gtj, ltj = pair_records[j]
            if gti == gtj:
                continue  # tie in GT — skip
            gt_order = gti < gtj
            if lti == ltj:
                discordant += 1   # LLM lost the ordering distinction
                continue
            llm_order = lti < ltj
            if gt_order == llm_order:
                concordant += 1
            else:
                discordant += 1
    total_pairs = concordant + discordant
    ordering_accuracy = concordant / total_pairs if total_pairs else None

    # ------------------ source attribution correctness ------------------
    # For each matched (GT, LLM) pair, compare normalised source strings.
    attr_total = attr_correct = 0
    per_src_attr_total = defaultdict(int)
    per_src_attr_correct = defaultdict(int)
    for gid, lidx in match_pairs:
        ge = gt_by_id[gid]
        le = llm_events[lidx]
        gs = _normalize_source(ge.get("source", ge.get("source_artifact", "")))
        ls = _normalize_source(le.get("artifact_type", le.get("source", "")))
        attr_total += 1
        per_src_attr_total[gs] += 1
        if gs == ls or (gs and ls and (gs in ls or ls in gs)):
            attr_correct += 1
            per_src_attr_correct[gs] += 1
    source_attribution = attr_correct / attr_total if attr_total else None

    return {
        "ground_truth": str(gt_path),
        "timeline": str(jsonl_path),
        "gt_total_events": total,
        "llm_total_events": len(llm_events),
        "matched": len(matched_gt),
        "recall": round(recall, 4),
        "precision_vs_gt": round(precision, 4),
        "unmatched_llm_events": len(unmatched_llm),
        "ordering_accuracy": round(ordering_accuracy, 4) if ordering_accuracy is not None else None,
        "ordering_pairs_total": total_pairs,
        "ordering_pairs_concordant": concordant,
        "source_attribution_accuracy": round(source_attribution, 4) if source_attribution is not None else None,
        "source_attribution_correct": attr_correct,
        "source_attribution_total": attr_total,
        "per_source_attribution": {
            s: f"{per_src_attr_correct[s]}/{per_src_attr_total[s]}"
            for s in sorted(per_src_attr_total)
        },
        "miss_reasons": dict(miss_reasons),
        "per_phase_recall": {
            ph: f"{phase_hit[ph]}/{phase_tot[ph]}" for ph in sorted(phase_tot)
        },
        "per_source_recall": {
            sr: f"{src_hit[sr]}/{src_tot[sr]}" for sr in sorted(src_tot)
        },
        "matched_ids": sorted(matched_gt),
        "missed": missed,
    }


def main():
    if len(sys.argv) < 3:
        print("usage: python score_timeline_jsonl.py <timeline.jsonl> <ground_truth.json>")
        sys.exit(1)
    rep = score(sys.argv[1], sys.argv[2])
    out = Path(sys.argv[1]).with_suffix(".score.json")
    with open(out, "w", encoding="utf-8") as f:
        json.dump(rep, f, indent=2, ensure_ascii=False)

    print(f"\n{'='*60}")
    print(f"TIMELINE SCORE")
    print(f"{'='*60}")
    print(f"GT events      : {rep['gt_total_events']}")
    print(f"LLM events     : {rep['llm_total_events']}")
    print(f"Matched        : {rep['matched']}")
    print(f"RECALL              : {rep['recall']*100:.1f}%")
    print(f"Precision vs GT     : {rep['precision_vs_gt']*100:.1f}%")
    print(f"Unmatched LLM  : {rep['unmatched_llm_events']} (extra-valid or hallucination)")
    if rep.get("ordering_accuracy") is not None:
        print(f"ORDERING ACCURACY   : {rep['ordering_accuracy']*100:.1f}%  "
              f"({rep['ordering_pairs_concordant']}/{rep['ordering_pairs_total']} pairs concordant)")
    if rep.get("source_attribution_accuracy") is not None:
        print(f"SOURCE ATTRIBUTION  : {rep['source_attribution_accuracy']*100:.1f}%  "
              f"({rep['source_attribution_correct']}/{rep['source_attribution_total']} matches)")
    print(f"Miss reasons   : {rep['miss_reasons']}")
    print(f"\nPer-source recall:")
    for sr, v in rep["per_source_recall"].items():
        print(f"  {sr:14s} {v}")
    print(f"\nPer-source attribution:")
    for sr, v in rep.get("per_source_attribution", {}).items():
        print(f"  {sr:14s} {v}")
    print(f"\nReport -> {out}")


if __name__ == "__main__":
    main()
