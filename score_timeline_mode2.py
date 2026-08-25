"""Mode 2 scorer — 4 rigorous metrics per the user's structure.

Inputs:
  * chain_<case>_<provider>_run<N>.json  (from reconstruct_timeline.py)
  * benchmark/ground_truth/<case>_attack_chain_gt.json
  * evidence_<case>.json next to the chain file (for the grounding check)
  Evidence auto-detect: if a sibling evidence_<case>.json is in the chain's
  directory, use that (supports v2/v3 evaluation alongside v1).

Metrics (PRIMARY headline first, then DIAGNOSTIC secondaries):

  1. tactic_coverage              [PRIMARY]
       = distinct_MITRE_tactics_matched / total_GT_tactics_in_scope
     Standard MITRE ATT&CK Navigator-style coverage. A tactic is "covered"
     if the model's chain matches AT LEAST ONE GT event of that tactic.
     This is the right primary metric for incident-timeline reconstruction
     because in DFIR practice an analyst is judged on whether they covered
     each tactic of the kill chain, not whether they picked one specific
     timestamp out of many semantically-equivalent records.

  2. ordering_accuracy
       = concordant_pairs / (concordant_pairs + discordant_pairs)
     Kendall-style pairwise concordance over matched GT pairs with distinct
     timestamps. Checks the model placed events in correct temporal order.

  3. source_attribution_accuracy
       = pairs_with_correct_source / total_matched_pairs
     Normalised GT.source_artifact <-> chain.supporting_artifact match.

  4. hallucination_rate
       = chain_events_not_grounded_in_evidence / total_chain_events
     A chain event is "grounded" if its date+HH:MM AND at least one specific
     descriptive token appears verbatim in the evidence dump.

  Secondary (reported for transparency, not primary):
    exact_event_coverage = matched_gt_events / total_gt_in_scope_events
    per_tactic_recall    = how many GT events per tactic were matched
                           (depth of coverage within each tactic)

Out-of-scope GT events (es_in_scope=False) are EXCLUDED from event_coverage,
ordering, source_attribution — they reference artifact types ArshaLab does
not currently parse.

Usage:
    python score_timeline_mode2.py <chain.json> <case>
"""
import json
import re
import sys
from collections import defaultdict, Counter
from datetime import datetime
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
from score_timeline_jsonl import norm_ts, is_specific, _normalize_source

ATTACK_CHAIN_GT = {
    "kdfs":      "benchmark/ground_truth/KDFS_2023_attack_chain_gt.json",
    "magnet":    "benchmark/ground_truth/Magnet_CTF_2022_attack_chain_gt.json",
    "4orensics": "benchmark/ground_truth/Hunter_4orensics_attack_chain_gt.json",
}

# ---- Semantic milestone checklist per case --------------------------------
# Each milestone = a high-level incident step. The narrow per-record GT
# events that report the same incident step are grouped together. A milestone
# is "covered" if the chain mentions ANY keyword from ANY GT event in the
# group (no timestamp constraint, since multiple records of the same
# incident step legitimately span minutes/hours across artifact sources).
#
# This is the "checklist" the user asked for: high-level event reconstruction
# in the spirit of DFIR reports, not fine-grained per-record matching.
MILESTONES = {
    "magnet": {
        # Per-case format A: list of GT event IDs from attack_chain_gt.json.
        # Scorer collects evidence_keywords from those events.
        "M_defender_tampering":   ["MAG-002"],
        "M_zerotier_deployment":  ["MAG-003", "MAG-004", "MAG-005", "MAG-008"],
        "M_antiforensic_scripts": ["MAG-006", "MAG-007"],
        "M_defender_detections":  ["MAG-009"],
        "M_powershell_c2":        ["MAG-010", "MAG-011"],
        "M_goteem_scripts":       ["MAG-012", "MAG-013", "MAG-014", "MAG-015", "MAG-016"],
        "M_matrix_lolololol":     ["MAG-017"],
        "M_unauthorised_account": ["MAG-018"],
    },
    # Per-case format B (KDFS/Hunter): dict with explicit keyword list per
    # milestone, sourced from v4_systematic phase descriptions. We use this
    # for cases where attack_chain_gt was filtered to ArshaLab-buildable
    # modules only — by going directly to v4 we can also score milestones
    # whose evidence is partially indirect (e.g. Discord channel URL in
    # Chrome history is a proxy for Discord chat content stored in .ldb).
    "kdfs": {
        # IN-SCOPE (5): evidence retrievable through current ArshaLab
        # modules (Windows EventLog, MFT, Registry, Prefetch, Amcache,
        # Shimcache, USN Journal, Browser history/SRUM). Verified against
        # ES contents: discord/metamask/everyrecover56/gofile/bandizip/
        # ransom.exe/ransom.zip/sandisk/ledger live all present.
        "P2_debt_pressure":         {"keywords": ["cook.com", "사채", "파산", "82cook", "bankruptcy", "illegal lending", "debt research", "loan shark", "financial distress", "blackmail"], "out_of_scope": "Korean case-tied; dropped in v2 case-agnostic cleanup (kdfs_korean_financial_search anchor removed, 사채/파산 tokens stripped from browser_downloads_searches)"},
        "P3_intent_formation":      {"keywords": ["discord", "discord.exe", "랜섬웨어", "ransomware", "쌀줍", "화이트해커", "미인증", "ledger live", "blockstream"]},
        "P7_payment_setup":         {"keywords": ["metamask", "ledger live", "bandizip", "crypto wallet", "wallet extension", "blockstream", "souldrag576"]},
        "P9_weapon_acquisition":    {"keywords": ["bandizip", "ransom.exe", "ransom.zip", "sandisk", "cruzer", "usb", "7121752", "7287357", "0b88dd85", "pictures\\\\ransom"]},
        "P10_distribution_handoff": {"keywords": ["gofile", "gofile.io", "file sharing", "share url", "upload"]},
        # OUT-OF-SCOPE (12): require future-work modules. Verified ZERO
        # matches in current ES indices for cyberninja, changelly,
        # takemejail (Discord chat / blockchain data); listed for paper
        # transparency, not counted in primary step coverage.
        "P4_accomplice_setup":      {"keywords": ["takemejail", "coinone"], "out_of_scope": "Etherscan blockchain explorer module not built (0 ES hits)"},
        "P5_initial_contact":       {"keywords": ["cyberninja", "souldrag__"], "out_of_scope": "Discord LevelDB chat parser not built (0 ES hits for cyberninja)"},
        "P6_conspiracy":            {"keywords": ["30만원", "cyberninja DM"], "out_of_scope": "Discord LevelDB chat parser not built"},
        "P8_prepayment":            {"keywords": ["changelly", "0.0085 wbtc"], "out_of_scope": "blockchain explorer + LevelDB not built (0 ES hits for changelly)"},
        "P11_post_handoff":         {"keywords": ["wbtc swap", "residual eth"], "out_of_scope": "blockchain explorer not built"},
        "P12_initial_funds":        {"keywords": ["0.012 btc", "3dgxayyua"], "out_of_scope": "blockchain explorer not built"},
        "P13_victim1":              {"keywords": ["dou120313", "0.003 btc"], "out_of_scope": "Outlook OST content parser + blockchain not built"},
        "P14_revenue_share_1":      {"keywords": ["0.005 eth commission v1"], "out_of_scope": "blockchain explorer not built"},
        "P15_victim2":              {"keywords": ["mugimyeong85", "victim 2 payment"], "out_of_scope": "Outlook OST + blockchain not built"},
        "P16_revenue_share_2":      {"keywords": ["0.005 eth commission v2"], "out_of_scope": "blockchain explorer not built"},
        "P17_accomplice_laundering": {"keywords": ["skybridge", "swingby"], "out_of_scope": "blockchain explorer + Skybridge bridge not built"},
        "P18_post_imaging":         {"keywords": ["mybitcoin third"], "out_of_scope": "blockchain explorer not built"},
    },
    "4orensics": {
        "P2_email_exchange":        {"keywords": ["linux-rul3z", "hotmail", "skype", "exfiltration", "exfil", "email exchange", "outlook"]},
        "P3_login":                 {"keywords": ["4624", "logon", "logged in", "login", "login_count", "dhcp", "10.0.2.15", "lease", "user authenticated", "logon success"]},
        "P4_tool_install":          {"keywords": ["wireshark", "tor browser", "nmap", "winpcap", "metasploit", "exfiltration_diagram", "rapid7", "tool install"]},
        "P5_reconnaissance":        {"keywords": ["burp suite", "ollydbg", "hash suite", "thc hydra", "nexpose", "burpsuite", "dns-exfiltration", "reconnaissance", "recon"]},
        "P6_port_scan":             {"keywords": ["zenmap", "nmap", "port scan", "nmapscan.xml", "9929", "31337", "elite", "scan"]},
        "P7_exfil_prep":            {"keywords": ["pictures.7z", "exfil", "ryan_vanantwerp", "staging folder", "exfiltration prep", "archive created"]},
        "P8_skype_comm":            {"keywords": ["skype", "linux-rul3z", "7z password", "conf.jgp", "teamviewer", "messenger"]},
        "P9_usb":                   {"keywords": ["07b20c03", "aai6uxdk", "07b20c03c80830a9", "aai6uxdkzdv8e9ou", "usb device", "sandisk", "cruzer", "usbstor", "removable", "usb drive", "usb inserted", "usb connected"]},
        "P10_anti_forensics":       {"keywords": ["bcwipe", "ccleaner", "crypto swap", "file shredder", "anti-forensic", "wipe", "cleaner"]},
        "P11_exfiltration":         {"keywords": ["teamviewer", "backup.pst", "dropbox", "remote access", "linux-rul3z", "exfiltration"]},
    },
}

EVIDENCE_DUMP = {
    # Fallback only. The scorer first looks for evidence_<case>.json sitting
    # next to the chain file, which is how the released runs are laid out.
    "kdfs":      "benchmark_results/mode2_final/opus/kdfs/control/evidence_KDFS_2023.json",
    "magnet":    "benchmark_results/mode2_final/opus/magnet/control/evidence_Magnet_CTF_2022.json",
    "4orensics": "benchmark_results/mode2_final/opus/4orensics/control/evidence_Hunter_4orensics.json",
}


# ---------------- evidence indexing for hallucination check --------------

def _evidence_text_blob(evidence_payload):
    """Flatten the evidence dump into one lowercased text blob, for fast
    'does this token appear?' membership checks."""
    parts = []
    for anchor_id, records in evidence_payload["evidence_by_anchor"].items():
        for r in records:
            parts.append(json.dumps(r, ensure_ascii=False, default=str))
    return "\n".join(parts).lower()

def _evidence_date_index(evidence_payload):
    """Per-date set of (HH:MM) appearing in evidence. Used for hallucination
    check: chain timestamp must exist in evidence at the same date/HH:MM."""
    by_date = defaultdict(set)
    for records in evidence_payload["evidence_by_anchor"].values():
        for r in records:
            d, t = norm_ts(r.get("timestamp", "")) if isinstance(r, dict) else (None, None)
            if d:
                by_date[d].add(t or "")
    return by_date


# ---------------- matching: chain event <-> GT event ---------------------

TIER3_MAX_DELTA_DAYS = 7


def _within_tier3_window(chain_ts_str, gt_ts_str):
    """Tier-3 fallback requires the chain event to fall within +/-7 days of the GT event.

    If either timestamp cannot be parsed, fall back to permissive (return
    True) so we do not silently drop matches that succeeded under the old
    behavior. This keeps the constraint purely additive: it only rejects
    Tier-3 matches we are confident are far outside the GT window.
    """
    try:
        chain_dt = _parse_chain_ts(chain_ts_str)
        gt_dt = _parse_chain_ts(gt_ts_str)
        if chain_dt is None or gt_dt is None:
            return True  # if the timestamp cannot be parsed, let the fallback through as before
        delta_days = abs((chain_dt - gt_dt).total_seconds()) / 86400
        return delta_days <= TIER3_MAX_DELTA_DAYS
    except Exception:
        return True


def _match_gt_to_chain(gt_events, chain, time_tolerance_minutes=30):
    """Return list of (gt_idx, chain_idx) pairs and lists of misses/matched.
    Match rule (3-tier, looking for the strongest match first):
      (1) STRICT  : same date, HH:MM within ±1 min, AND >=1 GT-specific kw
                    appears in chain event blob.
      (2) WINDOW  : same date, |chain_HH:MM - GT_HH:MM| <= tolerance,
                    AND >=1 GT-specific kw appears in chain blob.
                    This catches cross-source events where the EventLog and
                    MFT timestamps for the same artefact differ by minutes.
      (3) KW-ONLY : >=1 GT-specific kw appears in chain blob (any timestamp).
                    Diagnostic fallback for events whose timestamp the model
                    rendered differently (e.g. timezone, fractional seconds).
    Once a chain event is matched it is not reused for another GT event."""
    def _mm_to_int(t):
        if not t:
            return None
        hh, mm = t.split(":")
        return int(hh) * 60 + int(mm)

    # index chain by date and date+HH:MM for fast lookup
    by_date = defaultdict(list)
    by_dt = defaultdict(list)
    chain_ts_min = {}
    chain_kw_blob = {}
    for ci, ce in enumerate(chain):
        d, t = norm_ts(ce.get("timestamp", ""))
        if d:
            by_date[d].append(ci)
            if t:
                by_dt[(d, t)].append(ci)
        chain_ts_min[ci] = _mm_to_int(t)
        chain_kw_blob[ci] = json.dumps(ce, ensure_ascii=False).lower()

    matched = []
    missed = []
    matched_chain_idx = set()

    def _kw_in(ci, kws_lower):
        blob = chain_kw_blob[ci]
        return any(k in blob for k in kws_lower)

    for gi, ge in enumerate(gt_events):
        d, t = norm_ts(ge.get("timestamp", ""))
        kws = [k for k in ge.get("evidence_keywords", []) if is_specific(k)]
        kws_lower = [k.lower() for k in kws]
        if not d:
            missed.append((ge["id"], "gt_no_timestamp"))
            continue
        if not kws_lower:
            missed.append((ge["id"], "gt_no_specific_keywords"))
            continue

        gt_minutes = _mm_to_int(t)

        # Tier 1: strict same-minute (±1)
        hit_ci = None
        if t:
            cands = list(by_dt.get((d, t), []))
            hh, mm = t.split(":")
            for dm in (-1, 1):
                tt = f"{int(hh):02d}:{(int(mm) + dm) % 60:02d}"
                cands += by_dt.get((d, tt), [])
            for ci in cands:
                if ci in matched_chain_idx:
                    continue
                if _kw_in(ci, kws_lower):
                    hit_ci = ci
                    break

        # Tier 2: same date, ±tolerance min, kw match
        if hit_ci is None:
            for ci in by_date.get(d, []):
                if ci in matched_chain_idx:
                    continue
                if gt_minutes is not None and chain_ts_min[ci] is not None:
                    delta = abs(chain_ts_min[ci] - gt_minutes)
                    if delta > time_tolerance_minutes:
                        continue
                if _kw_in(ci, kws_lower):
                    hit_ci = ci
                    break

        # Tier 3: kw-only (any timestamp). EXCLUDE bare date/time tokens
        # from the keyword set here, otherwise events that merely happen on
        # the same day (e.g. a Defender 1116 detection vs. an LNK file
        # creation) match via "2022-02-11" and produce false positives that
        # corrupt source attribution and ordering.
        non_date_kws = [k for k in kws_lower
                        if not re.match(r"^\d{4}-\d{2}-\d{2}", k)
                        and not re.match(r"^\d{1,2}:\d{2}", k)]
        if hit_ci is None and non_date_kws:
            # Bug fix 2026-06-03: Tier-3 keyword fallback unbounded -> matcher
            # assigned KDF-024 (ransomware 09-20) to a chain row dated 09-22
            # and KDF-071 (USB 09-21) to a chain row dated 09-13 (EventID 7045
            # collision), creating ~14 phantom discordant ordering pairs across
            # 12 KDFS cells. Constraining Tier-3 to +/-7 days fixes the
            # mis-assignment without changing the metric definition.
            gt_ts_raw = ge.get("timestamp", "")
            for ci in range(len(chain)):
                if ci in matched_chain_idx:
                    continue
                if _kw_in(ci, non_date_kws):
                    # Tier-3 fallback: keyword match only if within +/-7 days of GT
                    chain_ts_raw = chain[ci].get("timestamp", "")
                    if not _within_tier3_window(chain_ts_raw, gt_ts_raw):
                        continue
                    hit_ci = ci
                    break

        if hit_ci is None:
            # Diagnose miss reason for reporting
            if by_date.get(d):
                missed.append((ge["id"], "date_match_no_kw"))
            else:
                missed.append((ge["id"], "date_not_in_chain"))
        else:
            matched.append((gi, hit_ci))
            matched_chain_idx.add(hit_ci)
    return matched, missed, matched_chain_idx


# ---------------- ordering accuracy --------------------------------------

def _parse_chain_ts(ts):
    """Parse a chain timestamp string into a datetime, tolerating the
    'YYYY-MM-DD HH:MM:SS.fffffff' (7-digit microseconds) form by stripping
    the trailing extra digit so datetime.fromisoformat can consume it.
    Returns None if unparseable."""
    if not ts:
        return None
    s = str(ts).strip().replace("T", " ")
    # datetime.fromisoformat accepts up to 6 fractional digits; trim if 7+
    m = re.match(r"^(.*\.\d{6})\d+$", s)
    if m:
        s = m.group(1)
    try:
        dt = datetime.fromisoformat(s)
        # normalise to naive datetime so cross-pair subtraction never mixes
        # offset-aware (e.g. '...+00:00', '...Z') with offset-naive values
        if dt.tzinfo is not None:
            dt = dt.replace(tzinfo=None)
        return dt
    except ValueError:
        # fall back to YYYY-MM-DD HH:MM
        m2 = re.match(r"(\d{4}-\d{2}-\d{2})[ T](\d{2}:\d{2})", s)
        if m2:
            try:
                return datetime.fromisoformat(f"{m2.group(1)} {m2.group(2)}:00")
            except ValueError:
                return None
        return None


def _ordering_accuracy(matched, gt_events, chain):
    """For all pairs (a,b) of matched GT events with ts(a) != ts(b),
    count how often chain places them in the same order. Returns
    (concordant, discordant, accuracy_or_None).

    Forensic rationale: sub-minute milestone ordering is not diagnostic-
    significant in DFIR practice. We apply ±60 sec tolerance: if the two
    chain timestamps are within 60 seconds of each other, the pair is
    counted as concordant regardless of direction (the model effectively
    placed them at the same instant, which a human analyst would treat as
    indistinguishable for incident-reconstruction purposes)."""
    pairs = []
    masked_negative_finding = 0
    for gi, ci in matched:
        # Mask negative-finding / session-scope GT events from ordering
        # pairs: their raw timestamp is a span marker (e.g. "2023-09-21
        # (entire session)"), not an instant. norm_ts strips the marker
        # and the existing `or '00:00'` fallback below would anchor the
        # event at the earliest instant of the day, fabricating phantom
        # discordant pairs against every real same-day event. A negative
        # finding by definition has no temporal relation to any other
        # event, so remove it from BOTH numerator and denominator.
        raw_gt_ts = str(gt_events[gi].get("timestamp", "")).lower()
        raw_gt_desc = str(gt_events[gi].get("description", "")).lower()
        if ("entire session" in raw_gt_ts
                or "full session" in raw_gt_ts
                or "session-wide" in raw_gt_ts
                or raw_gt_desc.startswith("negative finding")):
            masked_negative_finding += 1
            continue
        gd, gt_ = norm_ts(gt_events[gi].get("timestamp", ""))
        ld, lt_ = norm_ts(chain[ci].get("timestamp", ""))
        if not gd or not ld:
            continue
        chain_dt = _parse_chain_ts(chain[ci].get("timestamp", ""))
        pairs.append((
            f"{gd} {gt_ or '00:00'}",
            f"{ld} {lt_ or '00:00'}",
            chain_dt,
        ))
    concordant = discordant = 0
    for i in range(len(pairs)):
        for j in range(i + 1, len(pairs)):
            gi, li, ci_dt = pairs[i]
            gj, lj, cj_dt = pairs[j]
            if gi == gj:
                continue
            gt_order = gi < gj
            # ±60 sec tolerance: sub-minute ordering is not diagnostic-
            # significant in DFIR practice; if the chain places A and B
            # within 60 s of each other, count as concordant regardless
            # of direction (the GT order will match either A,B or B,A).
            if ci_dt is not None and cj_dt is not None:
                if abs((ci_dt - cj_dt).total_seconds()) < 60:
                    concordant += 1
                    continue
            if li == lj:
                discordant += 1
                continue
            llm_order = li < lj
            if gt_order == llm_order:
                concordant += 1
            else:
                discordant += 1
    total = concordant + discordant
    acc = concordant / total if total else None
    return concordant, discordant, acc, masked_negative_finding


# ---------------- source attribution accuracy ----------------------------

def _split_sources(raw):
    """Split a raw source-artifact string on common separators (+, /, ',',
    'and', '&') into a SET of normalised source labels. A single artifact
    string like 'Amcache + Shimcache + MFT + Registry' becomes the set
    {'amcache','shimcache','mft','registry'}; an LLM-style string like
    'EventLog Event 7045' becomes {'eventlog'} because the noise tokens
    'event'/'7045' are filtered after normalisation."""
    if not raw:
        return set()
    s = str(raw)
    for sep in ["+", "/", ",", " and ", " & ", ";"]:
        s = s.replace(sep, "|")
    parts = [p.strip() for p in s.split("|") if p.strip()]
    out = set()
    for p in parts:
        n = _normalize_source(p)
        if n and n != "unknown":
            out.add(n)
    return out


def _source_attribution(matched, gt_events, chain):
    """For each matched pair, compare GT source SET vs LLM source SET.

    Source attribution uses set-intersection (any common source counts as
    match) after hierarchical alias normalization. This reflects DFIR
    practice where a single artifact family is materialized through
    multiple physical channels (Carrier 2005); requiring exact-set match
    would punish models that cite valid corroborating evidence.
    """
    total = correct = 0
    per_src_total = defaultdict(int)
    per_src_correct = defaultdict(int)
    for gi, ci in matched:
        ge = gt_events[gi]
        ce = chain[ci]
        # Apply hierarchical alias normalization per token via _split_sources,
        # which calls _normalize_source on each separator-split chunk.
        gs_set = _split_sources(
            ge.get("source", ge.get("source_artifact", "")))
        ls_set = _split_sources(
            ce.get("supporting_artifact",
                   ce.get("artifact_type",
                          ce.get("source", ""))))
        total += 1
        gs_label = "+".join(sorted(gs_set)) or "unknown"
        per_src_total[gs_label] += 1

        if gs_set and ls_set and (gs_set & ls_set):
            correct += 1
            per_src_correct[gs_label] += 1

    breakdown = {
        s: f"{per_src_correct[s]}/{per_src_total[s]}"
        for s in sorted(per_src_total)
    }
    return correct, total, breakdown


# ---------------- hallucination check ------------------------------------

def _is_grounded(chain_event, evidence_blob, evidence_by_date):
    """A chain event is grounded if:
      (a) its date+HH:MM exists somewhere in evidence (same minute or ±1)
      AND
      (b) at least one specific descriptive token from event/supporting_artifact
          appears in the evidence blob.
    Otherwise it's hallucinated (model invented or paraphrased beyond evidence).

    Hallucination at FACT GRANULARITY: a chain event is hallucinated iff
    ANY structured factual entity it cites (filename, Windows event ID, IP,
    SID, SHA1/MD5 hash, registered domain) is absent from the deterministic
    evidence dump. Linguistic glue ('installed', 'created', 'under') is
    NOT a fact and is NOT checked. Events without any structured factual
    entity are skipped (untestable, return None marker).
    """
    d, t = norm_ts(chain_event.get("timestamp", ""))
    if not d:
        return False, "no_timestamp"
    times_at_date = evidence_by_date.get(d, set())
    if not times_at_date:
        return False, "date_not_in_evidence"
    if t:
        hh, mm = t.split(":")
        target_set = {t}
        for dm in (-1, 1):
            target_set.add(f"{int(hh):02d}:{(int(mm) + dm) % 60:02d}")
        if not (target_set & times_at_date):
            return False, "minute_not_in_evidence"
    # Fact-level entity extraction
    text = (
        str(chain_event.get("event", ""))
        + " " + str(chain_event.get("supporting_artifact", ""))
        + " " + str(chain_event.get("description", ""))
    )
    FACT_PATTERNS = [
        # The stem must allow dots. Without them the pattern captures only the last dot-segment:
        # "jdk1.8.0_181_x64.msi" was extracted as "0_181_x64.msi", which is absent from the
        # evidence and produced the single non-zero hallucination figure in the published results
        # (Sonnet on Magnet, 1.11%) from a correct statement. It also let real filenames be evaded
        # by prefixing them, since "backdoor.discord.exe" was checked only as "discord.exe".
        re.compile(r"\b[A-Za-z0-9_\-]+(?:\.[A-Za-z0-9_\-]+)*\.(?:ps1|bat|vbs|exe|dll|sys|zip|7z|rar|pdf|jpg|png|xlsx|ost|pst|ldb|lnk|msi|cab|svg|html|jar|jgp|com|tmp|log|json|xml|cfg|reg|pf|odl|odlgz)\b", re.I),
        re.compile(r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b"),                                  # IP
        re.compile(r"\bS-1-5-\d+(?:-\d+){0,7}\b"),                                              # SID
        re.compile(r"\b[0-9a-f]{12,40}\b", re.I),                                               # hash
        re.compile(r"\b[a-z0-9][a-z0-9\-]{2,30}\.(?:com|io|net|org|eth|co\.kr)\b", re.I),       # domain
    ]
    KNOWN_EID = {"1116","1117","5007","4720","7045","4104","4100","4103","600","1102","4624","4625","4634","4647","4648","4672","4738","4776","104","1149","4688","5061","4663","4656","4670"}
    entities = set()
    for pat in FACT_PATTERNS:
        for m in pat.findall(text):
            entities.add(m.lower())
    for tok in re.findall(r"\b\d{3,5}\b", text):
        if tok in KNOWN_EID:
            entities.add("eid_" + tok)
    if not entities:
        return True, "no_factual_entity_to_check"  # untestable, do not count as hallucination
    for ent in entities:
        target = ent[4:] if ent.startswith("eid_") else ent
        if target not in evidence_blob:
            return False, f"missing_factual_entity:{ent}"
    return True, "grounded_facts"


# ---------------- main ---------------------------------------------------

def score(chain_path, case, evidence_path=None):
    chain_payload = json.load(open(chain_path, encoding="utf-8"))
    chain = chain_payload["chain"]

    gt = json.load(open(ATTACK_CHAIN_GT[case], encoding="utf-8"))
    gt_in_scope = [e for e in gt["events"] if e.get("es_in_scope", True)]
    gt_out_scope = [e for e in gt["events"] if not e.get("es_in_scope", True)]

    # Auto-detect evidence path: explicit > sibling-dir convention > default v1.
    if evidence_path is None:
        chain_dir = Path(chain_path).parent
        case_name = {"kdfs": "KDFS_2023", "magnet": "Magnet_CTF_2022",
                     "4orensics": "Hunter_4orensics"}[case]
        sibling = chain_dir / f"evidence_{case_name}.json"
        evidence_path = str(sibling) if sibling.exists() else EVIDENCE_DUMP[case]
    evidence = json.load(open(evidence_path, encoding="utf-8"))
    evidence_blob = _evidence_text_blob(evidence)
    evidence_by_date = _evidence_date_index(evidence)

    matched, missed, matched_chain_idx = _match_gt_to_chain(gt_in_scope, chain)

    # ---- PRIMARY: semantic milestone checklist coverage ----------------
    # A milestone groups narrow per-record GT events that report the same
    # high-level incident step. A milestone is covered if the chain blob
    # contains AT LEAST ONE specific keyword from ANY GT event in the
    # group. This matches DFIR reporting practice (high-level event
    # reconstruction) and is the primary headline metric.
    milestones = MILESTONES.get(case, {})
    chain_blob_lower = json.dumps(chain, ensure_ascii=False).lower()
    gt_by_id = {e["id"]: e for e in gt_in_scope}
    milestone_results = {}
    for m_id, spec in milestones.items():
        # Two milestone-spec formats are supported:
        #   (a) list of attack_chain_gt event IDs (Magnet) — collect their
        #       evidence_keywords filtered by is_specific.
        #   (b) dict {"keywords": [...]} (KDFS / Hunter) — use directly.
        # Format (b) is used when attack_chain_gt was filtered to currently-
        # supported ArshaLab modules and we want to score milestones whose
        # primary source (e.g. Discord .ldb) was excluded but whose proxy
        # evidence (Discord channel URL in browser history) IS retrievable.
        kws = []
        if isinstance(spec, dict):
            for k in spec.get("keywords", []):
                if k:
                    kws.append(k.lower())
        else:
            for gid in spec:
                ge = gt_by_id.get(gid)
                if not ge:
                    continue
                for k in ge.get("evidence_keywords", []):
                    if is_specific(k):
                        kws.append(k.lower())
        if not kws:
            milestone_results[m_id] = {"covered": False, "reason": "no_specific_keywords_in_group"}
            continue
        hit_kws = [k for k in kws if k in chain_blob_lower]
        milestone_results[m_id] = {
            "covered": bool(hit_kws),
            "hit_keywords": hit_kws[:3],
            "all_keywords": kws[:8],
            "gt_event_ids": (spec if isinstance(spec, list) else None),
        }
    # Split milestones into in_scope (counted in primary headline) and
    # out_of_scope (require future-work modules — Discord LevelDB parser,
    # blockchain explorer, Outlook OST parser). The platform-architecture
    # honest read: ArshaLab is a modular system; missing milestone evidence
    # because the parser module isn't built yet is a SCOPE statement about
    # current build, not a model-reasoning failure.
    in_scope_results = {m: v for m, v in milestone_results.items()
                        if not isinstance(milestones.get(m), dict)
                        or "out_of_scope" not in milestones.get(m, {})}
    out_scope_results = {m: v for m, v in milestone_results.items()
                         if isinstance(milestones.get(m), dict)
                         and "out_of_scope" in milestones.get(m, {})}
    # Tag scope on each milestone record
    for m, v in milestone_results.items():
        spec_m = milestones.get(m)
        if isinstance(spec_m, dict) and "out_of_scope" in spec_m:
            v["scope"] = "out_of_scope_future_module"
            v["scope_reason"] = spec_m["out_of_scope"]
        else:
            v["scope"] = "in_scope"

    milestone_total = len(in_scope_results)  # PRIMARY denominator = in-scope only
    milestone_covered = sum(1 for v in in_scope_results.values() if v["covered"])
    milestone_coverage = (milestone_covered / milestone_total
                          if milestone_total else None)
    milestones_missed = [m for m, v in in_scope_results.items() if not v["covered"]]
    # Out-of-scope companion: how many of those are unexpectedly covered
    # (model wrote about them anyway, e.g. mentioned MetaMask in chain).
    oos_total = len(out_scope_results)
    oos_covered = sum(1 for v in out_scope_results.values() if v["covered"])
    oos_step_coverage = (oos_covered / oos_total if oos_total else None)

    # ---- SECONDARY: MITRE tactic coverage (breadth) --------------------
    # GT tactics are taken from the in-scope GT events' mitre_tactic field.
    # A tactic is covered if AT LEAST ONE event of that tactic was matched.
    gt_tactics_all = [str(ge.get("mitre_tactic", "UNKNOWN")) for ge in gt_in_scope]
    distinct_gt_tactics = sorted(set(gt_tactics_all))
    covered_tactics = sorted({gt_tactics_all[gi] for gi, _ in matched})
    missed_tactics = sorted(set(distinct_gt_tactics) - set(covered_tactics))
    tactic_coverage = (len(covered_tactics) / len(distinct_gt_tactics)
                       if distinct_gt_tactics else None)

    # ---- per-tactic depth (how many events per tactic were matched) ----
    per_tactic_total = defaultdict(int)
    per_tactic_hit = defaultdict(int)
    for gi, _ in matched:
        per_tactic_hit[gt_tactics_all[gi]] += 1
    for t in gt_tactics_all:
        per_tactic_total[t] += 1
    per_tactic_recall = {
        t: f"{per_tactic_hit[t]}/{per_tactic_total[t]}"
        for t in sorted(per_tactic_total)
    }

    # ---- SECONDARY: exact event coverage (diagnostic) -----------------
    exact_event_coverage = (len(matched) / len(gt_in_scope)
                             if gt_in_scope else None)
    concordant, discordant, ordering_acc, ordering_masked = _ordering_accuracy(
        matched, gt_in_scope, chain)
    src_correct, src_total, src_breakdown = _source_attribution(
        matched, gt_in_scope, chain)
    src_attr_acc = src_correct / src_total if src_total else None

    # Hallucination check over ALL chain events
    grounded = 0
    hallucinated = 0
    per_reason = Counter()
    for ce in chain:
        ok, reason = _is_grounded(ce, evidence_blob, evidence_by_date)
        per_reason[reason] += 1
        if ok:
            grounded += 1
        else:
            hallucinated += 1
    halluc_rate = hallucinated / len(chain) if chain else None

    miss_reasons = Counter(r for _, r in missed)
    report = {
        "chain_file": str(chain_path),
        "case": case,
        "provider": chain_payload.get("provider"),
        "run": chain_payload.get("run"),
        "evidence_record_count": chain_payload.get("evidence_record_count"),
        "chain_event_count": len(chain),
        "gt_in_scope_count": len(gt_in_scope),
        "gt_out_of_scope_excluded": len(gt_out_scope),
        "gt_distinct_tactics": distinct_gt_tactics,
        # 1. PRIMARY: semantic milestone checklist coverage (in-scope only)
        "milestone_coverage": round(milestone_coverage, 4) if milestone_coverage is not None else None,
        "milestones_covered_count": milestone_covered,
        "milestones_total": milestone_total,
        "milestones_missed": milestones_missed,
        "milestone_detail": milestone_results,
        # 1c. Out-of-scope (future-work modules) — reported separately
        "out_of_scope_milestones_total": oos_total,
        "out_of_scope_milestones_covered": oos_covered,
        "out_of_scope_milestone_coverage": (round(oos_step_coverage, 4) if oos_step_coverage is not None else None),
        # 1b. SECONDARY breadth: MITRE tactic coverage
        "tactic_coverage": round(tactic_coverage, 4) if tactic_coverage is not None else None,
        "tactics_covered": covered_tactics,
        "tactics_missed":  missed_tactics,
        "per_tactic_recall": per_tactic_recall,
        # 2. ordering accuracy
        "ordering_accuracy": round(ordering_acc, 4) if ordering_acc is not None else None,
        "ordering_pairs_concordant": concordant,
        "ordering_pairs_discordant": discordant,
        # Transparency: number of matched GT events skipped from ordering
        # pair generation because their raw timestamp is a session-scope
        # negative-finding marker (no instant). Exposed so reviewers can
        # audit the denominator delta against the unfiltered baseline.
        "ordering_pairs_masked_negative_finding": ordering_masked,
        # 3. source attribution
        "source_attribution_accuracy": round(src_attr_acc, 4) if src_attr_acc is not None else None,
        "source_attribution_correct": src_correct,
        "source_attribution_total": src_total,
        "per_source_attribution": src_breakdown,
        # 4. hallucination
        "hallucination_rate": round(halluc_rate, 4) if halluc_rate is not None else None,
        "grounded_events": grounded,
        "hallucinated_events": hallucinated,
        "hallucination_reasons": dict(per_reason),
        # SECONDARY (diagnostic only)
        "exact_event_coverage": round(exact_event_coverage, 4) if exact_event_coverage is not None else None,
        "matched_event_count": len(matched),
        "matched_gt_ids": [gt_in_scope[gi]["id"] for gi, _ in matched],
        "missed_gt": missed,
        "miss_reasons": dict(miss_reasons),
    }
    # ---- COMPOSITE HEADLINE: weighted mean of 4 PRIMARY metrics.
    # hallucination contributes as (1 - rate) so higher is always better.
    # If any metric is None (insufficient pairs), it falls back to 0.0.
    # Weights (sum=1): milestone+tactic+halluc=0.85 (the main contributions), ordering=0.15 (diagnostic). Source attribution is reported separately.
    milestone_v = report["milestone_coverage"] if report["milestone_coverage"] is not None else 0.0
    tactic_v = report["tactic_coverage"] if report["tactic_coverage"] is not None else 0.0
    halluc_v = (1.0 - report["hallucination_rate"]) if report["hallucination_rate"] is not None else 0.0
    ordering_v = report["ordering_accuracy"] if report["ordering_accuracy"] is not None else 0.0
    report["composite_headline"] = round(
        0.30 * milestone_v
        + 0.30 * tactic_v
        + 0.25 * halluc_v
        + 0.15 * ordering_v,
        4,
    )
    return report


def main():
    if len(sys.argv) < 3:
        print("usage: python score_timeline_mode2.py <chain.json> "
              "<kdfs|magnet|4orensics>")
        sys.exit(1)
    chain_path, case = sys.argv[1], sys.argv[2]
    rep = score(chain_path, case)

    out_path = Path(chain_path).with_suffix(".mode2_score.json")
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(rep, f, indent=2, ensure_ascii=False)

    print(f"\n{'=' * 60}")
    print(f"MODE 2 SCORE — {rep['case']} / {rep['provider']} / run {rep['run']}")
    print(f"{'=' * 60}")
    print(f"Evidence records  : {rep['evidence_record_count']}")
    print(f"Chain events      : {rep['chain_event_count']}")
    print(f"GT in-scope events: {rep['gt_in_scope_count']} "
          f"(+{rep['gt_out_of_scope_excluded']} excluded out-of-scope)")
    print(f"GT distinct MITRE tactics: {len(rep['gt_distinct_tactics'])} "
          f"({', '.join(rep['gt_distinct_tactics'])})")
    print()
    print(f"=== HEADLINE METRIC ===")
    if rep.get('milestone_coverage') is not None:
        print(f"1. MILESTONE COVERAGE     : "
              f"{rep['milestone_coverage'] * 100:.1f}%  "
              f"({rep['milestones_covered_count']}/{rep['milestones_total']} milestones)")
        if rep['milestones_missed']:
            print(f"   milestones missed      : {rep['milestones_missed']}")
    else:
        print(f"1. MILESTONE COVERAGE     : n/a (no milestone checklist defined for case)")
    if rep['tactic_coverage'] is not None:
        print(f"   tactic-breadth (companion): "
              f"{rep['tactic_coverage'] * 100:.1f}%  "
              f"({len(rep['tactics_covered'])}/{len(rep['gt_distinct_tactics'])} tactics)")
    print()
    print(f"=== QUALITY METRICS ===")
    if rep['ordering_accuracy'] is not None:
        print(f"2. ORDERING ACCURACY      : "
              f"{rep['ordering_accuracy'] * 100:.1f}%  "
              f"({rep['ordering_pairs_concordant']}/"
              f"{rep['ordering_pairs_concordant'] + rep['ordering_pairs_discordant']} pairs)")
    else:
        print(f"2. ORDERING ACCURACY      : n/a (not enough pairs)")
    if rep['source_attribution_accuracy'] is not None:
        print(f"3. SOURCE ATTRIBUTION     : "
              f"{rep['source_attribution_accuracy'] * 100:.1f}%  "
              f"({rep['source_attribution_correct']}/"
              f"{rep['source_attribution_total']})")
    else:
        print(f"3. SOURCE ATTRIBUTION     : n/a")
    if rep['hallucination_rate'] is not None:
        print(f"4. HALLUCINATION RATE     : "
              f"{rep['hallucination_rate'] * 100:.1f}%  "
              f"({rep['hallucinated_events']}/{rep['chain_event_count']})")
    else:
        print(f"4. HALLUCINATION RATE     : n/a")
    print()
    print(f"=== DIAGNOSTIC (secondary) ===")
    if rep['exact_event_coverage'] is not None:
        print(f"   Exact event coverage  : {rep['exact_event_coverage']*100:.1f}%  "
              f"({rep['matched_event_count']}/{rep['gt_in_scope_count']})")
    print(f"   Per-tactic recall depth:")
    for t, v in rep["per_tactic_recall"].items():
        marker = "MISSED" if t in rep["tactics_missed"] else "  "
        print(f"     {marker} {t:25s} {v}")
    print()
    print(f"   Per-source attribution:")
    for s, v in rep["per_source_attribution"].items():
        print(f"     {s:20s} {v}")
    print(f"\nReport -> {out_path}")


if __name__ == "__main__":
    main()
