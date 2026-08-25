# -*- coding: utf-8 -*-
"""Strict fact-grounding score for Mode 2 attack chains.

The scorer in `score_timeline_mode2.py` measures grounding in a way that cannot support a general
non-fabrication claim. Three properties were established empirically on 2026-07-31:

  * an entity is only checkable if it matches one of five regexes or appears in a hardcoded 25-item
    Event-ID allowlist, so most stated Event IDs, and whole classes of fact (.txt/.docx/.evtx files,
    .ru/.xyz domains, SHA256, registry keys, hostnames, ports) are never examined;
  * grounding is a substring test over a flattened dump in which every record carries its `_anchor`,
    and 44 anchor names embed a 3-5 digit number, so those digits are permanently "present";
  * an event with no recognised entity returns grounded, which covers 36.4% of published events.

Together those let a chain in which every event is invented score 0.00%.

This module fixes all three. Event IDs are matched against the `event_id` FIELD of evidence records
(including ones nested in `_raw` payloads); every other entity is matched against a blob built with
`_anchor` removed; and events with nothing checkable are reported as a separate coverage figure
instead of being counted as grounded.

Usage:
    python score_fabrication_strict.py <chain.json> [<evidence.json>]
    python score_fabrication_strict.py --dir <directory>
"""
import argparse
import difflib
import json
import os
import re
import sys
from collections import Counter

# Entity classes. Deliberately wider than the original: the point is to check what a model actually
# says, not only the categories that happen to be easy.
PATTERNS = [
    ('file', re.compile(
        r'\b[A-Za-z0-9_\-.]+\.(?:ps1|bat|cmd|vbs|js|py|exe|dll|sys|scr|com|msi|cab|zip|7z|rar|gz|tar'
        r'|pdf|jpg|jpeg|png|gif|svg|txt|log|csv|xlsx|xls|docx|doc|pptx|ost|pst|eml|msg|lnk|url'
        r'|evtx|hve|dat|db|sqlite|ldb|json|xml|reg|cfg|ini|tmp|pf|odl|odlgz|jar|apk|iso|vhd|img)\b',
        re.I)),
    ('ip', re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')),
    ('sid', re.compile(r'\bS-1-5-\d+(?:-\d+){2,7}\b', re.I)),
    ('hash', re.compile(r'\b[0-9a-f]{32,64}\b', re.I)),
    ('domain', re.compile(
        r'\b(?:[a-z0-9][a-z0-9\-]{1,30}\.)+(?:com|io|net|org|ru|kr|co\.kr|xyz|biz|info|top|cc|gg'
        r'|onion|eth|dev|app|me|tv|cn|jp|uk|de|fr)\b', re.I)),
    ('email', re.compile(r'\b[\w.+\-]+@[\w\-]+\.\w{2,}\b')),
]
# an Event ID stated as such - no allowlist
EID = re.compile(r'(?:event\s*id|eventid)\s*[:#=]?\s*(\d{3,5})', re.I)
TEXT_FIELDS = ('event', 'description', 'summary', 'supporting_artifact', 'details')


def _iter_records(evidence):
    by = evidence.get('evidence_by_anchor', evidence)
    if isinstance(by, dict):
        for recs in by.values():
            for r in recs or []:
                if isinstance(r, dict):
                    yield r
    elif isinstance(by, list):
        for r in by:
            if isinstance(r, dict):
                yield r


FILE_IN_EVIDENCE = re.compile(r'[A-Za-z0-9_\-.]+\.[A-Za-z0-9]{2,7}\b')


def build_index(evidence):
    """Return (event_ids, blob, names_by_minute).

    event_ids comes from typed fields, never from anchor names. names_by_minute maps a
    (date, HH:MM) key to the filenames appearing in records at that minute; it is what allows a
    mistyped filename to be distinguished from an invented one.
    """
    ids = Counter()
    parts = []
    names = {}
    for r in _iter_records(evidence):
        eid = r.get('event_id')
        if eid is not None:
            ids[str(eid)] += 1
        raw = str(r.get('_raw') or '')
        for m in re.findall(r"'event_id':\s*(\d+)", raw):
            ids[m] += 1
        clean = {k: v for k, v in r.items() if k != '_anchor'}
        body = json.dumps(clean, ensure_ascii=False, default=str)
        parts.append(body.lower())
        key = _minute_key(r.get('timestamp'))
        if key:
            names.setdefault(key, set()).update(
                n.lower() for n in FILE_IN_EVIDENCE.findall(body))
    return ids, '\n'.join(parts), names


def _minute_key(ts):
    m = re.match(r'(\d{4}-\d{2}-\d{2})[ T](\d{2}):(\d{2})', str(ts or ''))
    return (m.group(1), int(m.group(2)), int(m.group(3))) if m else None


def _name_variant_of(written, event_ts, names_by_minute, threshold=0.90):
    """Is `written` a mistyped form of a filename present at this event's own minute?

    Requires the same extension, a similarity at or above the threshold, and that the real name
    occurs in a record within one minute of the event. Those three conditions together separate a
    transcription slip - the model naming the right artifact and misspelling it - from a filename
    that points at nothing. A near-match found anywhere in the pool would not be enough: chrome.exe
    and chrome2.exe are 0.94 similar and are different files.

    Known limitation, verified by adversarial probe: a substitution that is short but semantically
    real - `...-STD-X86.EXE` for `...-STD-X64.EXE` - scores 0.96 and would be accepted, although the
    two are different binaries. The rule is therefore a convenience, not an authority. Whenever the
    substantive rate is reported, the events it reclassifies must be few enough to list and must be
    inspected by hand; do not lean on it to absorb a large number of cases.
    """
    key = _minute_key(event_ts)
    if not key:
        return None
    date, hh, mm = key
    pool = set()
    for dm in (-1, 0, 1):
        pool |= names_by_minute.get((date, hh, (mm + dm) % 60), set())
    ext = written.rsplit('.', 1)[-1]
    best, best_ratio = None, 0.0
    for cand in pool:
        if cand.rsplit('.', 1)[-1] != ext or cand == written:
            continue
        ratio = difflib.SequenceMatcher(None, written, cand).ratio()
        if ratio > best_ratio:
            best, best_ratio = cand, ratio
    return (best, round(best_ratio, 3)) if best_ratio >= threshold else None


def entities_of(event):
    text = ' '.join(str(event.get(f, '')) for f in TEXT_FIELDS)
    found = []
    for kind, pat in PATTERNS:
        for m in pat.findall(text):
            found.append((kind, m.lower()))
    for eid in EID.findall(text):
        found.append(('event_id', eid))
    return found


def score_chain(chain_path, evidence_path=None):
    d = json.load(open(chain_path, encoding='utf-8'))
    events = d.get('chain') if isinstance(d, dict) else d
    if evidence_path is None:
        folder = os.path.dirname(os.path.abspath(chain_path))
        # A directory can hold several cases, so the evidence must be selected by case name,
        # not by whatever sorts first. Picking the wrong case makes every real fact look invented.
        case = (d.get('case_name') if isinstance(d, dict) else None) or ''
        named = os.path.join(folder, 'evidence_%s.json' % case)
        if case and os.path.exists(named):
            evidence_path = named
        else:
            cands = [f for f in os.listdir(folder)
                     if f.startswith('evidence_') and f.endswith('.json')]
            if len(cands) != 1:
                raise SystemExit('cannot pick evidence for %s (case=%r, candidates=%s)'
                                 % (os.path.basename(chain_path), case, cands))
            evidence_path = os.path.join(folder, cands[0])
    ids, blob, names_by_minute = build_index(json.load(open(evidence_path, encoding='utf-8')))
    minutes = set(names_by_minute)
    dates = {k[0] for k in minutes}

    checked = ungrounded = unchecked = variant_events = 0
    bad_time = 0
    reasons = Counter()
    offenders = []
    variants = []
    time_offenders = []
    for i, e in enumerate(events or []):
        # A timeline event asserts a time as much as it asserts a fact, so the timestamp is checked
        # too. Omitting this was a real regression: without it an event dated four years outside the
        # case scored as perfectly grounded, which is indefensible in a paper about reconstructing
        # chronology. The tolerance matches the retrieval sort - the minute itself or either
        # neighbour - and an event whose date is absent from the evidence entirely is worse still.
        key = _minute_key(e.get('timestamp'))
        if key is None:
            time_reason = 'no_timestamp'
        elif key[0] not in dates:
            time_reason = 'date_absent_from_evidence'
        elif not any((key[0], key[1], (key[2] + d) % 60) in minutes for d in (-1, 0, 1)):
            time_reason = 'minute_absent_from_evidence'
        else:
            time_reason = None
        if time_reason:
            bad_time += 1
            reasons[time_reason] += 1
            time_offenders.append(dict(index=i, timestamp=e.get('timestamp'),
                                       event=str(e.get('event'))[:110], reason=time_reason))

        ents = entities_of(e)
        if not ents:
            unchecked += 1
            continue
        checked += 1
        bad, slips = [], []
        for kind, val in ents:
            if kind == 'event_id':
                if ids.get(val, 0) == 0:
                    bad.append('event_id:%s' % val)
            elif val not in blob:
                near = _name_variant_of(val, e.get('timestamp'), names_by_minute) \
                    if kind == 'file' else None
                if near:
                    slips.append(dict(written=val, actual=near[0], similarity=near[1]))
                else:
                    bad.append('%s:%s' % (kind, val))
        if bad:
            ungrounded += 1
            reasons.update(bad)
            offenders.append(dict(index=i, timestamp=e.get('timestamp'),
                                  event=str(e.get('event'))[:110], missing=bad))
        elif slips:
            # The artifact named at this minute exists; only its spelling is wrong. Reported as its
            # own category so the reader can count it either way rather than take our word for it.
            variant_events += 1
            variants.append(dict(index=i, timestamp=e.get('timestamp'),
                                 event=str(e.get('event'))[:110], slips=slips))
    n = len(events or [])
    return {
        'chain': os.path.basename(chain_path),
        'provider': d.get('provider') if isinstance(d, dict) else None,
        'case': d.get('case_name') if isinstance(d, dict) else None,
        'events': n,
        'events_with_checkable_fact': checked,
        'events_unchecked': unchecked,
        'metric_coverage': round(checked / n, 4) if n else None,
        'ungrounded_events': ungrounded,
        'name_variant_events': variant_events,
        'events_with_unsupported_timestamp': bad_time,
        'unsupported_timestamp_rate': round(bad_time / n, 4) if n else None,
        'timestamp_offenders': time_offenders,
        # strict: a mistyped filename counts against the model
        'strict_fabrication_rate': round((ungrounded + variant_events) / checked, 4) if checked else None,
        # substantive: only claims that point at nothing in the evidence count
        'substantive_fabrication_rate': round(ungrounded / checked, 4) if checked else None,
        'fabrication_rate_over_all_events': round(ungrounded / n, 4) if n else None,
        'missing_entities': dict(reasons),
        'offenders': offenders,
        'name_variants': variants,
    }


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('chain', nargs='?')
    ap.add_argument('evidence', nargs='?')
    ap.add_argument('--dir')
    a = ap.parse_args()
    sys.stdout.reconfigure(encoding='utf-8')

    targets = []
    if a.dir:
        for root, _, files in os.walk(a.dir):
            for f in files:
                if f.startswith('chain_') and f.endswith('.json') and 'score' not in f:
                    targets.append(os.path.join(root, f))
    else:
        targets = [a.chain]

    rows = [score_chain(t, a.evidence) for t in sorted(targets)]
    print('%-44s %7s %8s %9s %7s %8s %11s %12s'
          % ('CHAIN', 'events', 'checked', 'coverage', 'wrong', 'mistyped', 'strict', 'substantive'))
    print('-' * 112)
    for r in rows:
        f = lambda v: ('%.2f%%' % (100 * v)) if v is not None else '-'
        print('%-44s %7d %8d %8.0f%% %7d %8d %11s %12s'
              % (r['chain'][:44], r['events'], r['events_with_checkable_fact'],
                 100 * (r['metric_coverage'] or 0), r['ungrounded_events'],
                 r['name_variant_events'], f(r['strict_fabrication_rate']),
                 f(r['substantive_fabrication_rate'])))
    if len(rows) > 1:
        ev = sum(r['events'] for r in rows)
        ck = sum(r['events_with_checkable_fact'] for r in rows)
        ug = sum(r['ungrounded_events'] for r in rows)
        vr = sum(r['name_variant_events'] for r in rows)
        print('-' * 112)
        print('%-44s %7d %8d %8.0f%% %7d %8d %11s %12s'
              % ('TOTAL', ev, ck, 100 * ck / ev if ev else 0, ug, vr,
                 '%.2f%%' % (100 * (ug + vr) / ck) if ck else '-',
                 '%.2f%%' % (100 * ug / ck) if ck else '-'))
    if len(rows) == 1 and rows[0]['offenders']:
        print()
        for o in rows[0]['offenders']:
            print('  [%d] %s  missing %s' % (o['index'], o['timestamp'], o['missing']))
            print('       %s' % o['event'])


if __name__ == '__main__':
    main()
