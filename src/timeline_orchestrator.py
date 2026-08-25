"""Fixed-checklist timeline reconstruction orchestrator.

Drives any analyzer with an `analyze(str) -> str` + `clear_history()` interface
(ClaudeAnalyzer, DeepSeekAnalyzer, OpusAnalyzer, or an MCP-CLI wrapper) through
a FIXED universal forensic checklist (not LLM-invented phases):

  - 12 standard forensic investigation steps, identical for every image
  - each step = one atomic targeted LLM call (the regime where the model is
    strong, like retrieval) -> JSON events appended to JSONL immediately
  - deterministic & exhaustive: every artifact dimension is always covered,
    so nothing structurally drops out (the phase approach lost MFT-created
    files because LLM-invented phases didn't systematically cover them)

The checklist contains ZERO content hints / file names — only standard
forensic dimensions (what any analyst / Plaso covers on any image). This
keeps ArshaLab modular and the evaluation scientifically honest.

Output: <out_dir>/timeline_<case>_<provider>.jsonl  (one event per line)
State : <out_dir>/timeline_<case>_<provider>_state.json (resume support)

Console shows only progress; full data goes to file. `verbose=True` prints more.
"""
import json
import re
import time
from pathlib import Path


# ----------------------------- JSON extraction -----------------------------

def extract_json(text: str):
    """Robustly pull the first JSON array/object out of an LLM response.

    Handles ```json fenced blocks, leading prose, trailing prose.
    Returns parsed Python object or None.
    """
    if not text:
        return None

    # 1. fenced ```json ... ```
    fence = re.search(r"```(?:json)?\s*(\[.*?\]|\{.*?\})\s*```", text, re.S)
    if fence:
        try:
            return json.loads(fence.group(1))
        except json.JSONDecodeError:
            pass

    # 2. first balanced [ ... ] (arrays are what we ask for)
    for opener, closer in (("[", "]"), ("{", "}")):
        start = text.find(opener)
        while start != -1:
            depth = 0
            in_str = False
            esc = False
            for i in range(start, len(text)):
                ch = text[i]
                if esc:
                    esc = False
                    continue
                if ch == "\\":
                    esc = True
                    continue
                if ch == '"':
                    in_str = not in_str
                    continue
                if in_str:
                    continue
                if ch == opener:
                    depth += 1
                elif ch == closer:
                    depth -= 1
                    if depth == 0:
                        candidate = text[start:i + 1]
                        try:
                            return json.loads(candidate)
                        except json.JSONDecodeError:
                            break
            start = text.find(opener, start + 1)
    return None


# ----------------------------- Orchestrator --------------------------------

class TimelineOrchestrator:
    # Universal forensic timeline checklist. Standard investigation
    # dimensions only — NO case-specific content / file names. Identical
    # for every Windows image (this is what keeps the approach modular and
    # the metric honest).
    CHECKLIST = [
        ("system_accounts",
         "Identify system & user context: primary user account, ALL local "
         "accounts, account creation and deletion events, group membership "
         "changes, OS version, timezone, and system install date."),
        ("authentication",
         "Reconstruct authentication activity: successful and failed logons, "
         "logoffs, remote/interactive/RDP sessions, and explicit-credential "
         "logons across the relevant period."),
        # Program execution split per source (one parser per step keeps the
        # JSON small enough to not overflow a single response).
        ("prefetch_execution",
         "Enumerate program execution from PREFETCH ONLY: every executed "
         "binary with run time(s) and run count, especially executables "
         "outside standard system paths."),
        ("shimcache_execution",
         "Enumerate program-execution evidence from SHIMCACHE "
         "(AppCompatCache) ONLY: every cached executable path with its "
         "timestamp."),
        ("amcache_execution",
         "Enumerate program install/execution from AMCACHE ONLY: every "
         "binary with path, SHA1, version and publisher."),
        # File-system split per source for the same reason.
        ("mft_file_creation",
         "Reconstruct file & folder CREATION/modification from MFT ONLY, in "
         "user, temp, public and download directories — scripts, "
         "executables, archives, documents. Report each item individually."),
        ("usnjrnl_file_ops",
         "Reconstruct granular file operations from the USN JOURNAL ONLY — "
         "create, delete, rename, modify — in user and temp directories. "
         "Report each operation individually."),
        ("deleted_items",
         "Recover deleted/recycled items: RecycleBin contents with original "
         "paths and deletion times, plus UsnJrnl delete records."),
        ("registry_persistence",
         "Examine the registry for persistence and user activity: "
         "Run/RunOnce keys, installed services, scheduled tasks, MRU keys "
         "(OpenSave/LastVisited/RunMRU), BAM/UserAssist execution evidence, "
         "and USB storage history."),
        ("service_driver_install",
         "Find service and driver installation events (e.g. EventLog service "
         "control records) and kernel-mode driver loads, with timestamps and "
         "the binary path of each installed service/driver."),
        ("security_defense",
         "Examine security/defense telemetry: antivirus/Defender threat "
         "detections and remediations, security audit-log clearing, "
         "PowerShell script-block/module/transcript logging, and audit "
         "policy changes."),
        ("network",
         "Analyze network activity from SRUM: per-application bytes "
         "sent/received, and indicators of VPN, tunneling, remote access or "
         "external connections."),
        ("browser_intent",
         "Extract browser activity that shows user INTENT: search queries, "
         "downloads, and visits to attacker-tool / how-to / research pages. "
         "Exclude routine navigation (login pages, app home pages) with no "
         "investigative significance."),
        ("external_devices",
         "Identify external/removable devices: USB storage devices with "
         "serial numbers, vendor/product, first/last connection, and mounted "
         "volumes."),
        ("antiforensics_lateral",
         "Detect anti-forensics and lateral-movement preparation: "
         "secure-deletion / disk-cleaning tools, timestamp manipulation, "
         "remote-access tools, and data staging or archiving consistent with "
         "exfiltration."),
    ]

    def __init__(self, analyzer, case_name, case_id, provider, scenario="",
                 out_dir="benchmark_results/timeline_evaluation", verbose=False):
        self.analyzer = analyzer
        self.case_name = case_name
        self.case_id = case_id
        self.provider = provider
        self.scenario = scenario
        self.verbose = verbose
        self.out_dir = Path(out_dir)
        self.out_dir.mkdir(parents=True, exist_ok=True)

        safe = re.sub(r"[^\w]+", "_", case_name).strip("_")
        self.jsonl_path = self.out_dir / f"timeline_{safe}_{provider}.jsonl"
        self.state_path = self.out_dir / f"timeline_{safe}_{provider}_state.json"

        self._seen = set()          # dedup keys
        self._events = []           # accumulated (also persisted to jsonl)
        self._state = {
            "case_name": case_name, "case_id": case_id, "provider": provider,
            "checklist": [s[0] for s in self.CHECKLIST],
            "steps_done": [], "started": time.time(),
            "total_events": 0,
        }

    # -- logging -------------------------------------------------------------

    def _log(self, msg):
        print(f"[{self.provider}/{self.case_name}] {msg}", flush=True)

    def _save_state(self):
        self._state["total_events"] = len(self._events)
        with open(self.state_path, "w", encoding="utf-8") as f:
            json.dump(self._state, f, indent=2, ensure_ascii=False)

    # -- dedup + persistence -------------------------------------------------

    def _dedup_key(self, ev):
        ts = str(ev.get("timestamp", "")).strip()[:19]      # to seconds
        at = str(ev.get("artifact_type", ev.get("source", ""))).lower().strip()
        desc = str(ev.get("description", "")).lower().strip()
        first_tok = desc.split()[0] if desc else ""
        return (ts, at, first_tok)

    def _append_events(self, events, step):
        added = 0
        with open(self.jsonl_path, "a", encoding="utf-8") as f:
            for ev in events:
                if not isinstance(ev, dict):
                    continue
                key = self._dedup_key(ev)
                if key in self._seen:
                    continue
                self._seen.add(key)
                ev.setdefault("step", step)
                f.write(json.dumps(ev, ensure_ascii=False) + "\n")
                self._events.append(ev)
                added += 1
        return added

    # -- timeline-mode system prompt override --------------------------------

    def _install_timeline_system_prompt(self):
        """Override the analyzer's RESPONSE FORMAT to demand raw JSON.

        BASE_SYSTEM_PROMPT tells the model to answer complex/timeline
        questions in bullet points — that silently overrides the per-step
        'output JSON array' instruction and yields 0 parsed events. Replace
        only the RESPONSE FORMAT block; keep all forensic/data-integrity
        rules. Retrieval is unaffected (it uses a separate analyzer instance).
        """
        sp = getattr(self.analyzer, "system_prompt", None)
        if not sp:
            return  # MCP-CLI analyzer has no system_prompt — per-call prompt handles it
        new_block = (
            "RESPONSE FORMAT (STRICT — timeline mode):\n"
            "- Your ENTIRE response MUST be a single raw JSON array, nothing else.\n"
            "- NO prose, NO bullet points, NO markdown, NO preamble, NO summary.\n"
            '- Each item exactly: {"timestamp":"<exact>","artifact_type":'
            '"<source>","description":"<concise fact>"}.\n'
            "- Use only exact values returned by tools. Empty -> [].\n\n"
        )
        sp2 = re.sub(r"RESPONSE FORMAT:.*?(?=BEHAVIOR:)", new_block, sp,
                     flags=re.S)
        if sp2 != sp:
            self.analyzer.system_prompt = sp2
            self._log("timeline system-prompt installed (JSON-strict)")

    # -- LLM call helper -----------------------------------------------------

    def _ask(self, prompt):
        if hasattr(self.analyzer, "clear_history"):
            try:
                self.analyzer.clear_history()
            except Exception:
                pass
        t0 = time.time()
        resp = self.analyzer.analyze(prompt)
        dt = time.time() - t0
        if isinstance(resp, dict):
            resp = resp.get("response") or resp.get("answer") or str(resp)
        if self.verbose:
            self._log(f"  (LLM {dt:.0f}s, {len(resp or '')} chars)")
        return resp or "", dt

    # -- checklist step ------------------------------------------------------

    def run_step(self, step_id, instruction, idx, total):
        prompt = (
            f"CRITICAL OUTPUT RULE: Your ENTIRE reply must be ONE raw JSON "
            f"array and nothing else. Ignore any earlier instruction about "
            f"bullet points or prose — do NOT use bullets, headers, or "
            f"explanation. If you output prose, the result is discarded.\n\n"
            f"Case {self.case_name} (case_id={self.case_id}). "
            f"Forensic timeline reconstruction — step {idx}/{total}: "
            f"{step_id}.\n\nTASK: {instruction}\n\n"
            f"Use the appropriate forensic tools (search_artifacts, "
            f"analyze_program_execution, analyze_security_events, "
            f"analyze_registry, analyze_web_activity, search_file_activity, "
            f"search_file_changes, analyze_deleted_files, "
            f"analyze_network_activity, correlate_activity, "
            f"find_suspicious_activity). Investigate thoroughly for THIS step "
            f"only. Report EVERY event the tools actually confirmed — do not "
            f"omit a confirmed artifact because it seems minor, and do not "
            f"summarize groups (list each file/event individually). "
            f"Do not fabricate — only report what tools returned. "
            f'Output ONLY a JSON array; each item: '
            f'{{"timestamp": "<exact timestamp from tool>", '
            f'"artifact_type": "<source: mft|registry|eventlog|prefetch|'
            f'shimcache|amcache|usnjrnl|browser|srum|jumplist|lnk|'
            f'recyclebin|powershell>", "description": "<concise fact with '
            f'concrete identifiers: filename, path, Event ID, account, '
            f'serial, key>"}}. No prose, only the JSON array (use [] if the '
            f"tools genuinely returned nothing for this step)."
        )
        resp, dt = self._ask(prompt)
        events = extract_json(resp)
        if not isinstance(events, list):
            events = []
        added = self._append_events(events, step_id)
        self._state["steps_done"].append(step_id)
        self._save_state()
        self._log(f"Step {idx}/{total} [{step_id}] -> "
                  f"{added} new events ({len(self._events)} total)")
        return added

    # -- driver --------------------------------------------------------------

    def run(self, **_ignored):
        self._install_timeline_system_prompt()
        # fresh jsonl unless resuming
        if not self._state["steps_done"]:
            self.jsonl_path.write_text("", encoding="utf-8")
        else:
            # resuming: rebuild dedup set + count from existing jsonl
            if self.jsonl_path.exists():
                for line in self.jsonl_path.read_text(encoding="utf-8").splitlines():
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        ev = json.loads(line)
                    except json.JSONDecodeError:
                        continue
                    self._events.append(ev)
                    self._seen.add(self._dedup_key(ev))

        t0 = time.time()
        total = len(self.CHECKLIST)
        for idx, (step_id, instruction) in enumerate(self.CHECKLIST, 1):
            if step_id in self._state["steps_done"]:
                self._log(f"Step {idx}/{total} [{step_id}] already done, skip")
                continue
            self.run_step(step_id, instruction, idx, total)

        elapsed = time.time() - t0
        self._state["elapsed_seconds"] = elapsed
        self._save_state()
        self._log(f"DONE: {len(self._events)} events in {elapsed:.0f}s "
                  f"-> {self.jsonl_path}")
        return {
            "case_name": self.case_name,
            "case_id": self.case_id,
            "provider": self.provider,
            "total_events": len(self._events),
            "elapsed_seconds": elapsed,
            "jsonl_path": str(self.jsonl_path),
            "checklist_steps": [s[0] for s in self.CHECKLIST],
        }
