"""Timeline orchestrator for no-tool RAG models (Ollama / local).

Same 15-dimension forensic checklist as TimelineOrchestrator (so results are
comparable), but the model has no autonomous tool use. Instead, we run a
fixed, case-agnostic ES retrieval recipe per step and pass the resulting
evidence as context to the model. The model's job is reduced to extracting
events as JSON from the pre-retrieved evidence.

This isolates retrieval from event-extraction, which is the operational
difference between tool-use cloud models and no-tool RAG models. It lets us
measure RAG model timeline capability fairly without confounding it with
their keyword-extraction heuristic.

Output layout matches TimelineOrchestrator:
    benchmark_results/timeline_evaluation/timeline_<case>_<provider>.jsonl
    benchmark_results/timeline_evaluation/timeline_<case>_<provider>_state.json

Usage (from run_timeline_v2.py path):
    orch = TimelineOrchestratorRAG(model="qwen2.5:14b",
                                   case_name="Magnet CTF 2022",
                                   case_id="case_20260323_032324",
                                   provider="qwen")
    orch.run()
"""
import json
import re
import time
import urllib.request
from pathlib import Path

from src.timeline_orchestrator import TimelineOrchestrator, extract_json


# ---------------- Per-step retrieval recipes -----------------------------
# Case-agnostic ES queries by forensic dimension. Identical for every image,
# same spirit as TimelineOrchestrator.CHECKLIST. Each entry is a list of
# (tool_method_name, kwargs) calls; results are concatenated into evidence
# context for the model.

STEP_RETRIEVALS = {
    "system_accounts": [
        ("_tool_analyze_security_events", {"event_id": 4720, "limit": 30}),
        ("_tool_search_artifacts",       {"query": "LastLoggedOnUser OR DefaultUserName OR RegisteredOwner OR InstallDate OR ProductName OR CurrentBuildNumber", "artifact_type": "registry", "limit": 30}),
    ],
    "authentication": [
        ("_tool_analyze_security_events", {"event_id": 4624, "limit": 30}),
        ("_tool_analyze_security_events", {"event_id": 4625, "limit": 30}),
        ("_tool_analyze_security_events", {"event_id": 4647, "limit": 30}),
        ("_tool_analyze_security_events", {"event_id": 4648, "limit": 20}),
    ],
    "prefetch_execution": [
        ("_es_search", {"index": "forensic-prefetch", "size": 100}),
    ],
    "shimcache_execution": [
        ("_es_search", {"index": "forensic-shimcache", "size": 100}),
    ],
    "amcache_execution": [
        ("_es_search", {"index": "forensic-amcache", "size": 100}),
    ],
    "mft_file_creation": [
        ("_tool_search_artifacts", {"query": ".ps1 OR .bat OR .vbs OR .exe OR .msi OR .zip OR .lnk", "artifact_type": "mft", "limit": 50}),
        ("_tool_search_artifacts", {"query": "Users AND (Downloads OR Documents OR Desktop OR Temp OR AppData)", "artifact_type": "mft", "limit": 50}),
    ],
    "usnjrnl_file_ops": [
        ("_tool_search_artifacts", {"query": ".ps1 OR .bat OR .vbs OR .exe OR .zip OR delete OR rename", "artifact_type": "usnjrnl", "limit": 60}),
    ],
    "deleted_items": [
        ("_tool_search_artifacts", {"query": "delete OR recycle", "artifact_type": "usnjrnl", "limit": 30}),
    ],
    "registry_persistence": [
        ("_tool_analyze_registry", {"category": "all", "query": "Run OR RunOnce OR Startup OR Services OR Tasks OR USBSTOR OR BAM OR UserAssist OR ScheduledTask OR Firewall", "limit": 60}),
    ],
    "service_driver_install": [
        ("_tool_analyze_security_events", {"event_id": 7045, "limit": 30}),
        ("_tool_search_artifacts", {"query": ".sys", "artifact_type": "mft", "limit": 30}),
    ],
    "security_defense": [
        ("_tool_analyze_security_events", {"event_id": 1116, "limit": 30}),
        ("_tool_analyze_security_events", {"event_id": 1117, "limit": 30}),
        ("_tool_analyze_security_events", {"event_id": 4104, "limit": 30}),
        ("_tool_analyze_security_events", {"event_id": 4100, "limit": 20}),
        ("_tool_analyze_security_events", {"event_id": 1102, "limit": 10}),
        ("_tool_analyze_security_events", {"event_id": 5007, "limit": 10}),
    ],
    "network": [
        ("_es_search", {"index": "forensic-srum", "size": 60}),
    ],
    "browser_intent": [
        ("_tool_analyze_web", {"limit": 50}),
        ("_tool_search_artifacts", {"query": "search OR download OR hack OR ransomware OR exfil OR vpn OR powercat OR torrent", "artifact_type": "browser", "limit": 30}),
    ],
    "external_devices": [
        ("_tool_search_artifacts", {"query": "USBSTOR OR USB OR removable", "artifact_type": "registry", "limit": 30}),
    ],
    "antiforensics_lateral": [
        ("_tool_search_artifacts", {"query": "file_deleter OR sdelete OR ccleaner OR wipe OR teamviewer OR anydesk OR putty OR psexec OR mimikatz", "artifact_type": "all", "limit": 40}),
        ("_tool_search_artifacts", {"query": ".ps1", "artifact_type": "mft", "limit": 20}),
    ],
}


class TimelineOrchestratorRAG:
    """Controlled-retrieval timeline orchestrator. Works with any provider:
    ollama (local), deepseek, openai (cloud). The orchestrator does
    deterministic per-step ES queries; the model only extracts events from
    the pre-retrieved evidence. This isolates event-extraction capability
    from tool-selection ability, allowing fair cross-model comparison.

    Provider routing:
        provider in {"llama", "qwen"}      -> direct Ollama HTTP
        provider in {"deepseek"}           -> OpenAI SDK against DeepSeek
        provider in {"openai"}             -> OpenAI SDK
        provider in {"sonnet", "opus"}     -> MCP CLI (no tool budget here,
                                              MCP runs without tool needs
                                              because evidence is in prompt)
    """
    def __init__(self, model, case_name, case_id, provider,
                 ollama_url="http://localhost:11434",
                 out_dir="benchmark_results/timeline_evaluation",
                 verbose=False, max_evidence_per_call_chars=48000):
        self.model = model
        self.case_name = case_name
        self.case_id = case_id
        self.provider = provider
        self.ollama_url = ollama_url
        self.verbose = verbose
        self.max_evidence_per_call_chars = max_evidence_per_call_chars
        self.out_dir = Path(out_dir)
        self.out_dir.mkdir(parents=True, exist_ok=True)

        from src.llm.base_analyzer import BaseAnalyzer
        self._es = BaseAnalyzer(es_url="http://localhost:9200", case_id=case_id)

        # Output suffixed with "_rag" so it doesn't clobber tool-use results.
        safe = re.sub(r"[^\w]+", "_", case_name).strip("_")
        self.jsonl_path = self.out_dir / f"timeline_{safe}_{provider}_rag.jsonl"
        self.state_path = self.out_dir / f"timeline_{safe}_{provider}_rag_state.json"

        self._events = []
        self._seen = set()
        self._state = {
            "case_name": case_name, "case_id": case_id, "provider": provider,
            "model": model, "mode": "rag-orchestrator",
            "checklist": [s[0] for s in TimelineOrchestrator.CHECKLIST],
            "steps_done": [], "started": time.time(),
            "total_events": 0,
        }

    def _log(self, msg):
        print(f"[{self.provider}/{self.case_name}] {msg}", flush=True)

    def _save_state(self):
        self._state["total_events"] = len(self._events)
        with open(self.state_path, "w", encoding="utf-8") as f:
            json.dump(self._state, f, indent=2, ensure_ascii=False)

    def _dedup_key(self, ev):
        ts = str(ev.get("timestamp", "")).strip()[:19]
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

    def _retrieve_context(self, step_id):
        """Deterministic ES retrieval for a checklist step. Returns evidence
        chunks as a single text blob, truncated to max_evidence_per_call_chars.
        """
        recipe = STEP_RETRIEVALS.get(step_id, [])
        chunks = []
        for tool_name, args in recipe:
            try:
                tool = getattr(self._es, tool_name)
                result = tool(**args)
                serial = json.dumps(result, ensure_ascii=False, default=str)
                header = f"\n--- {tool_name}({json.dumps(args, ensure_ascii=False)}) ---\n"
                chunks.append(header + serial)
            except Exception as exc:
                chunks.append(f"\n--- {tool_name}(...) ERROR: {exc} ---\n")
        evidence = "".join(chunks)
        if len(evidence) > self.max_evidence_per_call_chars:
            evidence = (evidence[:self.max_evidence_per_call_chars]
                        + f"\n[... truncated to {self.max_evidence_per_call_chars} chars ...]")
        return evidence

    def _ask_ollama(self, prompt, num_ctx=65536, max_tokens=8192):
        body = json.dumps({
            "model": self.model,
            "messages": [{"role": "user", "content": prompt}],
            "stream": False,
            "options": {"temperature": 0, "num_ctx": num_ctx,
                        "num_predict": max_tokens},
        }).encode()
        req = urllib.request.Request(
            f"{self.ollama_url}/api/chat", body,
            {"Content-Type": "application/json"})
        return json.load(urllib.request.urlopen(req, timeout=900))["message"]["content"]

    def _ask_openai_compat(self, model, base_url, api_key_env, prompt,
                           max_tokens=8192):
        import os
        from openai import OpenAI
        api_key = os.getenv(api_key_env)
        if not api_key:
            raise RuntimeError(f"{api_key_env} not set")
        client = (OpenAI(api_key=api_key, base_url=base_url) if base_url
                  else OpenAI(api_key=api_key))
        kwargs = dict(model=model, messages=[
            {"role": "user", "content": prompt},
        ])
        if "gpt-5" in model:
            kwargs["max_completion_tokens"] = max_tokens
        else:
            kwargs["max_tokens"] = max_tokens
            kwargs["temperature"] = 0
        resp = client.chat.completions.create(**kwargs)
        return resp.choices[0].message.content or ""

    def _ask_mcp_cli(self, model, prompt):
        from src.llm.mcp_cli_analyzer import MCPCLIAnalyzer
        a = MCPCLIAnalyzer(case_id=self.case_id, model=model, timeout=900)
        # MCP-CLI has tools available but per-step prompt already contains
        # all evidence, so model should not need to call tools.
        return a.analyze(prompt)

    def _ask_model(self, prompt):
        """Dispatch to the right LLM backend based on provider."""
        if self.provider in ("llama", "qwen"):
            return self._ask_ollama(prompt)
        if self.provider == "deepseek":
            return self._ask_openai_compat(
                "deepseek-chat", "https://api.deepseek.com",
                "DEEPSEEK_API_KEY", prompt, max_tokens=16384)
        if self.provider == "openai":
            return self._ask_openai_compat(
                "gpt-5.1", None, "OPENAI_API_KEY", prompt, max_tokens=16384)
        if self.provider in ("sonnet", "opus"):
            return self._ask_mcp_cli(self.provider, prompt)
        raise ValueError(f"unknown provider {self.provider}")

    def _build_prompt(self, step_id, instruction, evidence):
        return (
            "You are a forensic analyst. Extract structured events from "
            "pre-retrieved Windows forensic evidence. The retrieval was done "
            "for you by ES queries scoped to the current case; you do NOT "
            "need to choose what to search.\n\n"
            f"FORENSIC DIMENSION ({step_id}): {instruction}\n\n"
            "RULES:\n"
            "- Use ONLY facts present in the evidence below. Do not invent.\n"
            "- Output ONLY a JSON array. No prose, no markdown, no preamble.\n"
            '- Each item: {"timestamp":"<exact>","artifact_type":"<source>",'
            '"description":"<concise fact with concrete identifiers>"}.\n'
            "- artifact_type must be one of: mft, registry, eventlog, prefetch, "
            "shimcache, amcache, usnjrnl, browser, srum, jumplist, lnk, "
            "recyclebin, powershell.\n"
            "- If the evidence is empty or irrelevant to this dimension, "
            "output [] (empty array).\n"
            "- Include EVERY relevant event in the evidence, not a sample.\n\n"
            "PRE-RETRIEVED EVIDENCE:\n"
            f"{evidence}\n\n"
            "Output only the JSON array now:"
        )

    def run_step(self, step_id, instruction, idx, total):
        evidence = self._retrieve_context(step_id)
        prompt = self._build_prompt(step_id, instruction, evidence)
        t0 = time.time()
        try:
            resp = self._ask_model(prompt)
        except Exception as exc:
            self._log(f"Step {idx}/{total} [{step_id}] ERROR: {exc}")
            return 0
        dt = time.time() - t0
        events = extract_json(resp)
        if not isinstance(events, list):
            events = []
        added = self._append_events(events, step_id)
        self._state["steps_done"].append(step_id)
        self._save_state()
        if self.verbose:
            self._log(f"  evidence {len(evidence)} chars, LLM {dt:.0f}s, "
                      f"response {len(resp or '')} chars")
        self._log(f"Step {idx}/{total} [{step_id}] -> "
                  f"{added} new events ({len(self._events)} total)")
        return added

    def run(self, **_ignored):
        # fresh jsonl unless resuming
        if not self._state["steps_done"]:
            self.jsonl_path.write_text("", encoding="utf-8")
        else:
            if self.jsonl_path.exists():
                for line in self.jsonl_path.read_text(encoding="utf-8").splitlines():
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        ev = json.loads(line)
                    except json.JSONDecodeError:
                        continue
                    self._seen.add(self._dedup_key(ev))
                    self._events.append(ev)

        checklist = TimelineOrchestrator.CHECKLIST
        total = len(checklist)
        done = set(self._state["steps_done"])
        t0 = time.time()
        for idx, (step_id, instruction) in enumerate(checklist, 1):
            if step_id in done:
                continue
            self.run_step(step_id, instruction, idx, total)

        elapsed = time.time() - t0
        summary = {
            "case_name": self.case_name,
            "case_id": self.case_id,
            "provider": self.provider,
            "mode": "rag-orchestrator",
            "model": self.model,
            "total_events": len(self._events),
            "elapsed_seconds": elapsed,
            "jsonl_path": str(self.jsonl_path),
            "checklist_steps": [s[0] for s in checklist],
        }
        self._log(f"DONE: {len(self._events)} events in {elapsed:.0f}s -> "
                  f"{self.jsonl_path}")
        return summary
