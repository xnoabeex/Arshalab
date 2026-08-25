"""Attack-chain reconstruction tool.

This module exposes the standardized attack-chain timeline reconstruction
pipeline as a single callable function suitable for use as an LLM tool
in interactive and MCP contexts.

Pipeline:
    1. Run 98-anchor evidence retrieval across 10 DFIR domains
       (`retrieve_evidence_v2.py`) with per-record compression to fit
       the ~350K prompt budget.
    2. Persist evidence dump to /reports/<case_id>/evidence_dumps/
    3. Run structured-prompt reconstruction (`reconstruct_timeline.py`)
    4. Persist attack-chain JSON to /reports/<case_id>/attack_chains/
    5. Return structured result with both artefact paths and chain summary

Design notes:
    - Subprocess wrappers around the existing CLI scripts: the same code
      paths that produced the published benchmark numbers are reused, so tool
      behavior is identical to the standalone evaluation pipeline.
    - Two-artefact persistence (evidence dump + chain JSON) ensures forensic
      completeness: analyst can audit the full evidence the LLM had access
      to, not only the 15-30 distilled chain steps.
    - Case-id -> case-key mapping is hardcoded for the three published cases;
      extending to a new case requires adding the case to retrieve_evidence.py
      CASES + INCIDENT_WINDOWS dicts and one entry here.
"""
from __future__ import annotations

import json
import shutil
import subprocess
import sys
from datetime import datetime
from pathlib import Path
from typing import Dict, Optional

# Resolve project root so subprocess calls work regardless of CWD.
_PROJECT_ROOT = Path(__file__).resolve().parents[2]

# Map ArshaLab case_ids to the case keys used by retrieve_evidence.py /
# reconstruct_timeline.py. Three published cases only.
_CASE_ID_TO_KEY: Dict[str, str] = {
    "case_20260128_141256": "kdfs",
    "case_20260323_032324": "magnet",
    "case_20260410_120043": "4orensics",
}

_CASE_KEY_TO_NAME: Dict[str, str] = {
    "kdfs": "KDFS_2023",
    "magnet": "Magnet_CTF_2022",
    "4orensics": "Hunter_4orensics",
}

_SUPPORTED_PROVIDERS = {"deepseek", "openai", "sonnet", "opus"}


def reconstruct_attack_chain(
    case_id: str,
    provider: str = "deepseek",
    run: int = 1,
    timeout_retrieve_sec: int = 300,
    timeout_reconstruct_sec: int = 300,
) -> Dict:
    """Run Mode 2 attack-chain reconstruction for a given case.

    Args:
        case_id: ArshaLab case identifier (e.g. case_20260323_032324).
        provider: LLM backend for reconstruction. One of
            {deepseek, openai, sonnet, opus}. Default: deepseek
            (highest cloud recall per §5.3).
        run: Independent run number (1, 2, 3) — Mode 2 evaluation uses
            three runs per (model, case) pair. Default 1.
        timeout_retrieve_sec: Hard timeout for evidence retrieval stage.
        timeout_reconstruct_sec: Hard timeout for LLM reconstruction stage.

    Returns:
        dict with status, evidence dump info, attack chain, persisted
        file paths, user-facing notification, and methodological
        provenance fields. On failure returns dict with status='error'
        and an error message.
    """
    case_key = _CASE_ID_TO_KEY.get(case_id)
    if case_key is None:
        return {
            "status": "error",
            "error": (
                f"Mode 2 reconstruction not yet wired for case_id={case_id}. "
                f"Supported case_ids: {list(_CASE_ID_TO_KEY.keys())}. "
                f"For a new case, register it in retrieve_evidence.py CASES "
                f"and INCIDENT_WINDOWS, then add the mapping here."
            ),
        }

    if provider not in _SUPPORTED_PROVIDERS:
        return {
            "status": "error",
            "error": (
                f"Provider '{provider}' not supported. "
                f"Choose one of {sorted(_SUPPORTED_PROVIDERS)}."
            ),
        }

    case_name = _CASE_KEY_TO_NAME[case_key]
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")

    # -- Stage 1: retrieve evidence via 98 anchors (v2) ----------------------
    retrieve_cmd = [
        sys.executable,
        str(_PROJECT_ROOT / "retrieve_evidence_v2.py"),
        "--case", case_key,
    ]
    try:
        retrieve_result = subprocess.run(
            retrieve_cmd,
            capture_output=True,
            text=True,
            timeout=timeout_retrieve_sec,
            cwd=str(_PROJECT_ROOT),
        )
    except subprocess.TimeoutExpired:
        return {
            "status": "error",
            "stage": "retrieve_evidence",
            "error": f"Evidence retrieval timed out after {timeout_retrieve_sec}s.",
        }

    if retrieve_result.returncode != 0:
        return {
            "status": "error",
            "stage": "retrieve_evidence",
            "error": "Evidence retrieval failed.",
            "stderr": (retrieve_result.stderr or "")[-2000:],
        }

    src_evidence = (_PROJECT_ROOT / "benchmark_results" / "mode2"
                    / f"evidence_{case_name}.json")
    if not src_evidence.exists():
        return {
            "status": "error",
            "stage": "retrieve_evidence",
            "error": f"Expected evidence file not found: {src_evidence}",
        }

    # Persist evidence dump to per-case reports directory (audit trail).
    reports_evidence_dir = _PROJECT_ROOT / "reports" / case_id / "evidence_dumps"
    reports_evidence_dir.mkdir(parents=True, exist_ok=True)
    persisted_evidence = reports_evidence_dir / f"{timestamp}_evidence.json"
    shutil.copy(src_evidence, persisted_evidence)

    with open(persisted_evidence, "r", encoding="utf-8") as f:
        evidence_payload = json.load(f)
    evidence_records = evidence_payload.get("total_records", 0)
    anchors_used = len(evidence_payload.get("anchors_used", []))
    evidence_size_bytes = persisted_evidence.stat().st_size

    # -- Stage 2: reconstruct attack chain via structured LLM prompt ----
    reconstruct_cmd = [
        sys.executable,
        str(_PROJECT_ROOT / "reconstruct_timeline.py"),
        "--provider", provider,
        "--case", case_key,
        "--run", str(run),
    ]
    try:
        reconstruct_result = subprocess.run(
            reconstruct_cmd,
            capture_output=True,
            text=True,
            timeout=timeout_reconstruct_sec,
            cwd=str(_PROJECT_ROOT),
        )
    except subprocess.TimeoutExpired:
        return {
            "status": "error",
            "stage": "reconstruct_timeline",
            "error": f"Reconstruction timed out after {timeout_reconstruct_sec}s.",
            "evidence_dump_path": str(persisted_evidence),
        }

    if reconstruct_result.returncode != 0:
        return {
            "status": "error",
            "stage": "reconstruct_timeline",
            "error": "Attack-chain reconstruction failed.",
            "stderr": (reconstruct_result.stderr or "")[-2000:],
            "evidence_dump_path": str(persisted_evidence),
        }

    src_chain = (_PROJECT_ROOT / "benchmark_results" / "mode2"
                 / f"chain_{case_name}_{provider}_run{run}.json")
    if not src_chain.exists():
        return {
            "status": "error",
            "stage": "reconstruct_timeline",
            "error": f"Expected chain file not found: {src_chain}",
            "evidence_dump_path": str(persisted_evidence),
        }

    chains_dir = _PROJECT_ROOT / "reports" / case_id / "attack_chains"
    chains_dir.mkdir(parents=True, exist_ok=True)
    persisted_chain = chains_dir / f"{timestamp}_chain.json"
    shutil.copy(src_chain, persisted_chain)

    with open(persisted_chain, "r", encoding="utf-8") as f:
        attack_chain = json.load(f)
    chain_length = len(attack_chain) if isinstance(attack_chain, list) else 0

    # Grounding is measured on the chain that was just produced, not asserted. Every factual entity
    # the chain states - filename, Event ID, IP, SID, hash, domain, email - is looked up in the
    # persisted evidence: Event IDs against the records' typed `event_id` field, everything else
    # against the record bodies with the `_anchor` label removed, because anchor names embed Event
    # IDs and would otherwise make them unfalsifiable. Events stating nothing checkable are reported
    # separately rather than counted as grounded, so `checked_share` shows how much of the chain the
    # figure actually covers.
    grounding = {"available": False,
                 "note": "grounding check unavailable in this environment"}
    try:
        import importlib.util as _ilu
        _spec = _ilu.spec_from_file_location(
            "_sfs", str(_PROJECT_ROOT / "score_fabrication_strict.py"))
        _sfs = _ilu.module_from_spec(_spec)
        _spec.loader.exec_module(_sfs)
        _r = _sfs.score_chain(str(persisted_chain), str(persisted_evidence))
        grounding = {
            "available": True,
            "events": _r["events"],
            "events_with_checkable_fact": _r["events_with_checkable_fact"],
            "checked_share": _r["metric_coverage"],
            "ungrounded_events": _r["ungrounded_events"],
            "ungrounded_rate_over_checked": _r["strict_fabrication_rate"],
            "missing_entities": _r["missing_entities"],
            "ungrounded_detail": _r["offenders"],
        }
    except Exception as exc:                      # never fail the tool over its own diagnostics
        grounding["note"] = "grounding check failed: %s" % str(exc)[:160]

    return {
        "status": "completed",
        "case_id": case_id,
        "case_name": case_name,
        "provider": provider,
        "run": run,
        "timestamp": timestamp,
        "evidence_dump": {
            "path": str(persisted_evidence),
            "records": evidence_records,
            "anchors_used": anchors_used,
            "size_mb": round(evidence_size_bytes / 1024 / 1024, 2),
        },
        "attack_chain": attack_chain,
        "attack_chain_path": str(persisted_chain),
        "chain_length": chain_length,
        "notification": (
            f"Evidence dump preserved: {evidence_records} records from "
            f"{anchors_used} anchor queries ("
            f"{round(evidence_size_bytes / 1024 / 1024, 2)} MB). "
            f"Attack chain ({chain_length} steps) distilled from this "
            f"evidence using {provider}. Both artefacts are persisted in "
            f"/reports/{case_id}/ for audit and analyst verification."
        ),
        "grounding": grounding,
        "grounding_note": (
            "Measured on this chain, not asserted. Retrieval bounds what the model is shown, "
            "but it does not by itself prevent a statement that goes beyond the evidence, so "
            "the chain is checked after the fact. `ungrounded_rate_over_checked` is computed "
            "over the events that state a checkable fact; `checked_share` reports how large "
            "that subset is, and events below it are neither credited nor penalised."
        ),
    }
