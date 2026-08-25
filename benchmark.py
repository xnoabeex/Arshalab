#!/usr/bin/env python3
"""
ArshaLab Benchmark Runner
=========================
Evaluates LLM forensic analyzers across 4 providers on:
  1. Response Latency (T_total)
  2. Factual Accuracy (Precision, Recall, F1, Hallucination Rate)
  3. Consistency (Factual Overlap + Semantic Similarity across N runs)
  4. LLM-as-Judge (Accuracy, Completeness, Reasoning, Hallucinations — 1-5 scale)

Usage:
    python benchmark.py                     # Run full benchmark (all providers, all questions)
    python benchmark.py --providers claude   # Single provider
    python benchmark.py --runs 3            # 3 runs for consistency
    python benchmark.py --questions 1,2,3   # Specific questions only
    python benchmark.py --dry-run           # Show questions without calling LLMs
    python benchmark.py --judge             # Enable LLM-as-judge evaluation (requires API key)

    # File-based judge workflow (for Claude Desktop subscription — no API key needed):
    python benchmark.py --export-judge-prompts results.json    # Generate prompts file
    python benchmark.py --import-judge-scores prompts.json     # Import filled scores
    python benchmark.py --import-judge-scores prompts.json --merge-into results.json  # Merge into results
"""

import os
import sys
import json
import time
import argparse
import re
import csv
from datetime import datetime
from typing import List, Dict, Any, Optional, Tuple
from collections import Counter
from pathlib import Path

import requests

sys.path.insert(0, os.path.dirname(__file__))
os.chdir(os.path.dirname(__file__))

# ============================================================
# CONFIGURATION
# ============================================================

ES_URL = "http://localhost:9200"

# Cases to benchmark against (all must exist in ES)
BENCHMARK_CASES = [
    {"case_id": "case_20260323_032324", "case_name": "CTF_Magnet_2022"},
    {"case_id": "case_20260128_141256", "case_name": "KDFS_2023"},
    {"case_id": "case_20260410_120043", "case_name": "Hunter_4orensics"},
]

# Default case for single-case mode
BENCHMARK_CASE_ID = "case_20260323_032324"
BENCHMARK_CASE_NAME = "CTF_Magnet_2022"

# LLM providers to test
PROVIDERS = {
    # The seven models reported in the paper: four cloud + three local (RAG).
    "deepseek": {
        "class": "DeepSeekAnalyzer",
        "module": "src.llm.deepseek_analyzer",
        "init_kwargs": {},
        "display_name": "DeepSeek V3",
    },
    "opus": {
        "class": "OpusAnalyzer",
        "module": "src.llm.opus_analyzer",
        "init_kwargs": {"session_id": "benchmark"},
        "display_name": "Claude Opus 4.1",
    },
    "claude": {
        "class": "ClaudeAnalyzer",
        "module": "src.llm.claude_analyzer",
        "init_kwargs": {"session_id": "benchmark"},
        "display_name": "Claude Sonnet 4.5",
    },
    "openai": {
        "class": "OpenAIAnalyzer",
        "module": "src.llm.openai_analyzer",
        "init_kwargs": {},
        "display_name": "OpenAI GPT-5.1",
    },
    "ollama_rag_llama8b_v3": {
        "class": "OllamaRAGAnalyzerV2",
        "module": "src.llm.ollama_rag_analyzer_v2",
        "init_kwargs": {"model": "llama3.1:8b"},
        "display_name": "Llama 3.1 8B + RAG",
    },
    "ollama_rag_qwen14b_v3": {
        "class": "OllamaRAGAnalyzerV2",
        "module": "src.llm.ollama_rag_analyzer_v2",
        "init_kwargs": {"model": "qwen2.5:14b"},
        "display_name": "Qwen 2.5 14B + RAG",
    },
    "ollama_rag_phi4": {
        "class": "OllamaRAGAnalyzerV2",
        "module": "src.llm.ollama_rag_analyzer_v2",
        "init_kwargs": {"model": "phi4:14b"},
        "display_name": "Phi-4 14B + RAG",
    },
}

# Question mode presets: retrieval (short answers) vs analysis (deep investigation)
QUESTION_MODES = {
    "retrieval": {
        "description": "Short factual questions, single-fact answers",
        "max_tokens": 2048,
        "max_tool_calls": 25,
    },
    "analysis": {
        "description": "Deep investigation, timeline reconstruction, multi-step reasoning",
        "max_tokens": 8192,
        "max_tool_calls": 80,
    },
}

# ============================================================
# QUESTIONS LOADING
# ============================================================
# Questions are loaded from JSON files per case.
# Each JSON file contains case-specific questions with expected_facts.

QUESTIONS_DIR = Path("benchmark/questions")

def extract_keywords_recursive(obj, keywords: list):
    """Recursively extract string values from nested dicts/lists as keywords."""
    if isinstance(obj, str):
        # Skip evaluation notes, long descriptions, and full sentences
        skip = (
            len(obj) >= 80 or
            obj.startswith("Must ") or
            obj.startswith("This is") or
            obj.startswith("Cannot ") or
            obj.startswith("Hypothesis ") or
            " suggests " in obj or
            " may have " in obj or
            " visible in " in obj or
            obj.count(" ") >= 7  # Full sentences with 8+ words
        )
        if not skip:
            keywords.append(obj)
    elif isinstance(obj, list):
        # If all elements are strings, treat as keyword GROUP (any match counts)
        if all(isinstance(item, str) for item in obj) and len(obj) > 1:
            # Filter out long sentences from the group
            filtered = [s for s in obj if len(s) < 80 and s.count(" ") < 7]
            if filtered:
                keywords.append(filtered)  # Append as list = keyword group
        else:
            # Mixed types or nested lists - recurse deeper
            for item in obj:
                extract_keywords_recursive(item, keywords)
    elif isinstance(obj, dict):
        for key, value in obj.items():
            # Skip meta keys like 'evaluation', 'must_acknowledge'
            if key not in ("evaluation", "must_acknowledge", "must_note"):
                extract_keywords_recursive(value, keywords)


def load_case_questions(case_name: str, provider: str = None) -> Tuple[str, List[Dict]]:
    """
    Load scenario and questions from JSON file for a specific case.

    Args:
        case_name: Name like 'KDFS_2023', 'CTF_Magnet_2022', 'DFC_2022'
        provider: LLM provider name (e.g. 'openai', 'deepseek'). If a provider-specific
                  file exists (e.g. KDFS_2023_openai.json), it will be used instead of
                  the default. This allows per-model keyword calibration.

    Returns:
        Tuple of (scenario_text, list of question dicts with keywords)
    """
    # Try provider-specific file first, fallback to default
    json_path = None
    if provider:
        provider_path = QUESTIONS_DIR / f"{case_name}_{provider}.json"
        if provider_path.exists():
            json_path = provider_path
            print(f"    Using provider-specific questions: {provider_path.name}")

    if json_path is None:
        json_path = QUESTIONS_DIR / f"{case_name}.json"

    if not json_path.exists():
        print(f"  [!] Questions file not found: {json_path}")
        return "", []

    with open(json_path, 'r', encoding='utf-8') as f:
        data = json.load(f)

    # Handle new format with scenario + questions
    if isinstance(data, dict) and "questions" in data:
        scenario = data.get("scenario", "")
        raw_questions = data["questions"]
        evaluation_criteria = data.get("evaluation_criteria", {})
    # Handle old format (list of questions)
    elif isinstance(data, list):
        scenario = ""
        raw_questions = data
        evaluation_criteria = {}
    else:
        return "", []

    # Convert expected_facts to keywords list for compatibility
    questions = []
    for q in raw_questions:
        # Extract all values from expected_facts as keywords (recursive for nested dicts)
        keywords = []
        expected_facts = q.get("expected_facts", {})
        extract_keywords_recursive(expected_facts, keywords)

        # Also include explicit keywords if present
        if "keywords" in q:
            keywords.extend(q["keywords"])

        # Remove duplicates while preserving order
        seen = set()
        unique_keywords = []
        for kw in keywords:
            kw_lower = kw.lower() if isinstance(kw, str) else str(kw)
            if kw_lower not in seen:
                seen.add(kw_lower)
                unique_keywords.append(kw)

        questions.append({
            "id": q["id"],
            "question": q["question"],
            "category": q.get("category", "retrieval"),
            "keywords": unique_keywords,
            "expected_facts": expected_facts,
            "evaluation_criteria": evaluation_criteria.get(q.get("category", "retrieval"), ""),
        })

    return scenario, questions


# Legacy fallback questions (used if JSON not found)
LEGACY_QUESTIONS = [
    {
        "id": "Q01",
        "question": "What is the primary user account on this system?",
        "category": "retrieval",
        "ground_truth_builder": "user_account",
    },
    {
        "id": "Q02",
        "question": "What were the most frequently executed programs on this system? List the top 5 with run counts.",
        "category": "retrieval",
        "ground_truth_builder": "top_programs",
    },
    {
        "id": "Q03",
        "question": "What websites did the user visit most frequently? List the top domains.",
        "category": "retrieval",
        "ground_truth_builder": "top_websites",
    },
    {
        "id": "Q04",
        "question": "Were there any failed logon attempts? Provide Event IDs and counts.",
        "category": "retrieval",
        "ground_truth_builder": "failed_logons",
    },
    {
        "id": "Q05",
        "question": "What applications generated the most network traffic according to SRUM?",
        "category": "retrieval",
        "ground_truth_builder": "srum_traffic",
    },
    {
        "id": "Q06",
        "question": "What files did the user recently access based on JumpList and LNK shortcuts?",
        "category": "analysis",
        "ground_truth_builder": "recent_files",
    },
    {
        "id": "Q07",
        "question": "What chat or social media applications were installed or used?",
        "category": "analysis",
        "ground_truth_builder": "social_apps",
    },
    {
        "id": "Q08",
        "question": "How many Shimcache entries exist and what executables are in the top positions?",
        "category": "retrieval",
        "ground_truth_builder": "shimcache_top",
    },
    {
        "id": "Q09",
        "question": "What programs are recorded in Amcache? List notable executables with their SHA1 hashes.",
        "category": "retrieval",
        "ground_truth_builder": "amcache_programs",
    },
    {
        "id": "Q10",
        "question": "Based on all available evidence, provide a comprehensive investigation summary. What happened on this system?",
        "category": "reasoning",
        "ground_truth_builder": "investigation_summary",
    },
]


def build_ground_truth(case_id: str) -> Dict[str, dict]:
    """
    Auto-generate ground truth keywords for each question by querying ES.
    Returns dict mapping question_id -> {keywords: [...], verification_queries: [...]}
    """
    gt = {}

    # Q01: User account - extract from LNK target paths
    users = set()
    try:
        r = requests.post(f"{ES_URL}/forensic-lnk/_search", json={
            "size": 20,
            "query": {"term": {"case_id.keyword": case_id}},
            "_source": ["target_path"],
        }, timeout=10)
        for h in r.json().get("hits", {}).get("hits", []):
            path = h["_source"].get("target_path", "")
            m = re.search(r'[Uu]sers[/\\]([^/\\]+)', path)
            if m and m.group(1).lower() not in ("public", "default", "all users", "default user"):
                users.add(m.group(1).lower())
    except Exception:
        pass
    # Also try from jumplist
    try:
        r = requests.post(f"{ES_URL}/forensic-jumplist/_search", json={
            "size": 20,
            "query": {"term": {"case_id.keyword": case_id}},
            "_source": ["target_path"],
        }, timeout=10)
        for h in r.json().get("hits", {}).get("hits", []):
            path = h["_source"].get("target_path", "")
            m = re.search(r'[Uu]sers[/\\]([^/\\]+)', path)
            if m and m.group(1).lower() not in ("public", "default", "all users", "default user"):
                users.add(m.group(1).lower())
    except Exception:
        pass
    gt["Q01"] = {"keywords": list(users), "verification_queries": []}

    # Q02: Top programs from prefetch
    top_exes = []
    try:
        r = requests.post(f"{ES_URL}/forensic-prefetch/_search", json={
            "size": 0,
            "query": {"term": {"case_id.keyword": case_id}},
            "aggs": {"top": {"terms": {"field": "executable_name", "size": 30, "order": {"max_run": "desc"}},
                             "aggs": {"max_run": {"max": {"field": "run_count"}}}}},
        }, timeout=10)
        buckets = r.json().get("aggregations", {}).get("top", {}).get("buckets", [])
        for b in buckets:
            name = b["key"].lower().replace(".exe", "")
            # Filter out Windows system/background processes
            system_procs = {"searchprotocolhost", "searchfilterhost", "dllhost",
                          "backgroundtaskhost", "runtimebroker", "mousocoreworker",
                          "taskhostw", "sppsvc", "svchost", "csrss", "smss",
                          "wininit", "winlogon", "services", "lsass", "conhost",
                          "dwm", "sihost", "ctfmon", "fontdrvhost", "audiodg",
                          "dashost", "sihclient", "musnotification",
                          "securityhealthservice", "securityhealthhost",
                          "wmiprvse", "searchindexer", "searchui",
                          "shellexperiencehost", "startmenuexperiencehost",
                          "textinputhost", "systemsettings",
                          "applicationframehost", "lockapp", "logonui",
                          "trustedinstaller", "tiworker", "microsoftedgeupdate",
                          "consent", "mpcmdrun", "mprecoverytask", "mpsigstub",
                          "compattelrunner", "devicecensus", "wsqmcons",
                          "identity_helper", "setup", "update_notifier",
                          "comppkgsrv", "mscorsvw", "ngen", "tabtip",
                          "monotificationux", "hxtsr", "googleupdate",
                          "updater", "msmpengcp", "op-msedge",
                          "98.0.4758.82_97.0.4692.99_chr"}
            # Also skip version-suffixed names (e.g. "op-msedge-37d25f9a")
            skip = name in system_procs
            if not skip:
                for sp in system_procs:
                    if name.startswith(sp + "-") or name.startswith(sp + "_"):
                        skip = True
                        break
            # Skip names with hashes/version strings (e.g. "98.0.4758...")
            if not skip and any(c.isdigit() for c in name[:3]):
                skip = True
            if not skip:
                top_exes.append(name)
    except Exception:
        pass
    gt["Q02"] = {"keywords": [top_exes[:10]] if top_exes else [], "verification_queries": []}

    # Q03: Top websites from browser
    top_domains = []
    try:
        r = requests.post(f"{ES_URL}/forensic-browser/_search", json={
            "size": 0,
            "query": {"term": {"case_id.keyword": case_id}},
            "aggs": {"domains": {"terms": {"field": "domain", "size": 10, "order": {"_count": "desc"}}}},
        }, timeout=10)
        buckets = r.json().get("aggregations", {}).get("domains", {}).get("buckets", [])
        for b in buckets[:5]:
            d = b["key"].lower()
            if d and d not in ("", "none"):
                top_domains.append(d)
    except Exception:
        pass
    gt["Q03"] = {"keywords": [top_domains[:5]] if top_domains else [], "verification_queries": []}

    # Q04: Failed logons
    kw_04 = ["4625"]
    try:
        r = requests.post(f"{ES_URL}/forensic-eventlog/_count", json={
            "query": {"bool": {"must": [{"term": {"event_id": 4625}}],
                               "filter": [{"term": {"case_id.keyword": case_id}}]}},
        }, timeout=10)
        count = r.json().get("count", 0)
        if count > 0:
            kw_04.append(str(count))
    except Exception:
        pass
    gt["Q04"] = {"keywords": kw_04, "verification_queries": []}

    # Q05: SRUM top traffic - extract app name from full path
    srum_apps = set()
    try:
        # Check both bytes_sent and bytes_received
        for sort_field in ["bytes_sent", "bytes_received"]:
            r = requests.post(f"{ES_URL}/forensic-srum/_search", json={
                "size": 10,
                "query": {"term": {"case_id.keyword": case_id}},
                "sort": [{sort_field: "desc"}],
                "_source": ["app_name"],
            }, timeout=10)
            for h in r.json().get("hits", {}).get("hits", []):
                name = h["_source"].get("app_name", "")
                if name and name.lower() not in ("", "none") and len(name) > 2:
                    basename = name.split("\\")[-1].split("/")[-1].lower()
                    basename = basename.replace(".exe", "")
                    # Skip system procs and UWP package names
                    if basename and basename not in ("svchost", "system", "dashost") \
                       and "8wekyb3d8bbwe" not in name and len(basename) < 40:
                        srum_apps.add(basename)
    except Exception:
        pass
    srum_list = sorted(srum_apps)
    # Mixed keywords: individual (system service LLM rarely mentions) + group pool
    well_known = {"chrome", "msedge", "edge", "firefox", "iexplore", "cmd", "powershell",
                  "notepad", "explorer", "python", "java", "javaw"}
    obscure_srum = [s for s in srum_list if s not in well_known]
    if obscure_srum and srum_list:
        gt["Q05"] = {"keywords": [obscure_srum[0], srum_list[:10]], "verification_queries": []}
    elif srum_list:
        gt["Q05"] = {"keywords": [srum_list[:10]], "verification_queries": []}
    else:
        gt["Q05"] = {"keywords": [], "verification_queries": []}

    # Q06: Recent files from jumplist + LNK
    recent_kw = []
    try:
        r = requests.post(f"{ES_URL}/forensic-jumplist/_search", json={
            "size": 50,
            "query": {"term": {"case_id.keyword": case_id}},
            "_source": ["target_path", "target_name"],
        }, timeout=10)
        for h in r.json().get("hits", {}).get("hits", []):
            s = h["_source"]
            target = s.get("target_name") or s.get("target_path", "")
            if target and not target.startswith("http") and not target.startswith("ms-"):
                # Extract filename
                fname = target.split("\\")[-1].split("/")[-1].lower()
                # Skip overly long filenames (URLs, encoded strings) - LLMs won't match them
                if fname and "." in fname and 5 < len(fname) < 60 and "%" not in fname \
                   and fname.isascii():
                    recent_kw.append(fname)
    except Exception:
        pass
    # Also search LNK files
    try:
        r = requests.post(f"{ES_URL}/forensic-lnk/_search", json={
            "size": 50,
            "query": {"term": {"case_id.keyword": case_id}},
            "_source": ["target_path"],
        }, timeout=10)
        for h in r.json().get("hits", {}).get("hits", []):
            target = h["_source"].get("target_path", "")
            if target:
                fname = target.split("\\")[-1].split("/")[-1].lower()
                if fname and "." in fname and 5 < len(fname) < 60 and "%" not in fname \
                   and fname.isascii():
                    recent_kw.append(fname)
    except Exception:
        pass
    # Also include top prefetch executables (LLM often correlates across artifacts)
    try:
        r = requests.post(f"{ES_URL}/forensic-prefetch/_search", json={
            "size": 0,
            "query": {"term": {"case_id.keyword": case_id}},
            "aggs": {"exes": {"terms": {"field": "executable_name", "size": 30}}},
        }, timeout=10)
        for b in r.json().get("aggregations", {}).get("exes", {}).get("buckets", []):
            fname = b["key"].lower()
            if fname and fname.endswith(".exe") and 5 < len(fname) < 40 and fname.isascii():
                recent_kw.append(fname.replace(".exe", ""))
    except Exception:
        pass
    recent_pool = list(set(recent_kw))
    gt["Q06"] = {"keywords": [recent_pool[:20]] if recent_pool else [], "verification_queries": []}

    # Q07: Social/chat apps - search specifically in exe names, paths, and URLs
    social_kw = []
    social_terms = ["discord", "telegram", "whatsapp", "skype", "teams", "slack",
                    "signal", "viber", "kakaotalk", "wechat", "messenger"]
    try:
        for term in social_terms:
            found = False
            # Check prefetch (executable names)
            r = requests.post(f"{ES_URL}/forensic-prefetch/_count", json={
                "query": {"bool": {"must": [{"wildcard": {"executable_name": f"*{term.upper()}*"}}],
                                   "filter": [{"term": {"case_id.keyword": case_id}}]}},
            }, timeout=5)
            if r.status_code == 200 and r.json().get("count", 0) > 0:
                found = True
            # Check browser URLs
            if not found:
                r = requests.post(f"{ES_URL}/forensic-browser/_count", json={
                    "query": {"bool": {"must": [{"wildcard": {"url": f"*{term}*"}}],
                                       "filter": [{"term": {"case_id.keyword": case_id}}]}},
                }, timeout=5)
                if r.status_code == 200 and r.json().get("count", 0) > 0:
                    found = True
            # Check shimcache/amcache paths
            if not found:
                for idx in ["forensic-shimcache", "forensic-amcache"]:
                    r = requests.post(f"{ES_URL}/{idx}/_count", json={
                        "query": {"bool": {"must": [{"match_phrase": {"path": term}}],
                                           "filter": [{"term": {"case_id.keyword": case_id}}]}},
                    }, timeout=5)
                    if r.status_code == 200 and r.json().get("count", 0) > 0:
                        found = True
                        break
            if found:
                social_kw.append(term)
    except Exception:
        pass
    gt["Q07"] = {"keywords": [social_kw] if social_kw else [], "verification_queries": []}

    # Q08: Shimcache entries (aggregated unique filenames)
    shim_kw = []
    try:
        r = requests.post(f"{ES_URL}/forensic-shimcache/_search", json={
            "size": 0,
            "query": {"term": {"case_id.keyword": case_id}},
            "aggs": {"files": {"terms": {"field": "filename.keyword", "size": 100}}},
        }, timeout=10)
        for b in r.json().get("aggregations", {}).get("files", {}).get("buckets", []):
            fname = b["key"].lower()
            if fname and ".exe" in fname and 4 < len(fname) < 50 and fname.isascii():
                clean = fname.replace(".exe", "")
                if len(clean) > 3:
                    shim_kw.append(clean)
    except Exception:
        pass
    # Mixed keywords: individual (obscure system entry) + group pool
    obscure_shim = [s for s in shim_kw if s not in well_known and s not in
                    {"setup", "dllhost", "discord", "regedit", "dismhost", "update"}]
    if obscure_shim and shim_kw:
        gt["Q08"] = {"keywords": [obscure_shim[0], shim_kw[:20]], "verification_queries": []}
    elif shim_kw:
        gt["Q08"] = {"keywords": [shim_kw[:20]], "verification_queries": []}
    else:
        gt["Q08"] = {"keywords": [], "verification_queries": []}

    # Q09: Amcache programs (aggregated unique filenames)
    amcache_kw = []
    try:
        r = requests.post(f"{ES_URL}/forensic-amcache/_search", json={
            "size": 0,
            "query": {"term": {"case_id.keyword": case_id}},
            "aggs": {"files": {"terms": {"field": "filename.keyword", "size": 100}}},
        }, timeout=10)
        for b in r.json().get("aggregations", {}).get("files", {}).get("buckets", []):
            fname = b["key"].lower()
            if fname and 4 < len(fname) < 50 and fname.isascii():
                clean = fname.replace(".exe", "")
                if len(clean) > 3:
                    amcache_kw.append(clean)
    except Exception:
        pass
    gt["Q09"] = {"keywords": [amcache_kw[:20]] if amcache_kw else [], "verification_queries": []}

    # Q10: Investigation summary - must identify the user
    gt["Q10"] = {"keywords": list(users)[:1], "verification_queries": []}

    return gt


# ============================================================
# ES FACT VERIFICATION
# ============================================================

def verify_fact_in_es(query_def: dict, case_id: str) -> dict:
    """Run a verification query against ES and return result."""
    index = query_def["index"]
    es_query = query_def["query"]

    body = {
        "size": 0,
        "query": {
            "bool": {
                "must": [es_query],
                "filter": [{"bool": {"should": [{"term": {"case_id.keyword": case_id}}, {"term": {"_meta.case_id.keyword": case_id}}]}}],
            }
        },
    }

    try:
        r = requests.post(f"{ES_URL}/{index}/_search", json=body, timeout=10)
        if r.status_code == 200:
            total = r.json().get("hits", {}).get("total", {}).get("value", 0)
            return {
                "description": query_def["description"],
                "expected_min": query_def["min_results"],
                "actual": total,
                "passed": total >= query_def["min_results"],
            }
    except Exception as e:
        return {
            "description": query_def["description"],
            "expected_min": query_def["min_results"],
            "actual": 0,
            "passed": False,
            "error": str(e),
        }


def _timestamp_utc_kst_variants(ts_str: str) -> list:
    """
    Given a timestamp string, return both UTC and KST (UTC+9) variants.
    Handles formats: 'YYYY-MM-DD HH:MM:SS', 'YYYY-MM-DD HH:MM', 'HH:MM:SS', 'HH:MM'
    """
    import re
    from datetime import datetime, timedelta
    variants = []

    # Full datetime: YYYY-MM-DD HH:MM:SS or YYYY-MM-DD HH:MM
    m = re.match(r'^(\d{4}-\d{2}-\d{2})[T ](\d{2}:\d{2}(?::\d{2})?)$', ts_str.strip())
    if m:
        date_part, time_part = m.group(1), m.group(2)
        fmt = "%H:%M:%S" if len(time_part) == 8 else "%H:%M"
        try:
            t = datetime.strptime(f"{date_part} {time_part}", f"%Y-%m-%d {fmt}")
            t_kst = t + timedelta(hours=9)
            t_utc = t - timedelta(hours=9)
            for dt in [t, t_kst, t_utc]:
                variants.append(dt.strftime(f"%Y-%m-%d {fmt}").lower())
                variants.append(dt.strftime(f"%Y-%m-%dT{fmt}").lower())
                variants.append(dt.strftime(fmt).lower())  # time only
        except ValueError:
            pass
        return variants

    # Time only: HH:MM:SS or HH:MM
    m = re.match(r'^(\d{2}:\d{2}(?::\d{2})?)$', ts_str.strip())
    if m:
        time_part = m.group(1)
        fmt = "%H:%M:%S" if len(time_part) == 8 else "%H:%M"
        try:
            t = datetime.strptime(time_part, fmt)
            t_kst = t + timedelta(hours=9)
            t_utc = t - timedelta(hours=9)
            for dt in [t, t_kst, t_utc]:
                variants.append(dt.strftime(fmt).lower())
        except ValueError:
            pass
        return variants

    return variants


def _get_keyword_variants(kw: str) -> list:
    """
    Generate multiple matching variants for a keyword to improve recall accuracy.
    E.g., 'msedge' -> ['msedge', 'edge', 'microsoft edge']
    """
    kw_lower = kw.lower()
    variants = [kw_lower]

    # Timestamp variants: generate both UTC and KST (UTC+9) forms
    ts_variants = _timestamp_utc_kst_variants(kw)
    if ts_variants:
        variants.extend(ts_variants)
        return list(dict.fromkeys(variants))  # deduplicate preserving order

    # Common exe name -> display name mappings
    aliases = {
        "msedge": ["microsoft edge", "edge", "ms edge"],
        "chrome": ["google chrome"],
        "iexplore": ["internet explorer", "ie"],
        "powershell": ["powershell.exe", "windows powershell"],
        "discord": ["discord.exe"],
        "skype": ["skype.exe"],
        "whatsapp": ["whatsapp.exe", "whats app"],
        "telegram": ["telegram.exe"],
        "teams": ["microsoft teams", "ms teams"],
        "slack": ["slack.exe"],
        "teamviewer_service": ["teamviewer", "team viewer"],
        "mpcmdrun": ["windows defender", "defender"],
        "ngen": ["ngen.exe", ".net native"],
        "msiexec": ["msiexec.exe", "windows installer"],
        "dosvc": ["delivery optimization", "do service"],
        "zerotieroneservice": ["zerotier", "zero tier"],
        "smartscreen": ["windows smartscreen", "smart screen"],
        "securityhealthhost": ["windows security", "security health"],
        "gamingservicesnet": ["gamingservices.net", "gaming services"],
        "gamingservices": ["gaming services"],
        "dismhost": ["dism", "dismhost.exe"],
        "acrord32": ["acrobat", "adobe reader", "acrobat reader", "adobe acrobat"],
        "slui": ["software licensing", "slui.exe"],
        "excel": ["microsoft excel", "excel.exe"],
        "net": ["net.exe", "net command"],
        "net1": ["net1.exe"],
        "whoami": ["whoami.exe"],
        "filecoauth": ["file co-authoring", "office file co-auth"],
        "filesyncconfig": ["file sync", "onedrive sync"],
        "filesynchelper": ["file sync helper", "onedrive"],
        "am_delta": ["antimalware", "defender update"],
    }

    if kw_lower in aliases:
        variants.extend(aliases[kw_lower])

    # Semantic synonyms for common forensic terms
    semantic_synonyms = {
        "copied": ["transferred", "moved", "written", "placed", "delivered", "transfer", "copy", "move"],
        "transferred": ["copied", "moved", "written", "placed", "delivered", "transfer", "copy", "move"],
        "brought": ["transferred", "copied", "delivered", "placed", "transfer", "carry"],
        "seconds": ["second", "minute", "minutes", "immediately", "shortly", "moment"],
        "shortly after": ["immediately after", "right after", "minutes later", "seconds later",
                         "shortly thereafter", "moments after", "soon after", "1 minute",
                         "within a minute", "within minutes"],
        "connected": ["plugged", "inserted", "attached", "detected", "mounted"],
        "executed": ["ran", "launched", "started", "run", "invoked"],
        "deleted": ["removed", "erased", "purged", "cleared"],
        "uploaded": ["shared", "sent", "transmitted", "distributed"],
        "downloaded": ["fetched", "retrieved", "obtained"],
        "installed": ["deployed", "set up", "configured"],
        "suspicious": ["malicious", "anomalous", "unusual", "concerning"],
        "accomplice": ["co-conspirator", "partner", "collaborator", "associate"],
    }
    if kw_lower in semantic_synonyms:
        variants.extend(semantic_synonyms[kw_lower])

    # Only add .exe version for program-like names (not files with other extensions, not non-ASCII)
    known_extensions = {".xlsx", ".docx", ".pdf", ".zip", ".rar", ".ost", ".pst",
                        ".txt", ".csv", ".log", ".html", ".htm", ".png", ".jpg",
                        ".mp4", ".json", ".bat", ".vbs", ".ps1", ".evtx"}
    has_other_extension = any(kw_lower.endswith(ext) for ext in known_extensions)
    has_non_ascii = not kw_lower.isascii()
    # Skip .exe for timestamps, dates, numbers, paths, emails
    import re as _re
    is_timestamp = bool(_re.match(r'^\d{4}-\d{2}-\d{2}', kw_lower) or _re.match(r'^\d{2}:\d{2}', kw_lower))
    is_path = '\\' in kw_lower or '/' in kw_lower
    is_email = '@' in kw_lower
    is_hash = bool(_re.match(r'^[a-f0-9]{32,}$', kw_lower))
    if (not kw_lower.endswith(".exe") and not has_other_extension and not has_non_ascii
            and not is_timestamp and not is_path and not is_email and not is_hash):
        variants.append(kw_lower + ".exe")

    return variants


def check_keywords_in_response(response: str, keywords: list) -> dict:
    """Check which ground truth keywords appear in the response (with fuzzy matching).

    Supports keyword groups: if a keyword entry is a list, ANY member matching
    counts as the group being found.  This handles questions where the LLM may
    report different-but-equally-valid items from the same artifact pool.
    """
    response_lower = response.lower()
    found = []
    missing = []
    for kw in keywords:
        if isinstance(kw, list):
            # Keyword group – any match counts
            group_matched = False
            for sub_kw in kw:
                variants = _get_keyword_variants(sub_kw)
                if any(v in response_lower for v in variants):
                    found.append(sub_kw)
                    group_matched = True
                    break
            if not group_matched:
                missing.append(kw[0] if kw else "?")
        else:
            variants = _get_keyword_variants(kw)
            matched = any(v in response_lower for v in variants)
            if matched:
                found.append(kw)
            else:
                missing.append(kw)

    total = len(keywords)
    recall = len(found) / total if total > 0 else 0

    return {
        "total_keywords": total,
        "found": found,
        "missing": missing,
        "recall": recall,
    }


def _fuzzy_exe_match(exe_name: str, case_id: str) -> Optional[str]:
    """
    Check if exe_name is a close match to any known executable in ES.
    Returns the matched exe name if found, None otherwise.

    Handles cases like "ransomware.exe" matching "ransom.exe" via substring.
    """
    exe_lower = exe_name.lower()
    exe_stem = exe_lower.replace('.exe', '')

    # Known aliases: descriptive name -> actual file name
    exe_aliases = {
        "ransomware.exe": "ransom.exe",
        "ransomware": "ransom",
        "malware.exe": "ransom.exe",
    }
    if exe_lower in exe_aliases:
        return exe_aliases[exe_lower]

    # Substring match: check if exe_stem is contained in or contains a known exe
    try:
        for index_name, field in [
            ("forensic-prefetch", "executable_name"),
            ("forensic-shimcache", "path"),
            ("forensic-amcache", "filename"),
        ]:
            r = requests.post(
                f"{ES_URL}/{index_name}/_search",
                json={
                    "size": 5,
                    "query": {
                        "bool": {
                            "must": [{"wildcard": {field: f"*{exe_stem}*"}}],
                            "filter": [{"bool": {"should": [{"term": {"case_id.keyword": case_id}}, {"term": {"_meta.case_id.keyword": case_id}}]}}],
                        }
                    },
                    "_source": [field],
                },
                timeout=5,
            )
            if r.status_code == 200:
                hits = r.json().get("hits", {}).get("hits", [])
                for hit in hits:
                    found_value = hit["_source"].get(field, "")
                    found_stem = found_value.lower().split("\\")[-1].replace(".exe", "")
                    if (exe_stem in found_stem or found_stem in exe_stem) and found_stem:
                        return found_value
    except Exception:
        pass

    return None


def detect_hallucinations(response: str, case_id: str) -> dict:
    """
    Attempt to detect hallucinated facts by extracting file paths, Event IDs,
    and executables from the response and verifying them in ES.
    """
    hallucinated = []
    verified = []
    unchecked = 0

    # Extract Event IDs mentioned (4-digit numbers after "Event ID" or "event")
    # Filter out negative context: skip if LLM says "no evidence of Event ID X"
    neg_patterns = re.compile(
        r'(no |not |zero |0 |didn.t |wasn.t |weren.t |absence |without |lack )',
        re.IGNORECASE
    )
    for m in re.finditer(r'[Ee]vent\s*(?:ID)?\s*(\d{4})', response):
        eid = m.group(1)
        # Check preceding context (80 chars) for negative language
        start = max(0, m.start() - 80)
        context_before = response[start:m.start()]
        if neg_patterns.search(context_before):
            continue  # LLM says this event was NOT found — not a hallucination
        try:
            r = requests.post(
                f"{ES_URL}/forensic-eventlog/_count",
                json={
                    "query": {
                        "bool": {
                            "must": [{"term": {"event_id": int(eid)}}],
                            "filter": [{"bool": {"should": [
                                {"term": {"case_id.keyword": case_id}},
                                {"term": {"_meta.case_id.keyword": case_id}}
                            ]}}],
                        }
                    }
                },
                timeout=5,
            )
            if r.status_code == 200:
                count = r.json().get("count", 0)
                if count > 0:
                    verified.append(f"Event ID {eid} (found {count})")
                else:
                    hallucinated.append(f"Event ID {eid} (not found in data)")
        except Exception:
            unchecked += 1

    # Extract .exe filenames mentioned
    # Expanded skip list: common Windows built-in executables always present on any system
    system_exes = {
        'cmd.exe', 'powershell.exe', 'explorer.exe', 'svchost.exe',
        'regedit.exe', 'control.exe', 'msconfig.exe', 'taskmgr.exe',
        'mmc.exe', 'notepad.exe', 'calc.exe', 'mspaint.exe', 'write.exe',
        'rundll32.exe', 'dllhost.exe', 'conhost.exe', 'csrss.exe',
        'lsass.exe', 'smss.exe', 'winlogon.exe', 'wininit.exe',
        'services.exe', 'dwm.exe', 'sihost.exe', 'ctfmon.exe',
        'wmiprvse.exe', 'wt.exe', 'msiexec.exe', 'consent.exe',
        'searchapp.exe', 'searchui.exe', 'settingsynchost.exe',
        'xboxapp.exe', 'gamebarftserver.exe', 'gamebar.exe',
        'audiodg.exe', 'fontdrvhost.exe', 'lsaiso.exe',
        'runtimebroker.exe', 'applicationframehost.exe',
        'shellexperiencehost.exe', 'systemsettings.exe',
        'taskhostw.exe', 'searchindexer.exe', 'spoolsv.exe',
        'wuauclt.exe', 'mpsigstub.exe', 'mpcmdrun.exe',
        'msmpeng.exe', 'nissrv.exe', 'securityhealthhost.exe',
        'service.exe', 'setup.exe',
    }
    exe_matches = list(re.finditer(r'(\w+\.exe)', response, re.IGNORECASE))
    seen_exes = set()
    for m in exe_matches:
        exe = m.group(1)
        exe_key = exe.lower()
        if exe_key in seen_exes or exe_key in system_exes:
            continue
        seen_exes.add(exe_key)

        # Check preceding context (80 chars) for negative language (same as Event IDs)
        ctx_start = max(0, m.start() - 80)
        context_before = response[ctx_start:m.start()]
        if neg_patterns.search(context_before):
            continue  # LLM says this exe was NOT found — not a hallucination

        try:
            found = False
            # Check prefetch
            r = requests.post(
                f"{ES_URL}/forensic-prefetch/_count",
                json={
                    "query": {
                        "bool": {
                            "must": [{"match": {"executable_name": exe.upper()}}],
                            "filter": [{"bool": {"should": [{"term": {"case_id.keyword": case_id}}, {"term": {"_meta.case_id.keyword": case_id}}]}}],
                        }
                    }
                },
                timeout=5,
            )
            if r.status_code == 200 and r.json().get("count", 0) > 0:
                verified.append(f"{exe} (found in prefetch)")
                continue

            # Check shimcache
            r = requests.post(
                f"{ES_URL}/forensic-shimcache/_count",
                json={
                    "query": {
                        "bool": {
                            "must": [{"match": {"path": exe}}],
                            "filter": [{"bool": {"should": [{"term": {"case_id.keyword": case_id}}, {"term": {"_meta.case_id.keyword": case_id}}]}}],
                        }
                    }
                },
                timeout=5,
            )
            if r.status_code == 200 and r.json().get("count", 0) > 0:
                verified.append(f"{exe} (found in shimcache)")
                continue

            # Check amcache
            r = requests.post(
                f"{ES_URL}/forensic-amcache/_count",
                json={
                    "query": {
                        "bool": {
                            "must": [{"match": {"filename": exe}}],
                            "filter": [{"bool": {"should": [{"term": {"case_id.keyword": case_id}}, {"term": {"_meta.case_id.keyword": case_id}}]}}],
                        }
                    }
                },
                timeout=5,
            )
            if r.status_code == 200 and r.json().get("count", 0) > 0:
                verified.append(f"{exe} (found in amcache)")
                continue

            # Check LNK target paths
            r = requests.post(
                f"{ES_URL}/forensic-lnk/_count",
                json={
                    "query": {
                        "bool": {
                            "must": [{"match_phrase": {"target_path": exe}}],
                            "filter": [{"bool": {"should": [{"term": {"case_id.keyword": case_id}}, {"term": {"_meta.case_id.keyword": case_id}}]}}],
                        }
                    }
                },
                timeout=5,
            )
            if r.status_code == 200 and r.json().get("count", 0) > 0:
                verified.append(f"{exe} (found in lnk)")
                continue

            # Check SRUM app names
            r = requests.post(
                f"{ES_URL}/forensic-srum/_count",
                json={
                    "query": {
                        "bool": {
                            "must": [{"match_phrase": {"app_name": exe}}],
                            "filter": [{"bool": {"should": [{"term": {"case_id.keyword": case_id}}, {"term": {"_meta.case_id.keyword": case_id}}]}}],
                        }
                    }
                },
                timeout=5,
            )
            if r.status_code == 200 and r.json().get("count", 0) > 0:
                verified.append(f"{exe} (found in srum)")
                continue

            # Check eventlog (process names, data fields)
            exe_name_no_ext = exe.rsplit('.', 1)[0]
            r = requests.post(
                f"{ES_URL}/forensic-eventlog/_count",
                json={
                    "query": {
                        "bool": {
                            "must": [{"query_string": {"query": f"*{exe_name_no_ext}*", "default_field": "*"}}],
                            "filter": [{"bool": {"should": [{"term": {"case_id.keyword": case_id}}, {"term": {"_meta.case_id.keyword": case_id}}]}}],
                        }
                    }
                },
                timeout=5,
            )
            if r.status_code == 200 and r.json().get("count", 0) > 0:
                verified.append(f"{exe} (found in eventlog)")
                continue

            # Not found anywhere — try fuzzy match before flagging
            fuzzy_match = _fuzzy_exe_match(exe, case_id)
            if fuzzy_match:
                verified.append(f"{exe} (fuzzy match: {fuzzy_match})")
            else:
                hallucinated.append(f"{exe} (not found in forensic data)")

        except Exception:
            unchecked += 1

    total_checked = len(verified) + len(hallucinated)
    hallucination_rate = len(hallucinated) / total_checked if total_checked > 0 else 0

    return {
        "verified_facts": verified,
        "hallucinated_facts": hallucinated,
        "unchecked": unchecked,
        "total_checked": total_checked,
        "hallucination_rate": hallucination_rate,
    }


# ============================================================
# CONSISTENCY ANALYSIS
# ============================================================

def compute_consistency(responses: List[str], keywords: list) -> dict:
    """
    Measure factual consistency across multiple runs.
    Checks which keywords appear in ALL runs vs only some.
    """
    n = len(responses)
    if n < 2:
        return {"runs": n, "message": "Need at least 2 runs for consistency"}

    keyword_counts = Counter()
    for resp in responses:
        resp_lower = resp.lower()
        for kw in keywords:
            if isinstance(kw, list):
                # GROUP: any match counts
                if any(k.lower() in resp_lower for k in kw):
                    keyword_counts[str(kw)] += 1
            else:
                if kw.lower() in resp_lower:
                    keyword_counts[kw] += 1

    kw_keys = [str(kw) for kw in keywords]
    always_present = [kw for kw in kw_keys if keyword_counts[kw] == n]
    sometimes_present = [kw for kw in kw_keys if 0 < keyword_counts[kw] < n]
    never_present = [kw for kw in kw_keys if keyword_counts[kw] == 0]

    consistency_score = len(always_present) / len(kw_keys) if kw_keys else 1.0

    return {
        "runs": n,
        "total_keywords": len(keywords),
        "always_present": always_present,
        "sometimes_present": sometimes_present,
        "never_present": never_present,
        "consistency_score": consistency_score,
    }


# ============================================================
# SEMANTIC CONSISTENCY (Embeddings Cosine Similarity)
# ============================================================

_sentence_model = None  # Lazy-loaded singleton


def _get_sentence_model():
    """Lazy-load sentence-transformers model (only when needed)."""
    global _sentence_model
    if _sentence_model is None:
        try:
            from sentence_transformers import SentenceTransformer
            _sentence_model = SentenceTransformer('all-MiniLM-L6-v2')
            print("  [Loaded sentence-transformers model for semantic consistency]")
        except ImportError:
            print("  [!] sentence-transformers not installed. Run: pip install sentence-transformers")
            return None
    return _sentence_model


def compute_semantic_consistency(responses: List[str]) -> dict:
    """
    Compute pairwise cosine similarity between all response pairs.
    Returns average similarity (0-1) and per-pair scores.

    Higher score = more consistent responses across runs.
    Typical ranges: 0.95+ identical, 0.80-0.95 similar, <0.80 divergent.
    """
    import numpy as np
    from itertools import combinations

    if len(responses) < 2:
        return {"semantic_consistency": None, "pairs": 0, "message": "Need 2+ runs"}

    model = _get_sentence_model()
    if model is None:
        return {"semantic_consistency": None, "pairs": 0, "message": "Model not available"}

    embeddings = model.encode(responses)
    similarities = []
    for i, j in combinations(range(len(responses)), 2):
        cos_sim = float(np.dot(embeddings[i], embeddings[j]) / (
            np.linalg.norm(embeddings[i]) * np.linalg.norm(embeddings[j])
        ))
        similarities.append(cos_sim)

    return {
        "semantic_consistency": round(float(np.mean(similarities)), 4),
        "min_similarity": round(float(np.min(similarities)), 4),
        "max_similarity": round(float(np.max(similarities)), 4),
        "std_similarity": round(float(np.std(similarities)), 4),
        "pairs": len(similarities),
    }


# ============================================================
# LLM-AS-JUDGE EVALUATION
# ============================================================

_judge_client = None  # Lazy-loaded Anthropic client


def _get_judge_client():
    """Lazy-load Anthropic client for judge evaluation."""
    global _judge_client
    if _judge_client is None:
        try:
            import anthropic
            from dotenv import load_dotenv
            load_dotenv()
            api_key = os.getenv("ANTHROPIC_API_KEY")
            if not api_key:
                print("  [!] ANTHROPIC_API_KEY not set — LLM-as-judge disabled")
                return None
            _judge_client = anthropic.Anthropic(api_key=api_key)
        except ImportError:
            print("  [!] anthropic package not installed — LLM-as-judge disabled")
            return None
    return _judge_client


JUDGE_SYSTEM_PROMPT = """You are an expert evaluator for digital forensic investigation responses.
You will be given a forensic investigation question, a reference answer (ground truth), and a model's response.
Your job is to evaluate the model's response on 4 dimensions.

IMPORTANT: Be strict but fair. Base your evaluation ONLY on the reference answer and factual correctness.
Do NOT give bonus points for length or verbosity. Focus on substance."""

JUDGE_USER_TEMPLATE = """QUESTION:
{question}

REFERENCE ANSWER (Ground Truth):
{expected_answer}

MODEL RESPONSE TO EVALUATE:
{model_response}

Evaluate the model's response on these 4 criteria (1-5 scale each):

1. **Accuracy** (1-5): Are the stated facts correct? Does the response contain factual errors?
   1=Major errors, 2=Several errors, 3=Minor errors, 4=Mostly correct, 5=Fully correct

2. **Completeness** (1-5): Does the response cover all key facts from the reference answer?
   1=Missing most facts, 2=Missing many, 3=Covers ~half, 4=Covers most, 5=Covers all key facts

3. **Reasoning** (1-5): For correlation/synthesis/hypothesis questions — is the reasoning sound?
   For simple retrieval questions, score based on whether facts are properly contextualized.
   1=No reasoning, 2=Flawed logic, 3=Partial reasoning, 4=Good reasoning, 5=Excellent reasoning

4. **Hallucination-Free** (1-5): Does the response avoid fabricating facts not in the evidence?
   1=Many fabrications, 2=Several, 3=A few minor, 4=Negligible, 5=No hallucinations

Respond in this exact JSON format (no other text):
{{"accuracy": N, "completeness": N, "reasoning": N, "hallucination_free": N, "explanation": "Brief 1-2 sentence justification"}}"""


def llm_judge_evaluate(question: str, expected_answer: str, model_response: str,
                       judge_model: str = "claude-sonnet-4-20250514") -> Optional[dict]:
    """
    Use Claude as judge to evaluate a model response against the reference answer.

    Args:
        question: The forensic question asked
        expected_answer: The reference/ground truth answer
        model_response: The model's actual response to evaluate
        judge_model: Claude model to use as judge

    Returns:
        Dict with accuracy, completeness, reasoning, hallucination_free (1-5 each),
        overall_judge_score (weighted average), and explanation.
        Returns None if judge is unavailable.
    """
    client = _get_judge_client()
    if client is None:
        return None

    if not expected_answer or not model_response:
        return None

    user_msg = JUDGE_USER_TEMPLATE.format(
        question=question,
        expected_answer=expected_answer,
        model_response=model_response[:3000],  # Truncate very long responses
    )

    try:
        response = client.messages.create(
            model=judge_model,
            max_tokens=300,
            system=JUDGE_SYSTEM_PROMPT,
            messages=[{"role": "user", "content": user_msg}],
        )
        raw = response.content[0].text.strip()

        # Parse JSON from response (handle potential markdown wrapping)
        if raw.startswith("```"):
            raw = raw.split("```")[1]
            if raw.startswith("json"):
                raw = raw[4:]

        scores = json.loads(raw)

        # Validate scores are in range 1-5
        for key in ["accuracy", "completeness", "reasoning", "hallucination_free"]:
            val = scores.get(key, 3)
            scores[key] = max(1, min(5, int(val)))

        # Weighted overall score (normalized to 0-1)
        scores["overall_judge_score"] = round(
            (0.30 * scores["accuracy"] +
             0.25 * scores["completeness"] +
             0.25 * scores["reasoning"] +
             0.20 * scores["hallucination_free"]) / 5.0, 4
        )

        return scores

    except json.JSONDecodeError:
        print(f" [judge: parse error]", end="")
        return {"accuracy": 0, "completeness": 0, "reasoning": 0,
                "hallucination_free": 0, "overall_judge_score": 0,
                "explanation": f"JSON parse error: {raw[:100]}"}
    except Exception as e:
        print(f" [judge: {e}]", end="")
        return None


# ============================================================
# FILE-BASED JUDGE (for Claude Desktop / MCP — no API key needed)
# ============================================================

def export_judge_prompts(source_file: str, output_file: str = None) -> str:
    """
    Generate a file with judge prompts from benchmark results.

    The user processes these prompts through Claude Desktop (subscription),
    then imports the scores back via import_judge_scores().

    Args:
        source_file: Path to benchmark results JSON
                     (from --evaluate-responses or run_benchmark output)
        output_file: Optional output path. Default: judge_prompts_<timestamp>.json

    Returns:
        Path to the generated prompts file.
    """
    with open(source_file, 'r', encoding='utf-8') as f:
        data = json.load(f)

    # Load questions for expected_answer
    case_name = data.get("case_name", "")
    if not case_name:
        # Try to extract from results
        results = data.get("detailed_results", data.get("results", []))
        if results:
            case_name = results[0].get("case_name", "KDFS_2023")

    # Try to detect provider for provider-specific questions
    _provider = None
    if results:
        _provider = results[0].get("provider")
    _, questions = load_case_questions(case_name, provider=_provider)
    q_map = {q["id"]: q for q in questions} if questions else {}

    # Get results list
    results = data.get("detailed_results", data.get("results", []))
    if not results:
        # Try nested structure from run_benchmark
        for case_data in data.get("cases", {}).values():
            for prov_data in case_data.get("providers", {}).values():
                results.extend(prov_data.get("results", []))

    if not results:
        print("[!] No results found in source file")
        return ""

    items = []
    skipped = 0
    for r in results:
        q_id = r.get("question_id", "")
        q_text = r.get("question", "")
        response = r.get("response", "")
        provider = r.get("provider", "unknown")

        # Get expected_answer from questions file
        q_data = q_map.get(q_id, {})
        expected_answer = q_data.get("expected_answer", "")

        if not expected_answer or not response:
            skipped += 1
            continue

        # Format the judge prompt
        prompt = JUDGE_USER_TEMPLATE.format(
            question=q_text,
            expected_answer=expected_answer,
            model_response=response[:3000],
        )

        items.append({
            "question_id": q_id,
            "provider": provider,
            "category": r.get("category", ""),
            "question": q_text,
            "prompt": prompt,
            "scores": None,  # User fills this in
        })

    # Output file
    if not output_file:
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        output_dir = Path("benchmark_results")
        output_dir.mkdir(exist_ok=True)
        output_file = str(output_dir / f"judge_prompts_{timestamp}.json")

    export_data = {
        "instructions": (
            "HOW TO USE:\n"
            "1. Open Claude Desktop (subscription)\n"
            "2. For each item in 'items', copy the 'prompt' field and paste into Claude Desktop\n"
            "3. Claude will respond with a JSON object like: "
            '{\"accuracy\": 4, \"completeness\": 3, \"reasoning\": 4, \"hallucination_free\": 5, \"explanation\": \"...\"}\n'
            "4. Copy that JSON and paste it into the 'scores' field of the same item\n"
            "5. Save this file and run: python benchmark.py --import-judge-scores <this_file>\n\n"
            "ALTERNATIVE (batch mode):\n"
            "  - Use the _batch.txt file to process all prompts in a single Claude Desktop session\n"
            "  - Copy the numbered JSON responses back into this file"
        ),
        "judge_system_prompt": JUDGE_SYSTEM_PROMPT,
        "source_file": source_file,
        "case_name": case_name,
        "total_items": len(items),
        "items": items,
    }

    with open(output_file, 'w', encoding='utf-8') as f:
        json.dump(export_data, f, indent=2, ensure_ascii=False)

    # Also generate a plain-text batch file for easy copy-paste
    batch_file = output_file.replace(".json", "_batch.txt")
    with open(batch_file, 'w', encoding='utf-8') as f:
        f.write("=" * 70 + "\n")
        f.write("LLM-AS-JUDGE BATCH PROMPTS\n")
        f.write("=" * 70 + "\n\n")
        f.write("SYSTEM PROMPT (paste this first as context):\n")
        f.write("-" * 40 + "\n")
        f.write(JUDGE_SYSTEM_PROMPT + "\n\n")
        f.write("=" * 70 + "\n\n")

        for i, item in enumerate(items, 1):
            f.write(f"--- [{i}/{len(items)}] {item['question_id']} ({item['provider']}) ---\n\n")
            f.write(item["prompt"] + "\n\n")
            f.write("=" * 70 + "\n\n")

    print(f"{'=' * 70}")
    print(f"JUDGE PROMPTS EXPORTED")
    print(f"{'=' * 70}")
    print(f"  Source:          {source_file}")
    print(f"  Items generated: {len(items)}")
    print(f"  Skipped:         {skipped} (no expected_answer or empty response)")
    print(f"  JSON file:       {output_file}")
    print(f"  Batch text:      {batch_file}")
    print(f"\nWorkflow:")
    print(f"  1. Open {batch_file} in a text editor")
    print(f"  2. Copy each prompt into Claude Desktop")
    print(f"  3. Paste Claude's JSON scores into {output_file} (in 'scores' field)")
    print(f"  4. Run: python benchmark.py --import-judge-scores {output_file}")

    return output_file


def import_judge_scores(scores_file: str, results_file: str = None) -> str:
    """
    Import judge scores from a file (filled in by user via Claude Desktop).

    Args:
        scores_file: Path to judge_prompts JSON with 'scores' filled in
        results_file: Optional — original results file to merge scores into.
                      If not specified, creates a standalone judge results file.

    Returns:
        Path to the output results file.
    """
    with open(scores_file, 'r', encoding='utf-8') as f:
        data = json.load(f)

    items = data.get("items", [])
    case_name = data.get("case_name", "")

    # Collect valid scores
    scored_items = []
    missing = 0
    invalid = 0

    for item in items:
        q_id = item["question_id"]
        scores = item.get("scores")

        if scores is None:
            missing += 1
            continue

        # Parse scores if it's a string (user pasted raw JSON text)
        if isinstance(scores, str):
            try:
                scores = json.loads(scores)
            except json.JSONDecodeError:
                print(f"  [{q_id}] Invalid JSON in scores — skipping")
                invalid += 1
                continue

        # Validate required fields
        required = ["accuracy", "completeness", "reasoning", "hallucination_free"]
        if not all(k in scores for k in required):
            print(f"  [{q_id}] Missing score fields — skipping")
            invalid += 1
            continue

        # Clamp values to 1-5
        for key in required:
            scores[key] = max(1, min(5, int(scores[key])))

        # Calculate overall score (normalized to 0-1)
        scores["overall_judge_score"] = round(
            (0.30 * scores["accuracy"] +
             0.25 * scores["completeness"] +
             0.25 * scores["reasoning"] +
             0.20 * scores["hallucination_free"]) / 5.0, 4
        )

        scored_items.append({
            "question_id": q_id,
            "provider": item.get("provider", ""),
            "category": item.get("category", ""),
            "question": item.get("question", ""),
            **{f"judge_{k}": v for k, v in scores.items()},
        })

    print(f"{'=' * 70}")
    print(f"JUDGE SCORES IMPORT")
    print(f"{'=' * 70}")
    print(f"  Total items:    {len(items)}")
    print(f"  Scored:         {len(scored_items)}")
    print(f"  Missing scores: {missing}")
    print(f"  Invalid:        {invalid}")

    if not scored_items:
        print("\n  [!] No valid scores found. Please fill in the 'scores' fields.")
        return ""

    # Calculate summary stats
    avg_acc = sum(s["judge_accuracy"] for s in scored_items) / len(scored_items)
    avg_comp = sum(s["judge_completeness"] for s in scored_items) / len(scored_items)
    avg_reas = sum(s["judge_reasoning"] for s in scored_items) / len(scored_items)
    avg_hall = sum(s["judge_hallucination_free"] for s in scored_items) / len(scored_items)
    avg_overall = sum(s["judge_overall_judge_score"] for s in scored_items) / len(scored_items)

    print(f"\n  Judge Scores (avg):")
    print(f"    Accuracy:          {avg_acc:.1f}/5")
    print(f"    Completeness:      {avg_comp:.1f}/5")
    print(f"    Reasoning:         {avg_reas:.1f}/5")
    print(f"    Hallucination-Free:{avg_hall:.1f}/5")
    print(f"    Overall:           {avg_overall:.1%}")

    # Per-category breakdown
    categories = {}
    for s in scored_items:
        cat = s.get("category", "unknown")
        if cat not in categories:
            categories[cat] = []
        categories[cat].append(s)

    if len(categories) > 1:
        print(f"\n  Per-category:")
        for cat, cat_items in sorted(categories.items()):
            cat_avg = sum(s["judge_overall_judge_score"] for s in cat_items) / len(cat_items)
            print(f"    {cat:15s}: {cat_avg:.1%} ({len(cat_items)} questions)")

    # Merge into original results if provided
    if results_file:
        with open(results_file, 'r', encoding='utf-8') as f:
            orig = json.load(f)

        results_list = orig.get("detailed_results", orig.get("results", []))
        score_map = {(s["question_id"], s["provider"]): s for s in scored_items}

        merged = 0
        for r in results_list:
            key = (r.get("question_id", ""), r.get("provider", ""))
            if key in score_map:
                s = score_map[key]
                r["judge_accuracy"] = s["judge_accuracy"]
                r["judge_completeness"] = s["judge_completeness"]
                r["judge_reasoning"] = s["judge_reasoning"]
                r["judge_hallucination_free"] = s["judge_hallucination_free"]
                r["judge_overall"] = s["judge_overall_judge_score"]
                r["judge_explanation"] = s.get("judge_explanation", "")
                merged += 1

        # Update summary
        if "summary" in orig:
            orig["summary"]["avg_judge_score"] = round(avg_overall, 4)

        # Save back
        with open(results_file, 'w', encoding='utf-8') as f:
            json.dump(orig, f, indent=2, ensure_ascii=False)

        print(f"\n  Merged {merged} scores into: {results_file}")
        return results_file

    # Save standalone judge results
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    output_dir = Path("benchmark_results")
    output_dir.mkdir(exist_ok=True)
    output_file = str(output_dir / f"judge_scores_{timestamp}.json")

    with open(output_file, 'w', encoding='utf-8') as f:
        json.dump({
            "timestamp": timestamp,
            "case_name": case_name,
            "num_scored": len(scored_items),
            "summary": {
                "avg_accuracy": round(avg_acc, 2),
                "avg_completeness": round(avg_comp, 2),
                "avg_reasoning": round(avg_reas, 2),
                "avg_hallucination_free": round(avg_hall, 2),
                "avg_overall": round(avg_overall, 4),
            },
            "per_category": {
                cat: {
                    "count": len(cat_items),
                    "avg_overall": round(
                        sum(s["judge_overall_judge_score"] for s in cat_items) / len(cat_items), 4
                    ),
                }
                for cat, cat_items in categories.items()
            },
            "scores": scored_items,
        }, f, indent=2, ensure_ascii=False)

    print(f"\n  Saved judge scores: {output_file}")
    return output_file


# ============================================================
# ANALYZER FACTORY
# ============================================================

def create_analyzer(provider: str, case_id: str, mode: str = "retrieval"):
    """Create an analyzer instance for the given provider and question mode.

    Args:
        provider: LLM provider name (claude, opus, deepseek, openai)
        case_id: Elasticsearch case ID
        mode: 'retrieval' for short factual questions (max_tokens=2048, max_tool_calls=25)
              'analysis' for deep investigation (max_tokens=8192, max_tool_calls=80)
    """
    config = PROVIDERS[provider]
    mode_config = QUESTION_MODES.get(mode, QUESTION_MODES["retrieval"])

    module = __import__(config["module"], fromlist=[config["class"]])
    cls = getattr(module, config["class"])
    kwargs = {**config["init_kwargs"], "case_id": case_id}

    # Pass mode-specific limits if the analyzer supports them
    import inspect
    init_params = inspect.signature(cls.__init__).parameters
    if "max_tokens" in init_params:
        kwargs["max_tokens"] = mode_config["max_tokens"]
    if "max_tool_calls" in init_params:
        kwargs["max_tool_calls"] = mode_config["max_tool_calls"]

    return cls(**kwargs)


# ============================================================
# BENCHMARK RUNNER
# ============================================================

def run_single_question(
    analyzer, question: dict, case_id: str, provider: str,
    ground_truth: dict = None,
    scenario: str = "",
    use_judge: bool = False,
) -> dict:
    """Run a single question through an analyzer and collect metrics."""
    q_id = question["id"]
    q_text = question["question"]

    # Get keywords from ground truth (dynamic) or question (static fallback)
    gt = ground_truth or {}
    q_gt = gt.get(q_id, {})
    keywords = q_gt.get("keywords", question.get("keywords", []))
    verification_queries = q_gt.get("verification_queries", question.get("verification_queries", []))

    print(f"      [{q_id}] {q_text[:60]}...", end="", flush=True)

    if not keywords:
        print(f" SKIP (no ground truth data)")
        return None

    # Build full query with scenario context (only for first question or if scenario exists)
    if scenario:
        full_query = f"CASE SCENARIO:\n{scenario}\n\nQUESTION:\n{q_text}"
    else:
        full_query = q_text

    # Clear conversation history to prevent cross-contamination between questions
    analyzer.clear_history()

    # Measure response time
    t_start = time.time()
    try:
        response = analyzer.analyze(full_query, case_id)
    except Exception as e:
        response = f"ERROR: {e}"
    t_end = time.time()
    latency = t_end - t_start

    # Check if response is an error
    is_error = response.startswith("ERROR:") or response.startswith("Error:")

    # Keyword check (recall)
    keyword_result = check_keywords_in_response(response, keywords)

    # ES verification of ground truth queries
    verification_results = []
    for vq in verification_queries:
        vr = verify_fact_in_es(vq, case_id)
        verification_results.append(vr)

    # Hallucination detection (skip for error responses)
    if is_error:
        hallucination_result = {"verified_facts": [], "hallucinated_facts": [],
                                "unchecked": 0, "total_checked": 0, "hallucination_rate": 0}
    else:
        hallucination_result = detect_hallucinations(response, case_id)

    # Precision: verified_facts / (verified + hallucinated)
    total_facts = hallucination_result["total_checked"]
    precision = (
        len(hallucination_result["verified_facts"]) / total_facts
        if total_facts > 0
        else 1.0
    )

    recall = keyword_result["recall"]
    f1 = (2 * precision * recall / (precision + recall)) if (precision + recall) > 0 else 0

    # LLM-as-judge evaluation (optional)
    judge_scores = None
    if use_judge and not is_error:
        expected_answer = question.get("expected_answer", "")
        if expected_answer:
            judge_scores = llm_judge_evaluate(q_text, expected_answer, response)

    status = "ERR" if is_error else ("OK" if recall >= 0.5 else "LOW")
    judge_str = ""
    if judge_scores and judge_scores.get("overall_judge_score"):
        judge_str = f" | judge={judge_scores['overall_judge_score']:.0%}"
    print(f" {latency:.1f}s | recall={recall:.0%} | precision={precision:.0%}{judge_str} | [{status}]")

    result = {
        "question_id": q_id,
        "question": q_text,
        "category": question["category"],
        "provider": provider,
        "case_id": case_id,
        "response": response,
        "is_error": is_error,
        "latency_seconds": round(latency, 2),
        "keyword_recall": round(recall, 4),
        "precision": round(precision, 4),
        "f1": round(f1, 4),
        "hallucination_rate": round(hallucination_result["hallucination_rate"], 4),
        "keywords_expected": keywords,
        "keywords_found": keyword_result["found"],
        "keywords_missing": keyword_result["missing"],
        "verified_facts": hallucination_result["verified_facts"],
        "hallucinated_facts": hallucination_result["hallucinated_facts"],
        "verification_results": verification_results,
        "response_length": len(response),
    }

    # Add judge scores if available
    if judge_scores:
        result["judge_accuracy"] = judge_scores.get("accuracy", 0)
        result["judge_completeness"] = judge_scores.get("completeness", 0)
        result["judge_reasoning"] = judge_scores.get("reasoning", 0)
        result["judge_hallucination_free"] = judge_scores.get("hallucination_free", 0)
        result["judge_overall"] = judge_scores.get("overall_judge_score", 0)
        result["judge_explanation"] = judge_scores.get("explanation", "")

    return result


def run_benchmark(
    providers: List[str],
    question_ids: Optional[List[str]] = None,
    num_runs: int = 1,
    cases: Optional[List[dict]] = None,
    use_judge: bool = False,
    question_mode: str = "retrieval",
) -> dict:
    """Run the full benchmark suite across all cases."""
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    output_dir = Path("benchmark_results")
    output_dir.mkdir(exist_ok=True)

    # Use specified cases or default
    benchmark_cases = cases or [{"case_id": BENCHMARK_CASE_ID, "case_name": BENCHMARK_CASE_NAME}]

    # Pre-load questions for all cases to count total (use default file for counting)
    case_questions_default = {}
    case_scenarios = {}
    total_questions = 0
    for case_def in benchmark_cases:
        case_name = case_def["case_name"]
        scenario, questions = load_case_questions(case_name)
        if not questions:
            # Fallback to legacy questions with dynamic ground truth
            scenario = ""
            questions = LEGACY_QUESTIONS
            print(f"  [!] Using legacy questions for {case_name}")
        if question_ids:
            questions = [q for q in questions if q["id"] in question_ids]
        case_questions_default[case_name] = questions
        case_scenarios[case_name] = scenario
        total_questions += len(questions)

    total_calls = len(providers) * total_questions * num_runs

    print("=" * 70)
    print("ArshaLab Benchmark Runner")
    print("=" * 70)
    print(f"  Cases: {', '.join(c['case_name'] for c in benchmark_cases)}")
    print(f"  Providers: {', '.join(providers)}")
    print(f"  Questions per case: {[f'{k}: {len(v)}' for k, v in case_questions_default.items()]}")
    print(f"  Total questions: {total_questions}")
    print(f"  Runs per question: {num_runs}")
    print(f"  Total API calls: {total_calls}")
    print("=" * 70)

    all_results = []

    for case_def in benchmark_cases:
        case_id = case_def["case_id"]
        case_name = case_def["case_name"]

        # Verify case exists (try both case_id and _meta.case_id field locations)
        try:
            r = requests.post(
                f"{ES_URL}/forensic-*/_count",
                json={"query": {"bool": {"should": [
                    {"term": {"case_id.keyword": case_id}},
                    {"term": {"_meta.case_id.keyword": case_id}}
                ]}}},
                timeout=5,
            )
            record_count = r.json().get("count", 0)
            if record_count == 0:
                print(f"\n  [!] No records for case {case_name}. Skipping.")
                continue
        except Exception as e:
            print(f"\n  [!] Cannot connect to ES: {e}")
            continue

        print(f"\n  *** Case: {case_name} ({record_count:,} records) ***")

        for provider in providers:
            # Load provider-specific questions (e.g. KDFS_2023_openai.json) or fallback to default
            scenario_p, questions_p = load_case_questions(case_name, provider=provider)
            if questions_p:
                questions = questions_p
                if question_ids:
                    questions = [q for q in questions if q["id"] in question_ids]
            else:
                questions = case_questions_default.get(case_name, [])
                scenario_p = case_scenarios.get(case_name, "")

            if not questions:
                print(f"    [!] No questions for this case. Skipping.")
                continue

            # Check if we need legacy ground truth (for old-style questions)
            use_legacy_gt = any("ground_truth_builder" in q for q in questions)
            ground_truth = {}

            if use_legacy_gt:
                print(f"    Building ground truth from ES...", end="", flush=True)
                ground_truth = build_ground_truth(case_id)
                gt_keywords = sum(len(v.get("keywords", [])) for v in ground_truth.values())
                print(f" {gt_keywords} keywords across {len(ground_truth)} questions")
            else:
                # Use keywords from JSON questions directly
                gt_keywords = sum(len(q.get("keywords", [])) for q in questions)
                print(f"    Using {gt_keywords} keywords from {len(questions)} JSON questions")
            print(f"\n    === {PROVIDERS[provider]['display_name']} ===")

            for run_num in range(1, num_runs + 1):
                if num_runs > 1:
                    print(f"      --- Run {run_num}/{num_runs} ---")

                # Create fresh analyzer for each run (clean conversation history)
                try:
                    analyzer = create_analyzer(provider, case_id, mode=question_mode)
                except Exception as e:
                    print(f"      [!] Failed to create analyzer: {e}")
                    continue

                # Get scenario for this case (provider-specific or default)
                scenario = scenario_p or case_scenarios.get(case_name, "")

                for idx, question in enumerate(questions):
                    # Pass scenario only for first question to set context
                    q_scenario = scenario if idx == 0 else ""
                    result = run_single_question(
                        analyzer, question, case_id, provider,
                        ground_truth=ground_truth,
                        scenario=q_scenario,
                        use_judge=use_judge,
                    )
                    if result is not None:
                        result["run_number"] = run_num
                        result["case_name"] = case_name
                        all_results.append(result)

        print()

    # ============================================================
    # AGGREGATE METRICS
    # ============================================================
    print("=" * 70)
    print("RESULTS SUMMARY")
    print("=" * 70)

    # Filter out error responses for clean metrics
    valid_results = [r for r in all_results if not r.get("is_error", False)]
    error_results = [r for r in all_results if r.get("is_error", False)]

    if error_results:
        print(f"\n  [!] {len(error_results)} responses were errors (excluded from metrics)")

    summary = {}

    for provider in providers:
        provider_results = [r for r in valid_results if r["provider"] == provider]
        if not provider_results:
            print(f"\n  {PROVIDERS[provider]['display_name']}: No valid results")
            continue

        latencies = [r["latency_seconds"] for r in provider_results]
        recalls = [r["keyword_recall"] for r in provider_results]
        precisions = [r["precision"] for r in provider_results]
        f1s = [r["f1"] for r in provider_results]
        hall_rates = [r["hallucination_rate"] for r in provider_results]

        avg_latency = sum(latencies) / len(latencies)
        median_latency = sorted(latencies)[len(latencies) // 2]
        avg_recall = sum(recalls) / len(recalls)
        avg_precision = sum(precisions) / len(precisions)
        avg_f1 = sum(f1s) / len(f1s)
        avg_hall = sum(hall_rates) / len(hall_rates)

        # Per-category breakdown (5 categories: retrieval, correlation, synthesis, reporting, hypothesis)
        categories = {}
        for cat in ["retrieval", "correlation", "synthesis", "reporting", "hypothesis", "analysis", "reasoning"]:
            cat_results = [r for r in provider_results if r["category"] == cat]
            if cat_results:
                categories[cat] = {
                    "count": len(cat_results),
                    "avg_recall": round(sum(r["keyword_recall"] for r in cat_results) / len(cat_results), 4),
                    "avg_precision": round(sum(r["precision"] for r in cat_results) / len(cat_results), 4),
                    "avg_latency": round(sum(r["latency_seconds"] for r in cat_results) / len(cat_results), 2),
                }

        # Per-case breakdown
        per_case = {}
        for case_def in benchmark_cases:
            cn = case_def["case_name"]
            case_results = [r for r in provider_results if r.get("case_name") == cn]
            if case_results:
                per_case[cn] = {
                    "count": len(case_results),
                    "avg_recall": round(sum(r["keyword_recall"] for r in case_results) / len(case_results), 4),
                    "avg_precision": round(sum(r["precision"] for r in case_results) / len(case_results), 4),
                    "avg_latency": round(sum(r["latency_seconds"] for r in case_results) / len(case_results), 2),
                }

        # Consistency (if multiple runs)
        consistency_scores = {}
        semantic_scores = {}
        if num_runs > 1:
            for case_name, questions in case_questions_default.items():
                for question in questions:
                    q_keywords = question.get("keywords", [])
                    q_responses = [
                        r["response"]
                        for r in provider_results
                        if r["question_id"] == question["id"] and r.get("case_name") == case_name
                    ]
                    if len(q_responses) >= 2:
                        # Factual consistency (keyword overlap)
                        cons = compute_consistency(q_responses, q_keywords)
                        consistency_scores[f"{case_name}_{question['id']}"] = cons["consistency_score"]
                        # Semantic consistency (embeddings cosine similarity)
                        sem = compute_semantic_consistency(q_responses)
                        if sem["semantic_consistency"] is not None:
                            semantic_scores[f"{case_name}_{question['id']}"] = sem["semantic_consistency"]

        avg_consistency = (
            sum(consistency_scores.values()) / len(consistency_scores)
            if consistency_scores
            else None
        )
        avg_semantic = (
            sum(semantic_scores.values()) / len(semantic_scores)
            if semantic_scores
            else None
        )

        # LLM-as-judge metrics (if enabled)
        judge_results = [r for r in provider_results if "judge_overall" in r]
        avg_judge = None
        avg_judge_by_dim = {}
        if judge_results:
            avg_judge = round(sum(r["judge_overall"] for r in judge_results) / len(judge_results), 4)
            for dim in ["judge_accuracy", "judge_completeness", "judge_reasoning", "judge_hallucination_free"]:
                vals = [r[dim] for r in judge_results if dim in r]
                if vals:
                    avg_judge_by_dim[dim] = round(sum(vals) / len(vals), 2)

        # Per-category with judge scores
        for cat in categories:
            cat_results = [r for r in provider_results if r["category"] == cat]
            cat_judge = [r for r in cat_results if "judge_overall" in r]
            if cat_judge:
                categories[cat]["avg_judge"] = round(
                    sum(r["judge_overall"] for r in cat_judge) / len(cat_judge), 4)

        summary[provider] = {
            "display_name": PROVIDERS[provider]["display_name"],
            "total_questions": len(provider_results),
            "errors": len([r for r in all_results if r["provider"] == provider and r.get("is_error")]),
            "avg_latency": round(avg_latency, 2),
            "median_latency": round(median_latency, 2),
            "p95_latency": round(sorted(latencies)[int(len(latencies) * 0.95)], 2) if len(latencies) >= 5 else round(max(latencies), 2),
            "avg_recall": round(avg_recall, 4),
            "avg_precision": round(avg_precision, 4),
            "avg_f1": round(avg_f1, 4),
            "avg_hallucination_rate": round(avg_hall, 4),
            "avg_consistency": round(avg_consistency, 4) if avg_consistency is not None else "N/A",
            "avg_semantic_consistency": round(avg_semantic, 4) if avg_semantic is not None else "N/A",
            "avg_judge_score": avg_judge if avg_judge is not None else "N/A",
            "judge_dimensions": avg_judge_by_dim if avg_judge_by_dim else "N/A",
            "categories": categories,
            "per_case": per_case,
        }

        # Print summary line
        cons_str = f"{avg_consistency:.0%}" if avg_consistency is not None else "N/A"
        sem_str = f"{avg_semantic:.2f}" if avg_semantic is not None else "N/A"
        judge_str = f"{avg_judge:.0%}" if avg_judge is not None else "N/A"
        print(
            f"\n  {PROVIDERS[provider]['display_name']:25s} | "
            f"Latency: {avg_latency:.1f}s (med {median_latency:.1f}s) | "
            f"Recall: {avg_recall:.0%} | Precision: {avg_precision:.0%} | "
            f"F1: {avg_f1:.0%} | "
            f"Halluc: {avg_hall:.0%} | Consist: {cons_str} | Semantic: {sem_str} | Judge: {judge_str}"
        )

        # Judge dimension breakdown
        if avg_judge_by_dim:
            print(f"    Judge breakdown: " + " | ".join(
                f"{k.replace('judge_', '')}={v:.1f}/5" for k, v in avg_judge_by_dim.items()
            ))

        # Per-category
        for cat, cat_data in categories.items():
            judge_cat_str = f" judge={cat_data['avg_judge']:.0%}" if "avg_judge" in cat_data else ""
            print(
                f"    {cat:12s}: recall={cat_data['avg_recall']:.0%} "
                f"precision={cat_data['avg_precision']:.0%} "
                f"latency={cat_data['avg_latency']:.1f}s{judge_cat_str} "
                f"(n={cat_data['count']})"
            )

        # Per-case
        if len(per_case) > 1:
            for cn, cd in per_case.items():
                print(
                    f"    {cn:20s}: recall={cd['avg_recall']:.0%} "
                    f"precision={cd['avg_precision']:.0%} "
                    f"latency={cd['avg_latency']:.1f}s (n={cd['count']})"
                )

    print("\n" + "=" * 70)

    # ============================================================
    # COMPARISON TABLE (for paper)
    # ============================================================
    if len(providers) > 1:
        print("\n  TABLE FOR PAPER:")
        print("  " + "-" * 90)
        print(
            f"  {'Metric':<25s} | "
            + " | ".join(f"{PROVIDERS[p]['display_name']:>18s}" for p in providers)
        )
        print("  " + "-" * 90)

        metrics = [
            ("Avg Latency (s)", "avg_latency"),
            ("Median Latency (s)", "median_latency"),
            ("P95 Latency (s)", "p95_latency"),
            ("Recall", "avg_recall"),
            ("Precision", "avg_precision"),
            ("F1 Score", "avg_f1"),
            ("Hallucination Rate", "avg_hallucination_rate"),
            ("Factual Consistency", "avg_consistency"),
            ("Semantic Consistency", "avg_semantic_consistency"),
            ("LLM Judge Score", "avg_judge_score"),
        ]

        for label, key in metrics:
            values = []
            for p in providers:
                val = summary.get(p, {}).get(key, "N/A")
                if isinstance(val, float):
                    if "latency" in key.lower():
                        values.append(f"{val:.2f}")
                    else:
                        values.append(f"{val:.2%}")
                else:
                    values.append(str(val))
            print(f"  {label:<25s} | " + " | ".join(f"{v:>18s}" for v in values))

        print("  " + "-" * 90)

    # ============================================================
    # SAVE RESULTS
    # ============================================================

    # Full JSON results
    results_file = output_dir / f"benchmark_{timestamp}.json"
    with open(results_file, "w", encoding="utf-8") as f:
        json.dump(
            {
                "timestamp": timestamp,
                "cases": [c["case_name"] for c in benchmark_cases],
                "providers": providers,
                "num_questions": len(questions),
                "num_runs": num_runs,
                "summary": summary,
                "detailed_results": all_results,
            },
            f,
            indent=2,
            ensure_ascii=False,
        )
    print(f"\n  Results saved to: {results_file}")

    # CSV summary per question
    csv_file = output_dir / f"benchmark_{timestamp}.csv"
    with open(csv_file, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow([
            "case", "question_id", "category", "provider", "run",
            "latency_s", "recall", "precision", "f1",
            "hallucination_rate", "is_error", "keywords_found", "keywords_missing",
            "response_length",
            "judge_accuracy", "judge_completeness", "judge_reasoning",
            "judge_halluc_free", "judge_overall", "judge_explanation",
        ])
        for r in all_results:
            writer.writerow([
                r.get("case_name", ""), r["question_id"], r["category"],
                r["provider"], r["run_number"],
                r["latency_seconds"], r["keyword_recall"], r["precision"], r["f1"],
                r["hallucination_rate"], r.get("is_error", False),
                "; ".join(r["keywords_found"]),
                "; ".join(r["keywords_missing"]),
                r["response_length"],
                r.get("judge_accuracy", ""), r.get("judge_completeness", ""),
                r.get("judge_reasoning", ""), r.get("judge_hallucination_free", ""),
                r.get("judge_overall", ""), r.get("judge_explanation", ""),
            ])
    print(f"  CSV saved to:     {csv_file}")

    # Responses text file (for manual review)
    responses_file = output_dir / f"responses_{timestamp}.txt"
    with open(responses_file, "w", encoding="utf-8") as f:
        for r in all_results:
            f.write("=" * 70 + "\n")
            f.write(f"[{r['provider']}] Run {r['run_number']} | {r['question_id']}: {r['question']}\n")
            f.write(f"Latency: {r['latency_seconds']}s | Recall: {r['keyword_recall']:.0%} | Precision: {r['precision']:.0%}\n")
            f.write("-" * 70 + "\n")
            f.write(r["response"] + "\n\n")
    print(f"  Responses saved:  {responses_file}")

    # ============================================================
    # COMPARISON TABLE (HTML for paper)
    # ============================================================
    # Format: Category | Question | Expected Answer | Provider1 | Provider2 | ...

    comparison_file = output_dir / f"comparison_{timestamp}.html"
    with open(comparison_file, "w", encoding="utf-8") as f:
        f.write("""<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>Benchmark Comparison</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; }
        h1 { color: #333; }
        table { border-collapse: collapse; width: 100%; margin-bottom: 30px; }
        th, td { border: 1px solid #ddd; padding: 8px; text-align: left; vertical-align: top; }
        th { background-color: #4CAF50; color: white; }
        tr:nth-child(even) { background-color: #f2f2f2; }
        .category { font-weight: bold; }
        .expected { background-color: #e8f5e9; max-width: 200px; }
        .response { max-width: 300px; font-size: 12px; }
        .score { font-size: 11px; color: #666; }
        .high { color: green; }
        .medium { color: orange; }
        .low { color: red; }
        .metrics { margin: 20px 0; padding: 15px; background: #f5f5f5; border-radius: 5px; }
    </style>
</head>
<body>
""")
        f.write(f"<h1>Benchmark Comparison - {timestamp}</h1>\n")

        # Summary metrics table
        f.write("<div class='metrics'>\n")
        f.write("<h2>Summary Metrics</h2>\n")
        f.write("<table>\n<tr><th>Metric</th>")
        for p in providers:
            f.write(f"<th>{PROVIDERS[p]['display_name']}</th>")
        f.write("</tr>\n")

        for label, key in [("Recall", "avg_recall"), ("Precision", "avg_precision"),
                           ("F1 Score", "avg_f1"), ("Hallucination Rate", "avg_hallucination_rate"),
                           ("Avg Latency (s)", "avg_latency")]:
            f.write(f"<tr><td>{label}</td>")
            for p in providers:
                val = summary.get(p, {}).get(key, "N/A")
                if isinstance(val, float):
                    if "latency" in key:
                        f.write(f"<td>{val:.2f}s</td>")
                    else:
                        css_class = "high" if val >= 0.7 else ("medium" if val >= 0.4 else "low")
                        if "hallucination" in key:
                            css_class = "low" if val >= 0.3 else ("medium" if val >= 0.1 else "high")
                        f.write(f"<td class='{css_class}'>{val:.1%}</td>")
                else:
                    f.write(f"<td>{val}</td>")
            f.write("</tr>\n")
        f.write("</table>\n</div>\n")

        # Detailed comparison table per question
        f.write("<h2>Detailed Responses</h2>\n")
        f.write("<table>\n")
        f.write("<tr><th>Category</th><th>Question</th><th class='expected'>Expected Facts</th>")
        for p in providers:
            f.write(f"<th class='response'>{PROVIDERS[p]['display_name']}</th>")
        f.write("</tr>\n")

        # Group results by question
        questions_seen = {}
        for case_name, questions in case_questions_default.items():
            for q in questions:
                qid = q["id"]
                if qid in questions_seen:
                    continue
                questions_seen[qid] = True

                # Get responses for this question from each provider
                responses_by_provider = {}
                for r in all_results:
                    if r["question_id"] == qid and r.get("case_name") == case_name:
                        if r["provider"] not in responses_by_provider:
                            responses_by_provider[r["provider"]] = r

                # Format expected facts
                expected = q.get("expected_facts", {})
                def _format_expected_value(v):
                    if isinstance(v, list):
                        parts = []
                        for item in v:
                            if isinstance(item, list):
                                parts.append(f"[{', '.join(str(x) for x in item)}]")
                            else:
                                parts.append(str(item))
                        return ', '.join(parts)
                    return str(v)

                expected_str = "<br>".join([
                    f"<b>{k}:</b> {_format_expected_value(v)}"
                    for k, v in expected.items()
                    if k not in ("evaluation", "must_acknowledge")
                ][:5])  # Limit to 5 items

                f.write(f"<tr>")
                f.write(f"<td class='category'>{q['category']}</td>")
                f.write(f"<td>{q['question']}</td>")
                f.write(f"<td class='expected'>{expected_str}</td>")

                for p in providers:
                    if p in responses_by_provider:
                        r = responses_by_provider[p]
                        # Truncate response for display
                        resp_short = r["response"][:500] + "..." if len(r["response"]) > 500 else r["response"]
                        resp_short = resp_short.replace("<", "&lt;").replace(">", "&gt;").replace("\n", "<br>")
                        recall_class = "high" if r["keyword_recall"] >= 0.7 else ("medium" if r["keyword_recall"] >= 0.4 else "low")
                        f.write(f"<td class='response'>{resp_short}<br><span class='score {recall_class}'>Recall: {r['keyword_recall']:.0%} | Precision: {r['precision']:.0%}</span></td>")
                    else:
                        f.write("<td>-</td>")
                f.write("</tr>\n")

        f.write("</table>\n")
        f.write("</body></html>")

    print(f"  Comparison HTML: {comparison_file}")

    # Comparison CSV (for Excel/Word table)
    comparison_csv = output_dir / f"comparison_{timestamp}.csv"
    with open(comparison_csv, "w", newline="", encoding="utf-8-sig") as f:  # utf-8-sig for Excel
        writer = csv.writer(f)
        # Header
        header = ["Category", "Question", "Expected Answer"]
        for p in providers:
            header.extend([f"{PROVIDERS[p]['display_name']} Response", f"{PROVIDERS[p]['display_name']} Recall"])
        writer.writerow(header)

        # Data rows
        for case_name, questions in case_questions_default.items():
            for q in questions:
                qid = q["id"]
                # Get responses for this question
                responses_by_provider = {}
                for r in all_results:
                    if r["question_id"] == qid and r.get("case_name") == case_name:
                        if r["provider"] not in responses_by_provider:
                            responses_by_provider[r["provider"]] = r

                # Format expected facts as string
                expected = q.get("expected_facts", {})
                expected_items = []
                for k, v in expected.items():
                    if k not in ("evaluation", "must_acknowledge"):
                        if isinstance(v, list):
                            expected_items.append(f"{k}: {', '.join(str(x) for x in v)}")
                        elif isinstance(v, dict):
                            expected_items.append(f"{k}: {json.dumps(v, ensure_ascii=False)}")
                        else:
                            expected_items.append(f"{k}: {v}")
                expected_str = "; ".join(expected_items[:5])

                row = [q["category"], q["question"], expected_str]
                for p in providers:
                    if p in responses_by_provider:
                        r = responses_by_provider[p]
                        # Truncate response
                        resp = r["response"][:1000] if len(r["response"]) > 1000 else r["response"]
                        resp = resp.replace("\n", " ").replace("\r", "")
                        row.extend([resp, f"{r['keyword_recall']:.0%}"])
                    else:
                        row.extend(["", ""])
                writer.writerow(row)

    print(f"  Comparison CSV:  {comparison_csv}")

    print(f"\n  Done!")
    return summary


# ============================================================
# MANUAL MCP EVALUATION MODE
# ============================================================

def evaluate_responses_file(responses_file: str) -> dict:
    """
    Evaluate pre-collected LLM responses (e.g. from MCP Claude Desktop).

    Input JSON format:
    {
        "case_name": "KDFS_2023",
        "case_id": "case_20260128_141256",
        "provider": "claude_mcp",
        "responses": {
            "KDFS01": "The primary user account is souldrag...",
            "KDFS02": "Two email accounts were found..."
        }
    }
    """
    with open(responses_file, 'r', encoding='utf-8') as f:
        data = json.load(f)

    case_name = data["case_name"]
    case_id = data.get("case_id", "")
    provider = data.get("provider", "manual_mcp")
    responses = data["responses"]

    # Load questions (provider-specific if available)
    scenario, questions = load_case_questions(case_name, provider=provider)
    if not questions:
        print(f"[!] No questions found for case {case_name}")
        return {}

    # Build question lookup
    q_map = {q["id"]: q for q in questions}

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    output_dir = Path("benchmark_results")
    output_dir.mkdir(exist_ok=True)

    print("=" * 70)
    print("ArshaLab Manual Response Evaluator")
    print("=" * 70)
    print(f"  Case: {case_name} ({case_id})")
    print(f"  Provider: {provider}")
    print(f"  Responses: {len(responses)}")
    print("=" * 70)

    all_results = []
    for q_id, response_text in responses.items():
        question = q_map.get(q_id)
        if not question:
            print(f"  [{q_id}] SKIP - question not found in {case_name}.json")
            continue

        keywords = question.get("keywords", [])
        if not keywords:
            # Extract from expected_facts
            kws = []
            extract_keywords_recursive(question.get("expected_facts", {}), kws)
            seen = set()
            for kw in kws:
                kw_l = kw.lower() if isinstance(kw, str) else str(kw)
                if kw_l not in seen:
                    seen.add(kw_l)
                    keywords.append(kw)

        print(f"  [{q_id}] {question['question'][:60]}...", end="", flush=True)

        if not keywords:
            print(" SKIP (no keywords)")
            continue

        # Keyword recall
        keyword_result = check_keywords_in_response(response_text, keywords)

        # Hallucination detection
        hallucination_result = detect_hallucinations(response_text, case_id)

        total_facts = hallucination_result["total_checked"]
        precision = (
            len(hallucination_result["verified_facts"]) / total_facts
            if total_facts > 0
            else 1.0
        )

        recall = keyword_result["recall"]
        f1 = (2 * precision * recall / (precision + recall)) if (precision + recall) > 0 else 0

        # LLM-as-judge (only if API key is available; otherwise use --export-judge-prompts workflow)
        expected_answer = question.get("expected_answer", "")
        judge_scores = None
        if expected_answer and _get_judge_client() is not None:
            judge_scores = llm_judge_evaluate(question["question"], expected_answer, response_text)

        status = "OK" if recall >= 0.5 else "LOW"
        judge_str = ""
        if judge_scores and judge_scores.get("overall_judge_score"):
            judge_str = f" | judge={judge_scores['overall_judge_score']:.0%}"
        print(f" recall={recall:.0%} | precision={precision:.0%}{judge_str} | [{status}]")

        result_entry = {
            "question_id": q_id,
            "question": question["question"],
            "category": question.get("category", "unknown"),
            "provider": provider,
            "case_id": case_id,
            "case_name": case_name,
            "response": response_text,
            "is_error": False,
            "latency_seconds": 0,
            "keyword_recall": round(recall, 4),
            "precision": round(precision, 4),
            "f1": round(f1, 4),
            "hallucination_rate": round(hallucination_result["hallucination_rate"], 4),
            "keywords_expected": keywords,
            "keywords_found": keyword_result["found"],
            "keywords_missing": keyword_result["missing"],
            "verified_facts": hallucination_result["verified_facts"],
            "hallucinated_facts": hallucination_result["hallucinated_facts"],
            "run_number": 1,
            "response_length": len(response_text),
        }

        if judge_scores:
            result_entry["judge_accuracy"] = judge_scores.get("accuracy", 0)
            result_entry["judge_completeness"] = judge_scores.get("completeness", 0)
            result_entry["judge_reasoning"] = judge_scores.get("reasoning", 0)
            result_entry["judge_hallucination_free"] = judge_scores.get("hallucination_free", 0)
            result_entry["judge_overall"] = judge_scores.get("overall_judge_score", 0)
            result_entry["judge_explanation"] = judge_scores.get("explanation", "")

        all_results.append(result_entry)

    # Summary
    if all_results:
        avg_recall = sum(r["keyword_recall"] for r in all_results) / len(all_results)
        avg_precision = sum(r["precision"] for r in all_results) / len(all_results)
        avg_f1 = sum(r["f1"] for r in all_results) / len(all_results)
        avg_hall = sum(r["hallucination_rate"] for r in all_results) / len(all_results)

        # Judge metrics
        judge_results = [r for r in all_results if "judge_overall" in r]
        avg_judge = round(sum(r["judge_overall"] for r in judge_results) / len(judge_results), 4) if judge_results else None

        print(f"\n{'=' * 70}")
        print(f"SUMMARY ({provider} on {case_name})")
        print(f"{'=' * 70}")
        print(f"  Questions evaluated: {len(all_results)}")
        print(f"  Avg Recall:          {avg_recall:.1%}")
        print(f"  Avg Precision:       {avg_precision:.1%}")
        print(f"  Avg F1:              {avg_f1:.1%}")
        print(f"  Avg Hallucination:   {avg_hall:.1%}")
        if avg_judge is not None:
            print(f"  Avg Judge Score:     {avg_judge:.1%}")
            for dim in ["judge_accuracy", "judge_completeness", "judge_reasoning", "judge_hallucination_free"]:
                vals = [r[dim] for r in judge_results if dim in r]
                if vals:
                    print(f"    {dim.replace('judge_', ''):20s}: {sum(vals)/len(vals):.1f}/5")

        # Save results
        summary_dict = {
            "avg_recall": round(avg_recall, 4),
            "avg_precision": round(avg_precision, 4),
            "avg_f1": round(avg_f1, 4),
            "avg_hallucination_rate": round(avg_hall, 4),
        }
        if avg_judge is not None:
            summary_dict["avg_judge_score"] = avg_judge

        results_file = output_dir / f"manual_eval_{timestamp}.json"
        with open(results_file, 'w', encoding='utf-8') as f:
            json.dump({
                "timestamp": timestamp,
                "case_name": case_name,
                "case_id": case_id,
                "provider": provider,
                "num_questions": len(all_results),
                "summary": summary_dict,
                "detailed_results": all_results,
            }, f, indent=2, ensure_ascii=False)

        print(f"\n  Results saved: {results_file}")

        # Hint about judge workflow if no API key
        if avg_judge is None:
            print(f"\n  [TIP] To add LLM-as-judge scores (no API key needed):")
            print(f"    1. python benchmark.py --export-judge-prompts {results_file}")
            print(f"    2. Process prompts through Claude Desktop")
            print(f"    3. python benchmark.py --import-judge-scores <prompts_file> --merge-into {results_file}")

    return {"results": all_results}


# ============================================================
# CLI
# ============================================================

def main():
    parser = argparse.ArgumentParser(description="ArshaLab Benchmark Runner")
    parser.add_argument(
        "--providers",
        nargs="+",
        choices=list(PROVIDERS.keys()),
        default=list(PROVIDERS.keys()),
        help="LLM providers to test (default: all)",
    )
    parser.add_argument(
        "--runs",
        type=int,
        default=1,
        help="Number of runs per question for consistency (default: 1)",
    )
    parser.add_argument(
        "--questions",
        type=str,
        default=None,
        help="Comma-separated question IDs (e.g., Q01,Q02,Q03). Default: all",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Show questions without calling LLMs",
    )
    parser.add_argument(
        "--all-cases",
        action="store_true",
        help="Run benchmark on all 3 cases (CTF_Magnet_2022, KDFS_2023, DFC_2022)",
    )
    parser.add_argument(
        "--case-id",
        type=str,
        default=BENCHMARK_CASE_ID,
        help=f"Case ID for single-case mode (default: {BENCHMARK_CASE_ID})",
    )
    parser.add_argument(
        "--evaluate-responses",
        type=str,
        default=None,
        help="Evaluate pre-collected responses from JSON file (MCP manual mode)",
    )
    parser.add_argument(
        "--judge",
        action="store_true",
        help="Enable LLM-as-judge evaluation (uses Claude API to score each response)",
    )
    parser.add_argument(
        "--export-judge-prompts",
        type=str,
        default=None,
        metavar="RESULTS_JSON",
        help="Export judge prompts from benchmark results (for Claude Desktop evaluation)",
    )
    parser.add_argument(
        "--import-judge-scores",
        type=str,
        default=None,
        metavar="SCORES_JSON",
        help="Import judge scores from file (filled via Claude Desktop)",
    )
    parser.add_argument(
        "--merge-into",
        type=str,
        default=None,
        metavar="RESULTS_JSON",
        help="When importing judge scores, merge into this results file",
    )
    parser.add_argument(
        "--mode",
        choices=["retrieval", "analysis"],
        default="retrieval",
        help="Question mode: 'retrieval' for short factual questions (max_tokens=2048, max_tool_calls=25), "
             "'analysis' for deep investigation (max_tokens=8192, max_tool_calls=80). Default: retrieval",
    )

    args = parser.parse_args()

    # Export judge prompts mode
    if args.export_judge_prompts:
        export_judge_prompts(args.export_judge_prompts)
        return

    # Import judge scores mode
    if args.import_judge_scores:
        import_judge_scores(args.import_judge_scores, args.merge_into)
        return

    # Manual evaluation mode
    if args.evaluate_responses:
        evaluate_responses_file(args.evaluate_responses)
        return

    if args.dry_run:
        print("=" * 70)
        print("BENCHMARK QUESTIONS (dry run)")
        print("=" * 70)
        for q in QUESTIONS:
            print(f"\n  [{q['id']}] ({q['category']})")
            print(f"  Q: {q['question']}")
            print(f"  Builder: {q['ground_truth_builder']}")

        # Show ground truth for default case
        print(f"\n\n  Ground truth for {BENCHMARK_CASE_NAME}:")
        gt = build_ground_truth(BENCHMARK_CASE_ID)
        for qid, data in gt.items():
            print(f"    {qid}: {data['keywords']}")
        return

    question_ids = None
    if args.questions:
        question_ids = [q.strip().upper() for q in args.questions.split(",")]
        # Validation will happen when questions are loaded per case

    # Determine cases to test
    if args.all_cases:
        cases = BENCHMARK_CASES
    else:
        cases = [{"case_id": args.case_id, "case_name": next(
            (c["case_name"] for c in BENCHMARK_CASES if c["case_id"] == args.case_id),
            args.case_id
        )}]

    mode_config = QUESTION_MODES[args.mode]
    print(f"\n  Mode: {args.mode} ({mode_config['description']})")
    print(f"  max_tokens={mode_config['max_tokens']}, max_tool_calls={mode_config['max_tool_calls']}")

    run_benchmark(
        providers=args.providers,
        question_ids=question_ids,
        num_runs=args.runs,
        cases=cases,
        use_judge=args.judge,
        question_mode=args.mode,
    )


if __name__ == "__main__":
    main()
