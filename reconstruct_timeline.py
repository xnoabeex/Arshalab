"""Mode 2 step 2 — model reasoning: order pre-retrieved evidence into a
causal-temporal incident timeline with provenance.

Per-step protocol (follows the user's structure literally):
  - input  : evidence dump produced by retrieve_evidence.py
  - task   : pick the events that form the adversary attack chain and order
             them chronologically with provenance
  - output : JSON array of {timestamp, event, supporting_artifact,
             confidence_or_caveat[, phase]}

Same evidence dump is fed to every model -> fair Mode 2 comparison.

Usage:
    python reconstruct_timeline.py --provider deepseek --case magnet --run 1
"""
import argparse
import json
import os
import re
import sys
import time
import urllib.request
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
from dotenv import load_dotenv
load_dotenv()

CASES = {
    "kdfs":      "KDFS_2023",
    "magnet":    "Magnet_CTF_2022",
    "4orensics": "Hunter_4orensics",
}

CASE_IDS = {
    "kdfs":      "case_20260128_141256",
    "magnet":    "case_20260323_032324",
    "4orensics": "case_20260410_120043",
}

SYSTEM_PROMPT = (
    "You are a senior DFIR (Digital Forensics and Incident Response) "
    "analyst. You will receive pre-retrieved Windows forensic evidence "
    "from a single case, organised by anchor query. Your job is to "
    "reconstruct the adversary attack chain: select the events that "
    "represent meaningful steps of preparation, execution, persistence, "
    "and cleanup, then order them chronologically with source provenance "
    "for every step. You must NOT invent events. You may only output a "
    "JSON array; no prose, no markdown, no preamble. "
    "STRICT FIELD GROUNDING FOR WINDOWS SERVICE EVENTS: For Windows "
    "Service Control Manager events (EventID 7045 service installation, "
    "EventID 7036 service state change), only state the service name or "
    "ImagePath if the evidence record contains an explicit `service_name`, "
    "`image_path`, or `ImagePath` field. If those fields are absent, "
    "describe the event generically (e.g., 'unidentified service "
    "installation, service name not in record') and set "
    "`confidence_or_caveat` to 'low'. Never infer service identity, "
    "binary filename, or vendor from external knowledge of the host, "
    "campaign, or other anchors. The same field-grounding rule applies "
    "to ANY field not literally present in the evidence record."
)

USER_TEMPLATE = """You are reconstructing the incident timeline for case "{case_name}". The evidence below was retrieved deterministically using DFIR anchor queries spanning communication apps, crypto/finance apps, file-sharing platforms, archive tools, remote-access tools, anti-forensic tools, email clients, Windows EventLog detections, PowerShell, MFT, registry, prefetch, amcache, USN journal, browser. Total records: {total_records}.

YOUR TASK: From this evidence, reconstruct the suspect's incident timeline and order events chronologically. The chain MUST span the FULL incident window. Do NOT cluster the chain on a single date.

This case may follow ANY of these incident patterns (you must identify which applies from the evidence):
  (A) Windows endpoint compromise — adversary tools installed, Defender tampered, PowerShell C2, persistence keys, exfil.
  (B) Insider data exfiltration — suspect uses tools (port scanners, archives, remote-access) to collect and ship data to an outside party.
  (C) Criminal-insider scenario — suspect's own conduct: financial motive research, online accomplice recruitment via chat apps (Discord/Skype/Telegram), crypto payment setup (MetaMask/Ledger/exchange), payload creation, file-sharing handoff URL, ransomware distribution, victim attacks, revenue laundering. Evidence is HUMAN/SOCIAL (chats, browser searches, crypto transactions, ENS domains) as much as it is technical (file drops, registry).
  (D) Mixed.

Select the events that represent meaningful incident steps across the applicable dimensions. For criminal-insider cases (C), Discord/Skype channel visits, crypto wallet installs, Bandizip / 7zip archive packaging, gofile/mega.nz/dropbox URLs, USB device connections, and ransom-related filenames ARE the attack chain — do not dismiss them as "user activity". For Windows compromise (A), pick Defender tampering, service installs, PowerShell scripts, persistence keys, account creation.

Examine these dimensions and select corresponding events WHERE THE EVIDENCE SUPPORTS THEM:
  - Suspect's motive / preparation (financial research, tool downloads, app installs preceding incident)
  - Communication / accomplice contact (Discord/Skype/Telegram channels, DM platforms, IRC)
  - Crypto / payment infrastructure (MetaMask install, Ledger Live, Coinone/Binance/Changelly, wallet transactions)
  - Payload / weapon (ransom*.exe / *.zip, suspicious archives, encoded files, malicious scripts)
  - Payload packaging (Bandizip / 7zip / WinRAR runs on payload files)
  - Distribution handoff (gofile / mega.nz / mediafire / wetransfer URLs, file-sharing services)
  - Remote access (TeamViewer / AnyDesk / VNC — for accomplice or hand-off)
  - USB / removable media exfil (USBSTOR registry, SanDisk/Cruzer-like USB devices in EventLog)
  - Email exfil (Outlook OST/PST modifications, attachment patterns)
  - Anti-forensic activity (BCWipe / CCleaner / Eraser / Crypto Swap, file_deleter, log clearing 1102)
  - Defender events (5007 config tampering, 1116/1117 detection/action)
  - Adversary-tool installation (EventLog 7045 service, .msi/.exe drops in Downloads/AppData, driver .sys)
  - Adversary scripts on disk (MFT .ps1/.bat/.vbs in user dirs)
  - PowerShell adversary activity (EventLog 4104/4103/4100)
  - Persistence registry keys (Run/RunOnce/Services/Tasks)
  - Unauthorized account creation (EventLog 4720)

OUTPUT FORMAT (strict): a single JSON array. Each element MUST be a JSON object with EXACTLY these fields:
  "timestamp"           : exact timestamp copied from evidence (string)
  "event"               : concise description, MUST mention concrete identifier (filename / event ID / SID / domain) from evidence
  "supporting_artifact" : the anchor / artifact source from evidence (e.g. "EventLog Event 4720", "MFT", "Registry Run key")
  "confidence_or_caveat": "high" / "medium" / "low" or a short caveat string
  "phase"               : one of: preparation, execution, persistence, privilege_escalation, defense_evasion, command_and_control, exfiltration, impact, anti_forensics

CRITICAL RULES:
- Use ONLY facts present in the evidence below. Do NOT invent timestamps, file names, or event IDs.
- Aim for 15 to 30 attack-chain events. Span the entire incident window — do not over-represent a single date.
- For each event, the "event" field MUST contain at least one concrete identifier from evidence (filename, event ID, IP, SID, account name).
- When the same artifact appears in multiple time records (e.g. ZeroTier service install across several dates), pick the EARLIEST occurrence as the install / first-seen moment. Later records of the same artifact are usually re-references, not new events.
- Records within each anchor are pre-sorted chronologically; the FIRST record per anchor is usually the genuine first-seen of that event class.
- Output ONLY the JSON array. No prose before or after. NO markdown headers. NO narrative summary.
- If you write prose, your output will be DISCARDED. The downstream parser cannot read prose.

MANDATORY MITRE TACTIC CHECKLIST:
Your chain MUST include at least one event for EACH of the following MITRE ATT&CK tactic categories WHEN the evidence contains a corresponding record. Before emitting your JSON, scan your chain and verify each applicable tactic is represented at least once. Do NOT skip a tactic if evidence for it exists.

  - reconnaissance        : search queries, recon downloads, port scans
  - initial_access        : downloaded installers, drive-by, first failed/successful logon, valid-account abuse
  - execution             : .ps1/.bat/.vbs/.exe file creations + corresponding PowerShell/cmd execution events
  - persistence           : Run/RunOnce/Services/Tasks/USBSTOR keys, service installs (Event 7045), new account creation (Event 4720)
  - privilege_escalation  : SYSTEM-attributed account modifications, 4672 special privilege, 4738 account modified by SYSTEM
  - defense_evasion       : Defender tampering (Event 5007), Defender detections (1116/1117), audit log clear (1102), hidden folders, anti-forensic file_deleter scripts
  - credential_access     : failed logons (Event 4625), explicit-credential logons (4648), credential dumping signatures
  - discovery             : network discovery, DHCP queries, system enumeration, scan tools
  - lateral_movement      : remote-access tools (TeamViewer, AnyDesk), RDP, PSExec
  - collection            : data staging folders, archive creation (.zip/.7z/.rar in user dirs)
  - command_and_control   : VPN tunnels (ZeroTier), powercat, suspicious external IPs in PowerShell 4100
  - exfiltration          : USB exfil, cloud-storage uploads, archive transfers
  - impact                : ransom indicators, file encryption, destruction
  - anti_forensics        : log clearing, secure-delete tools, evidence wiping

If the evidence contains records relevant to a tactic above, include AT LEAST ONE chain event for that tactic. Failing to cover a tactic when evidence supports it is a critical reporting error.

EXAMPLE OUTPUT FORMAT (a 2-event chain for illustration — fields ONLY, do NOT copy these literal values; your real output will have 15-30 events grounded in the evidence below):
[
  {{
    "timestamp": "<EXACT timestamp string copied from an evidence record>",
    "event": "<concise description with at least one concrete identifier (filename/EventID/SID/domain) that LITERALLY appears in an evidence record>",
    "supporting_artifact": "<artifact source label, e.g. 'EventLog Event 7045'>",
    "confidence_or_caveat": "high | medium | low | <short caveat>",
    "phase": "preparation | execution | persistence | privilege_escalation | defense_evasion | command_and_control | exfiltration | impact | anti_forensics"
  }}
]

Now produce YOUR JSON array for case "{case_name}" based on the evidence below. Remember: JSON ARRAY ONLY, no prose.

PRE-RETRIEVED EVIDENCE (JSON, anchor -> list of records):
{evidence}
"""

# ----------------------------- I/O helpers -------------------------------

def load_evidence(case_key, evidence_dir="benchmark_results/mode2"):
    case_name = CASES[case_key]
    path = Path(f"{evidence_dir}/evidence_{case_name}.json")
    if not path.exists():
        raise FileNotFoundError(
            f"Evidence dump not found: {path}. "
            f"Run: python retrieve_evidence.py --case {case_key}")
    return json.load(open(path, encoding="utf-8"))

def compact_evidence(evidence_payload, max_chars=350000):
    """Render evidence as compact text. Truncate per-anchor if huge.
    Per-record limit raised to 1500 chars so embedded high-signal tokens
    (Discord chat handles, MetaMask folder names, Korean search queries)
    survive truncation — these are often deep inside JSON .message or
    .file_path fields that the 600-char cap was clipping."""
    chunks = []
    for anchor_id, records in evidence_payload["evidence_by_anchor"].items():
        if not records:
            continue
        chunk = f"\n--- {anchor_id} ({len(records)} records) ---\n"
        for r in records:
            line = json.dumps(r, ensure_ascii=False, default=str)
            if len(line) > 1500:
                line = line[:1500] + "...]"
            chunk += line + "\n"
        chunks.append(chunk)
    text = "".join(chunks)
    if len(text) > max_chars:
        text = text[:max_chars] + f"\n[... evidence truncated to {max_chars} chars ...]\n"
    return text

def extract_json_array(text):
    if not text:
        return None
    m = re.search(r"```(?:json)?\s*(\[.*?\])\s*```", text, re.S)
    if m:
        try:
            return json.loads(m.group(1))
        except json.JSONDecodeError:
            pass
    start = text.find("[")
    while start != -1:
        depth = 0; in_str = False; esc = False
        for i in range(start, len(text)):
            ch = text[i]
            if esc: esc = False; continue
            if ch == "\\": esc = True; continue
            if ch == '"': in_str = not in_str; continue
            if in_str: continue
            if ch == "[": depth += 1
            elif ch == "]":
                depth -= 1
                if depth == 0:
                    try:
                        return json.loads(text[start:i+1])
                    except json.JSONDecodeError:
                        break
        start = text.find("[", start + 1)
    return None

# ----------------------------- LLM backends ------------------------------

def call_openai_compat(model, base_url, api_key_env, prompt, system,
                       max_tokens=8192):
    from openai import OpenAI
    api_key = os.getenv(api_key_env)
    if not api_key:
        raise RuntimeError(f"{api_key_env} not set")
    client = (OpenAI(api_key=api_key, base_url=base_url) if base_url
              else OpenAI(api_key=api_key))
    kwargs = dict(model=model, messages=[
        {"role": "system", "content": system},
        {"role": "user",   "content": prompt},
    ])
    if "gpt-5" in model:
        kwargs["max_completion_tokens"] = max_tokens
    else:
        kwargs["max_tokens"] = max_tokens
        kwargs["temperature"] = 0
    # gpt-5.1 occasionally returns an empty "[]" response on first try
    # (non-deterministic). Retry up to 3 times if we got <100 chars back.
    for attempt in range(3):
        resp = client.chat.completions.create(**kwargs)
        content = resp.choices[0].message.content or ""
        if len(content) >= 100 or attempt == 2:
            return content
        print(f"  [openai retry {attempt+1}/3] got {len(content)} chars, retrying", flush=True)
    return content

def call_ollama(model, prompt, system, num_ctx=131072, max_tokens=8192):
    body = json.dumps({
        "model": model,
        "messages": [
            {"role": "system", "content": system},
            {"role": "user",   "content": prompt},
        ],
        "stream": False,
        "options": {"temperature": 0, "num_ctx": num_ctx,
                    "num_predict": max_tokens},
    }).encode()
    req = urllib.request.Request(
        "http://localhost:11434/api/chat", body,
        {"Content-Type": "application/json"})
    return json.load(urllib.request.urlopen(req, timeout=1800))["message"]["content"]

def call_mcp_cli(model, prompt, case_id):
    """Spawn claude CLI in headless mode. Long evidence prompts can exceed
    Windows CLI arg length (~32K char), so we write the prompt to a temp
    file and pipe it via stdin."""
    import subprocess
    import tempfile
    import os
    CLAUDE_CMD = os.environ.get("CLAUDE_CMD", "claude")
    project_dir = Path(__file__).resolve().parent
    mcp_config = str(project_dir / "mcp_config.json")
    full = (
        "You will be given a JSON evidence dump and must produce a JSON "
        "array per the strict schema in the prompt. Do not call any tools. "
        "Use ONLY the evidence provided in the prompt below.\n\n"
        + prompt
    )
    cmd = [
        CLAUDE_CMD, "-p",
        "--mcp-config", mcp_config,
        "--model", model,
        "--dangerously-skip-permissions",
        "--max-turns", "3",
    ]
    # Pipe prompt via stdin to bypass Windows CLI arg-length limit.
    result = subprocess.run(cmd, input=full, capture_output=True, text=True,
                            timeout=1800, cwd=str(project_dir),
                            encoding="utf-8")
    if result.returncode != 0:
        return f"ERROR: claude CLI exit {result.returncode}: {(result.stderr or '')[:300]}"
    return (result.stdout or "").strip()

PROVIDERS = {
    "deepseek": lambda p, s, cid: call_openai_compat(
        "deepseek-chat", "https://api.deepseek.com", "DEEPSEEK_API_KEY",
        p, s, max_tokens=16384),
    "openai":   lambda p, s, cid: call_openai_compat(
        "gpt-5.1", None, "OPENAI_API_KEY", p, s, max_tokens=32768),
    "sonnet":   lambda p, s, cid: call_mcp_cli("sonnet", p, cid),
    "opus":     lambda p, s, cid: call_mcp_cli("opus",   p, cid),
    "llama":    lambda p, s, cid: call_ollama("llama3.1:8b", p, s),
    "qwen":     lambda p, s, cid: call_ollama("qwen2.5:14b", p, s),
}

# ----------------------------- main --------------------------------------

def reconstruct(provider, case_key, run_idx,
                evidence_dir="benchmark_results/mode2",
                out_dir_override=None):
    case_name = CASES[case_key]
    case_id   = CASE_IDS[case_key]
    out_dir = Path(out_dir_override) if out_dir_override else Path("benchmark_results/mode2")
    out_dir.mkdir(parents=True, exist_ok=True)

    evidence = load_evidence(case_key, evidence_dir=evidence_dir)
    evidence_text = compact_evidence(evidence)
    prompt = USER_TEMPLATE.format(
        case_name=case_name, total_records=evidence["total_records"],
        evidence=evidence_text)
    prompt_size = len(prompt)
    print(f"[mode2 {provider}/{case_key}/run{run_idx}] "
          f"prompt {prompt_size} chars (~{prompt_size//4} tokens)")

    t0 = time.time()
    resp = PROVIDERS[provider](prompt, SYSTEM_PROMPT, case_id)
    dt = time.time() - t0
    print(f"[mode2 {provider}/{case_key}/run{run_idx}] "
          f"LLM response {len(resp or '')} chars in {dt:.0f}s")

    chain = extract_json_array(resp or "")
    out_stem = f"chain_{case_name}_{provider}_run{run_idx}"
    if not isinstance(chain, list):
        (out_dir / f"{out_stem}.error.txt").write_text(resp or "", encoding="utf-8")
        print(f"ERROR: model did not return a JSON array. "
              f"raw saved -> {out_dir / (out_stem + '.error.txt')}",
              file=sys.stderr)
        sys.exit(3)

    out_path = out_dir / f"{out_stem}.json"
    payload = {
        "provider": provider,
        "case": case_key,
        "case_name": case_name,
        "case_id": case_id,
        "run": run_idx,
        "evidence_file": f"evidence_{case_name}.json",
        "evidence_record_count": evidence["total_records"],
        "chain_event_count": len(chain),
        "prompt_chars": prompt_size,
        "elapsed_seconds": round(dt, 1),
        "chain": chain,
    }
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(payload, f, indent=2, ensure_ascii=False)
    print(f"[mode2 {provider}/{case_key}/run{run_idx}] "
          f"chain {len(chain)} events -> {out_path}")
    return payload


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--provider", required=True, choices=list(PROVIDERS))
    ap.add_argument("--case", required=True, choices=list(CASES))
    ap.add_argument("--run", type=int, default=1)
    ap.add_argument("--evidence_dir", default="benchmark_results/mode2",
                    help="Directory containing evidence_<case>.json (default v1 path)")
    ap.add_argument("--out_dir", default=None,
                    help="Output directory for chain JSON (default same as evidence_dir parent or mode2)")
    args = ap.parse_args()
    reconstruct(args.provider, args.case, args.run,
                evidence_dir=args.evidence_dir,
                out_dir_override=args.out_dir)


if __name__ == "__main__":
    main()
