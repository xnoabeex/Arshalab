"""Attack-chain reconstruction, stage 1 (v2) — comprehensive DFIR evidence retrieval.

Goal vs v1: replace the 48-anchor v1 set (mixing universal + case-tuned
signal) with a canonical 98-anchor catalog covering all major Windows
incident-response domains. Designed to be strictly case-agnostic and forensically complete.

Design principles:
  1. Universal pattern on every anchor — no hardcoded filenames, usernames,
     IPs, hashes, or domain strings from our 3 evaluation cases.
  2. Microsoft-documented EventIDs and channel names only.
  3. Domain-category anchors use generic indicator lists (TeamViewer,
     AnyDesk, ...) covering the documented threat-tooling landscape, not
     specific instances from KDFS/Magnet/Hunter.
  4. Tiered sizing keeps the evidence pool within the prompt budget. The
     released pools hold 691 records on Hunter, 746 on KDFS and 798 on Magnet.

Anchors cover 10 DFIR domains:
  A. Identity & Access     (19)
  B. Process & Execution   (16)
  C. Defense & Tampering   (10)
  D. Network & Connectivity (6)
  E. Removable Media & USB  (4)
  F. RDP & Lateral Movement (4)
  G. File & Registry Audit  (5)
  H. MFT / File-System      (10)
  I. Persistence & Configuration (6)
  J. Application Errors & Domain (18)
                              = 98 anchors

Output schema is identical to v1 so the downstream scorer
(score_timeline_mode2.py) does not need to change.

Output: benchmark_results/mode2_v2/evidence_<case>.json
"""
import argparse
import json
import os
import re
import sys
import requests
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
from src.llm.base_analyzer import BaseAnalyzer

CASES = {
    "kdfs":      ("KDFS_2023",        "case_20260128_141256"),
    "magnet":    ("Magnet_CTF_2022",  "case_20260323_032324"),
    "4orensics": ("Hunter_4orensics", "case_20260410_120043"),
}

# Bounded incident windows per case (same as v1 — these define the time
# scope of the investigation, not the anchor patterns themselves).
INCIDENT_WINDOWS = {
    "kdfs":      ("2023-09-15", "2023-09-30"),
    "magnet":    ("2022-02-01", "2022-02-14"),
    "4orensics": ("2016-06-15", "2016-06-25"),
}

# Multiplier applied to every anchor's `limit`/`size`. 1.0 reproduces the catalogue as written.
ANCHOR_LIMIT_SCALE = float(os.environ.get("ARSHALAB_ANCHOR_LIMIT_SCALE", "1.0"))


def _es_search_bounded(case_id, index_pattern, query_string, start_date,
                       end_date, size=80, sort_asc=True):
    """ES search bounded by case + incident window + free-text query.
    Identical to v1 helper."""
    body = {
        "size": size,
        "query": {
            "bool": {
                "must": [
                    {"query_string": {"query": query_string,
                                       "default_field": "*",
                                       "lenient": True}}
                ] if query_string else [{"match_all": {}}],
                "filter": [
                    {"term": {"case_id.keyword": case_id}},
                    {"range": {"timestamp.keyword": {
                        "gte": start_date,
                        "lte": f"{end_date}T23:59:59"
                    }}}
                ],
                # Phase-4 hallucination-investigation fix (root-cause B):
                # excludes records where timestamp.keyword is the empty string,
                # which otherwise sort to the top under asc and crowd out real
                # records for amcache/shimcache/jumplist/usnjrnl anchors.
                "must_not": [{"term": {"timestamp.keyword": ""}}]
            }
        },
        "sort": [{"timestamp.keyword": {
            "order": "asc" if sort_asc else "desc",
            "unmapped_type": "keyword"}}],
    }
    try:
        r = requests.post(f"http://localhost:9200/{index_pattern}/_search",
                          json=body, timeout=15)
        if r.status_code != 200:
            return []
        return [h["_source"] for h in r.json().get("hits", {}).get("hits", [])]
    except Exception:
        return []


# =============================================================================
# RECORD-LEVEL COMPRESSION
# Shrinks raw forensic records (~1100 chars JSON-dumped) down to ~200 chars by
# keeping only forensically diagnostic fields. The artifact type is inferred
# from the anchor_id prefix; unknown anchors get a 200-char fallback dump.
# =============================================================================
ARTIFACT_FIELD_MAP = {
    # eventlog-family anchors -> keep these fields
    'eventlog': ['event_id', 'channel', 'computer', 'user_name', 'source_ip',
                  'target_user', 'target_domain', 'logon_type', 'image_path',
                  'command_line', 'target_filename', '_bucket'],
    'mft': ['file_path', 'full_path', 'file_name', 'in_use', 'size_bytes',
            'size', 'parent_path', 'file_extension', 'sha1', 'md5'],
    'registry': ['key_path', 'value_name', 'value_data', 'value', 'hive'],
    'usnjrnl': ['file_name', 'reason', 'file_path'],
    'browser': ['url', 'title', 'visit_time', 'user'],
    'execution': ['executable_name', 'run_count', 'last_run_time',
                  'executable_path', 'sha1'],
    'lnk': ['target_path', 'target_size', 'machine_id', 'target_modified',
            'target_path_full'],
    'srum': ['application', 'bytes_sent', 'bytes_received', 'user'],
}

ANCHOR_TO_TYPE = {
    'eventlog': ['auth_', 'proc_', 'svc_', 'tasks_', 'ps_', 'def_', 'audit_',
                  'fw_', 'net_', 'dhcp_', 'usb_', 'device_', 'rdp_', 'smb_',
                  'file_audit_', 'object_', 'permissions_', 'registry_audit_',
                  'app_crashes', 'app_hangs', 'wer_', 'applocker_', 'wmi_',
                  'time_'],
    'mft': ['mft_'],
    'registry': ['reg_'],
    'usnjrnl': ['usnjrnl_'],
    'browser': ['browser_'],
    'execution': ['prefetch_', 'shimcache_', 'amcache_'],
    'lnk': ['lnk_', 'jumplist_'],
    'srum': ['srum_'],
}


def _infer_artifact_type(anchor_id):
    for atype, prefixes in ANCHOR_TO_TYPE.items():
        for p in prefixes:
            if anchor_id.startswith(p):
                return atype
    return None


def compress_record(record, anchor_id, max_fallback_chars=200):
    """Compress a raw forensic record to its diagnostic essentials.

    Keeps: timestamp + _anchor (always) + artifact-type-specific fields.
    For unknown anchor types, keeps timestamp + a 200-char str(record) blob.
    """
    if not isinstance(record, dict):
        return {'_raw': str(record)[:max_fallback_chars], '_anchor': anchor_id}
    out = {'_anchor': anchor_id}
    ts = record.get('timestamp')
    if ts is not None:
        out['timestamp'] = ts
    atype = _infer_artifact_type(anchor_id)
    if atype and atype in ARTIFACT_FIELD_MAP:
        for f in ARTIFACT_FIELD_MAP[atype]:
            v = record.get(f)
            if v is not None and v != '':
                out[f] = v
    else:
        # Fallback: keep timestamp + first N chars of str(record)
        out['_raw'] = str(record)[:max_fallback_chars]
    return out


# =============================================================================
# COMPREHENSIVE DFIR ANCHOR CATALOG (98 anchors, 10 domains)
# Each entry: (anchor_id, tool_method_or_BOUNDED_ES, kwargs)
# Size tiers: Core=40-50, Standard=20-30, Narrow=10-20
# =============================================================================

ANCHORS_V2 = [

    # =========================================================================
    # A. IDENTITY & ACCESS — Windows authentication and account lifecycle.
    # All Microsoft Security-Auditing channel EventIDs, universal across any
    # Windows incident.
    # =========================================================================

    # Interactive logon (physical console) — most diagnostic for "who used the box".
    ("auth_logon_interactive_type2", "_tool_search_artifacts",
     {"query": "4624 AND \"LogonType=2\"", "artifact_type": "eventlog", "limit": 15}),
    # Network logon (SMB / file share / shell) — primary lateral-movement indicator.
    ("auth_logon_network_type3", "_tool_search_artifacts",
     {"query": "4624 AND \"LogonType=3\"", "artifact_type": "eventlog", "limit": 12}),
    # RDP logon — high-value lateral-movement indicator.
    ("auth_logon_rdp_type10", "_tool_search_artifacts",
     {"query": "4624 AND \"LogonType=10\"", "artifact_type": "eventlog", "limit": 12}),
    # Service / batch logon — service or scheduled-task execution context.
    ("auth_logon_service_type5", "_tool_search_artifacts",
     {"query": "4624 AND (\"LogonType=4\" OR \"LogonType=5\")", "artifact_type": "eventlog", "limit": 10}),
    # Unlock — session resumption after lock screen.
    ("auth_logon_unlock_type7", "_tool_search_artifacts",
     {"query": "4624 AND \"LogonType=7\"", "artifact_type": "eventlog", "limit": 8}),
    # Logon failures — brute-force or misconfigured-credential attempts.
    ("auth_logon_failures_4625", "_tool_analyze_security_events",
     {"event_id": 4625, "limit": 15}),
    # Explicit-credentials use — RunAs, lateral movement via specified creds.
    ("auth_explicit_cred_4648", "_tool_analyze_security_events",
     {"event_id": 4648, "limit": 12}),
    # Special privileges assigned at logon — admin / privileged session start.
    ("auth_priv_assigned_4672", "_tool_analyze_security_events",
     {"event_id": 4672, "limit": 10}),
    # Account lifecycle — creation, enable/disable, deletion.
    ("auth_account_created_4720", "_tool_analyze_security_events",
     {"event_id": 4720, "limit": 12}),
    ("auth_account_enabled_4722", "_tool_search_artifacts",
     {"query": "4722", "artifact_type": "eventlog", "limit": 15}),
    ("auth_account_disabled_4725", "_tool_search_artifacts",
     {"query": "4725", "artifact_type": "eventlog", "limit": 15}),
    ("auth_account_deleted_4726", "_tool_search_artifacts",
     {"query": "4726", "artifact_type": "eventlog", "limit": 15}),
    # Account modification — group membership changes and account attribute mods.
    ("auth_account_modified_4738", "_tool_analyze_security_events",
     {"event_id": 4738, "limit": 10}),
    # Group membership operations.
    ("auth_group_added_4732", "_tool_search_artifacts",
     {"query": "4732", "artifact_type": "eventlog", "limit": 20}),
    # Account lockout & unlock.
    ("auth_account_lockout_4740", "_tool_search_artifacts",
     {"query": "4740", "artifact_type": "eventlog", "limit": 15}),
    # Kerberos TGT request — golden-ticket detection foundation.
    ("auth_kerberos_tgt_4768", "_tool_search_artifacts",
     {"query": "4768", "artifact_type": "eventlog", "limit": 10}),
    # Kerberos service ticket — silver-ticket detection foundation.
    ("auth_kerberos_service_4769", "_tool_search_artifacts",
     {"query": "4769", "artifact_type": "eventlog", "limit": 10}),
    # NTLM authentication — legacy auth, often lateral.
    ("auth_ntlm_4776", "_tool_search_artifacts",
     {"query": "4776", "artifact_type": "eventlog", "limit": 10}),
    # Logoff events — session boundary.
    ("auth_logoff", "_tool_search_artifacts",
     {"query": "4634 OR 4647", "artifact_type": "eventlog", "limit": 15}),

    # =========================================================================
    # B. PROCESS & EXECUTION — process creation, services, scheduled tasks,
    # script engines. Captures every execution path the attacker could use.
    # =========================================================================

    # Process creation (4688) — universal need; depends on Audit Process Creation policy.
    ("proc_creation_4688", "_tool_search_artifacts",
     {"query": "4688", "artifact_type": "eventlog", "limit": 20}),
    # Process termination — anomalous early termination, anti-debug indicators.
    ("proc_termination_4689", "_tool_search_artifacts",
     {"query": "4689", "artifact_type": "eventlog", "limit": 15}),
    # Service installation — classic persistence vector (7045).
    ("svc_install_7045", "_tool_analyze_security_events",
     {"event_id": 7045, "limit": 15}),
    # Service crashes — instability or attack-induced failure.
    ("svc_crashed_7034", "_tool_search_artifacts",
     {"query": "7034", "artifact_type": "eventlog", "limit": 20}),
    # Service state changes — start/stop of attacker-controlled services.
    ("svc_state_change", "_tool_search_artifacts",
     {"query": "7035 OR 7036", "artifact_type": "eventlog", "limit": 15}),
    # Service start-type change — persistence elevation (auto-start).
    ("svc_starttype_changed_7040", "_tool_search_artifacts",
     {"query": "7040", "artifact_type": "eventlog", "limit": 15}),
    # Scheduled-task creation — persistence vector.
    ("tasks_created_4698", "_tool_search_artifacts",
     {"query": "4698", "artifact_type": "eventlog", "limit": 12}),
    # Scheduled-task deletion — cleanup attempt.
    ("tasks_deleted_4699", "_tool_search_artifacts",
     {"query": "4699", "artifact_type": "eventlog", "limit": 15}),
    # Scheduled-task enabled / disabled / updated.
    ("tasks_lifecycle", "_tool_search_artifacts",
     {"query": "4700 OR 4701 OR 4702", "artifact_type": "eventlog", "limit": 15}),
    # PowerShell ScriptBlock logging — actual script content if enabled.
    ("ps_scriptblock_4104", "_tool_search_artifacts",
     {"query": "4104", "artifact_type": "eventlog", "limit": 15}),
    # PowerShell module logging.
    ("ps_module_4103", "_tool_search_artifacts",
     {"query": "4103", "artifact_type": "eventlog", "limit": 10}),
    # PowerShell engine errors / exceptions — diagnostic for failed malicious script execution.
    ("ps_errors_4100", "_tool_search_artifacts",
     {"query": "4100", "artifact_type": "eventlog", "limit": 10}),
    # PowerShell engine start / pipeline execution.
    ("ps_engine_lifecycle", "_tool_search_artifacts",
     {"query": "\"600\" AND PowerShell OR \"800\" AND PowerShell",
      "artifact_type": "eventlog", "limit": 8}),
    # WMI event-subscription persistence — fileless persistence.
    ("wmi_subscription", "_tool_search_artifacts",
     {"query": "5857 OR 5858 OR 5859 OR 5860 OR 5861",
      "artifact_type": "eventlog", "limit": 10}),
    # AppLocker audit-mode events — audit-mode would-be-blocked execution attempts.
    ("applocker_audited", "_tool_search_artifacts",
     {"query": "8003 OR 8006", "artifact_type": "eventlog", "limit": 8}),
    # AppLocker blocked events — attempted execution blocks.
    ("applocker_blocked", "_tool_search_artifacts",
     {"query": "8004 OR 8007", "artifact_type": "eventlog", "limit": 10}),

    # =========================================================================
    # C. DEFENSE STATUS & TAMPERING — Defender, audit policy, firewall stop,
    # log clearing. Detects anti-forensic activity and security weakening.
    # =========================================================================

    # Defender threat detection — primary AV signal.
    ("def_threat_detected_1116", "_tool_analyze_security_events",
     {"event_id": 1116, "limit": 15}),
    # Defender action taken — remediation log.
    ("def_action_taken_1117", "_tool_analyze_security_events",
     {"event_id": 1117, "limit": 12}),
    # Defender action failed — attempted-but-failed cleanup.
    ("def_action_failed_1118", "_tool_search_artifacts",
     {"query": "1118", "artifact_type": "eventlog", "limit": 15}),
    # Defender config change — disabling or weakening AV.
    ("def_config_change_5007", "_tool_search_artifacts",
     {"query": "5007", "artifact_type": "eventlog", "limit": 10}),
    # Defender real-time protection disabled.
    ("def_realtime_disabled", "_tool_search_artifacts",
     {"query": "5004 OR 5010", "artifact_type": "eventlog", "limit": 10}),
    # Defender engine updates — health-check timeline.
    ("def_engine_update", "_tool_search_artifacts",
     {"query": "2000 OR 2001 OR 2002 OR 2003", "artifact_type": "eventlog", "limit": 6}),
    # Audit log cleared — explicit anti-forensic act.
    ("audit_log_cleared_1102", "_tool_search_artifacts",
     {"query": "1102", "artifact_type": "eventlog", "limit": 15}),
    # Audit policy changed — silent tampering with what gets logged.
    ("audit_policy_changed_4719", "_tool_search_artifacts",
     {"query": "4719", "artifact_type": "eventlog", "limit": 20}),
    # Firewall service stopped — perimeter weakening.
    ("fw_stopped_5025", "_tool_search_artifacts",
     {"query": "5025", "artifact_type": "eventlog", "limit": 15}),
    # System time changed — anti-forensic clock manipulation.
    ("time_changed_4616", "_tool_search_artifacts",
     {"query": "4616", "artifact_type": "eventlog", "limit": 8}),

    # =========================================================================
    # D. NETWORK & CONNECTIVITY — connection events, firewall rule changes,
    # DHCP authentication. Surfaces network-attack indicators.
    # =========================================================================

    # Filtering Platform Connection allowed (5156) — outbound/inbound traffic.
    ("net_connections_5156", "_tool_search_artifacts",
     {"query": "5156", "artifact_type": "eventlog", "limit": 15}),
    # Firewall rule lifecycle — attacker-added exceptions.
    ("fw_rule_added_4946", "_tool_search_artifacts",
     {"query": "4946", "artifact_type": "eventlog", "limit": 20}),
    ("fw_rule_modified_4947", "_tool_search_artifacts",
     {"query": "4947", "artifact_type": "eventlog", "limit": 15}),
    ("fw_rule_deleted_4948", "_tool_search_artifacts",
     {"query": "4948", "artifact_type": "eventlog", "limit": 15}),
    # Firewall settings changes via group policy / local policy.
    ("fw_setting_changed", "_tool_search_artifacts",
     {"query": "4950 OR 4954 OR 4956", "artifact_type": "eventlog", "limit": 8}),
    # DHCP-Client/Admin channel — DHCP client lease state changes.
    ("dhcp_auth_50036_50037", "_tool_search_artifacts",
     {"query": "50036 OR 50037", "artifact_type": "eventlog", "limit": 10}),

    # =========================================================================
    # E. REMOVABLE MEDIA & USB — USB attach detection through multiple sources.
    # Critical for insider-data-exfiltration scenarios.
    # =========================================================================

    # USB attach detail via DriverFrameworks-UserMode/USBSTOR — definitive USB-attach record.
    ("usb_attach_driverframeworks", "BOUNDED_ES",
     {"index": "forensic-eventlog",
      "query": "USBSTOR OR \"DriverFrameworks-UserMode\" OR \"Mass Storage\"",
      "size": 15}),
    # Kernel-PnP device install (Kernel-PnP) — hardware enumeration.
    ("usb_kernel_pnp_install", "_tool_search_artifacts",
     {"query": "219 OR 225 OR 410 OR 411 OR 420 OR 441 OR 442", "artifact_type": "eventlog", "limit": 10}),
    # Security-Auditing external device recognition.
    ("device_install_recognition", "_tool_search_artifacts",
     {"query": "6416 OR 6419 OR 6420 OR 6421 OR 6422 OR 6423 OR 6424", "artifact_type": "eventlog", "limit": 10}),
    # SetupAPI-style device install events (more generic capture).
    ("device_setupapi_events", "_tool_search_artifacts",
     {"query": "20001 OR 20003", "artifact_type": "eventlog", "limit": 10}),

    # =========================================================================
    # F. RDP & LATERAL MOVEMENT — RDP session events, SMB share access,
    # remote-execution indicators.
    # =========================================================================

    # RDP session lifecycle via TerminalServices-LocalSessionManager.
    ("rdp_session_lifecycle", "BOUNDED_ES",
     {"index": "forensic-eventlog",
      "query": "(21 OR 22 OR 25) AND \"TerminalServices-LocalSessionManager\"",
      "size": 12}),
    # RDP connection-manager events.
    ("rdp_connection_manager", "_tool_search_artifacts",
     {"query": "1149 OR \"TerminalServices-RemoteConnectionManager\"",
      "artifact_type": "eventlog", "limit": 12}),
    # RDP disconnect reasons — telemetric clue to attacker behavior.
    ("rdp_disconnect_reasons", "_tool_search_artifacts",
     {"query": "(24 OR 25 OR 39 OR 40) AND \"TerminalServices-LocalSessionManager\"", "artifact_type": "eventlog", "limit": 8}),
    # SMB share access (4140/4145) — lateral file access.
    ("smb_share_access", "_tool_search_artifacts",
     {"query": "5140 OR 5145", "artifact_type": "eventlog", "limit": 12}),

    # =========================================================================
    # G. FILE & REGISTRY AUDIT — object access trail when audit policy enabled.
    # =========================================================================

    # File audit access (4663) — requires SACL on the file/folder.
    ("file_audit_access_4663", "_tool_search_artifacts",
     {"query": "4663", "artifact_type": "eventlog", "limit": 12}),
    # Object handle request — early-stage access to audited objects.
    ("object_handle_request_4656", "_tool_search_artifacts",
     {"query": "4656", "artifact_type": "eventlog", "limit": 10}),
    # Object deletion — destructive operation on audited object.
    ("object_deleted_4660", "_tool_search_artifacts",
     {"query": "4660", "artifact_type": "eventlog", "limit": 10}),
    # Permissions changed (DACL modification).
    ("permissions_changed_4670", "_tool_search_artifacts",
     {"query": "4670", "artifact_type": "eventlog", "limit": 15}),
    # Registry-key audit (requires registry SACL).
    ("registry_audit_4657", "_tool_search_artifacts",
     {"query": "4657", "artifact_type": "eventlog", "limit": 10}),

    # =========================================================================
    # H. MFT / FILE-SYSTEM ACTIVITY — file-creation patterns commonly used
    # by attackers, ADS hiding, deleted-recoverable files.
    # =========================================================================

    # Executable / script file types — capture potential malicious payloads.
    ("mft_ps1_files", "BOUNDED_ES",
     {"index": "forensic-mft",
      "query": "\"*.ps1\" AND NOT \"Windows.old\" AND NOT WinSxS",
      "size": 15}),
    ("mft_bat_files", "BOUNDED_ES",
     {"index": "forensic-mft",
      "query": "\"*.bat\" AND NOT \"Windows.old\" AND NOT WinSxS",
      "size": 12}),
    ("mft_lnk_files", "BOUNDED_ES",
     {"index": "forensic-mft",
      "query": "\"*.lnk\" AND NOT \"Windows.old\" AND NOT WinSxS",
      "size": 12}),
    ("mft_sys_drivers", "BOUNDED_ES",
     {"index": "forensic-mft",
      "query": "\"*.sys\" AND (drivers OR System32) AND NOT \"Windows.old\" AND NOT WinSxS",
      "size": 12}),
    ("mft_msi_installers", "BOUNDED_ES",
     {"index": "forensic-mft",
      "query": "\"*.msi\" AND NOT \"Windows.old\" AND NOT WinSxS",
      "size": 10}),
    ("mft_archive_files", "BOUNDED_ES",
     {"index": "forensic-mft",
      "query": "(\"*.zip\" OR \"*.7z\" OR \"*.rar\" OR \"*.tar\" OR \"*.gz\") AND NOT \"Windows.old\"",
      "size": 10}),
    # Executable files dropped on disk — capture potential malicious binaries.
    ("mft_exe_files", "BOUNDED_ES",
     {"index": "forensic-mft",
      "query": "\"*.exe\" AND NOT \"Windows.old\" AND NOT WinSxS",
      "size": 15}),
    # User-writable directories — where attacker drops payloads (generic, no usernames).
    ("mft_user_writable_dirs", "BOUNDED_ES",
     {"index": "forensic-mft",
      "query": "Users AND (Downloads OR Documents OR Desktop OR AppData OR Temp) AND NOT Windows.old",
      "size": 15}),
    # Alternate Data Streams — common hiding technique.
    ("mft_alternate_data_streams", "BOUNDED_ES",
     {"index": "forensic-mft",
      "query": "\"Zone.Identifier\" OR \"alternate data stream\" OR (stream AND NOT \"::$DATA\")",
      "size": 10}),
    # USN journal recent file activity.
    ("usnjrnl_recent_changes", "_tool_search_artifacts",
     {"query": "\"*.ps1\" OR \"*.bat\" OR \"*.vbs\" OR \"*.exe\" OR \"*.zip\" OR reason:*DELETE* OR reason:*RENAME*",
      "artifact_type": "usnjrnl", "limit": 15}),

    # =========================================================================
    # I. PERSISTENCE & CONFIGURATION — registry-based persistence vectors.
    # =========================================================================

    # Master persistence anchor — Run/RunOnce/Tasks/Services/USBSTOR/BAM.
    ("reg_persistence_master", "_tool_analyze_registry",
     {"category": "all",
      "query": "Run OR RunOnce OR Startup OR Services OR Tasks OR ScheduledTask OR USBSTOR OR BAM OR UserAssist OR Firewall",
      "limit": 25}),
    # Image File Execution Options — DLL hijacking / debugger persistence.
    ("reg_image_file_execution_options", "_tool_analyze_registry",
     {"category": "all",
      "query": "Image File Execution Options OR IFEO OR Debugger",
      "limit": 12}),
    # AppInit_DLLs — classic DLL injection persistence.
    ("reg_appinit_dlls", "_tool_analyze_registry",
     {"category": "all",
      "query": "AppInit_DLLs OR AppCertDlls",
      "limit": 10}),
    # Winlogon helpers — logon-time persistence.
    ("reg_winlogon_helpers", "_tool_analyze_registry",
     {"category": "all",
      "query": "Winlogon AND (Userinit OR Shell OR Notify)",
      "limit": 12}),
    # Startup folders content (MFT).
    ("mft_startup_folders", "BOUNDED_ES",
     {"index": "forensic-mft",
      "query": "Startup AND (Programs OR Menu) AND NOT \"Windows.old\"",
      "size": 12}),
    # User context registry values — identity foundation.
    ("reg_user_context", "_tool_analyze_registry",
     {"category": "all",
      "query": "DefaultUserName OR LastLoggedOnUser OR RegisteredOwner OR InstallDate OR ProductName OR CurrentBuildNumber OR ComputerName",
      "limit": 12}),

    # =========================================================================
    # J. APPLICATION ERRORS, EXECUTION TRACES & DOMAIN INDICATORS.
    # Crashes + program-execution artifacts + generic threat-tooling lists.
    # All domain queries use universal indicator lists, no case-specific names.
    # =========================================================================

    # Application crashes — instability or attack-induced failure.
    ("app_crashes_1000", "_tool_search_artifacts",
     {"query": "1000", "artifact_type": "eventlog", "limit": 10}),
    # Application hangs.
    ("app_hangs_1002", "_tool_search_artifacts",
     {"query": "1002", "artifact_type": "eventlog", "limit": 6}),
    # Windows Error Reporting.
    ("wer_reports_1001", "_tool_search_artifacts",
     {"query": "1001 AND \"Windows Error Reporting\"",
      "artifact_type": "eventlog", "limit": 6}),

    # Program-execution traces — Prefetch / Shimcache / Amcache.
    ("prefetch_top", "_es_search",
     {"index": "forensic-prefetch", "size": 20}),
    ("shimcache_top", "_es_search",
     {"index": "forensic-shimcache", "size": 20}),
    ("amcache_top", "_es_search",
     {"index": "forensic-amcache", "size": 20}),
    # Recent files via LNK / JumpList.
    ("lnk_recent_files", "_es_search",
     {"index": "forensic-lnk", "size": 15}),
    ("jumplist_recent", "_es_search",
     {"index": "forensic-jumplist", "size": 12}),
    # Network usage per app via SRUM.
    ("srum_network_usage", "_es_search",
     {"index": "forensic-srum", "size": 15}),

    # Browser activity — raw history dump + suspicious-pattern search.
    ("browser_raw_history", "_es_search",
     {"index": "forensic-browser", "size": 15}),
    ("browser_downloads_searches", "_tool_search_artifacts",
     {"query": "download OR search OR hack OR ransomware OR malware OR phishing OR \"dark web\" OR keylogger OR crypter OR shellcode",
      "artifact_type": "browser", "limit": 15}),

    # Domain-category threat-tooling indicators — generic industry lists.
    # NO case-specific filenames; only widely-known threat tooling.
    ("app_communication", "BOUNDED_ES",
     {"index": "forensic-*",
      "query": "discord OR skype OR telegram OR whatsapp OR slack OR \"microsoft teams\" OR signal",
      "size": 15}),
    ("app_crypto_finance", "BOUNDED_ES",
     {"index": "forensic-*",
      "query": "electrum OR exodus OR atomic OR phantom OR \"trust wallet\" OR coinbase OR binance OR metamask OR \"ledger live\" OR trezor OR opensea OR uniswap",
      "size": 15}),
    ("app_remote_access", "BOUNDED_ES",
     {"index": "forensic-*",
      "query": "teamviewer OR anydesk OR vnc OR rustdesk OR splashtop OR \"chrome remote desktop\"",
      "size": 15}),
    ("app_antiforensic", "BOUNDED_ES",
     {"index": "forensic-*",
      "query": "ccleaner OR sdelete OR eraser OR \"privacy eraser\" OR wipedisk OR bcwipe OR \"secure delete\"",
      "size": 12}),
    ("app_archive_tools", "BOUNDED_ES",
     {"index": "forensic-*",
      "query": "\"7-zip\" OR 7zip OR winrar OR peazip OR winzip OR bandizip",
      "size": 12}),
    ("app_email_client", "BOUNDED_ES",
     {"index": "forensic-*",
      "query": "outlook OR thunderbird OR \".ost\" OR \".pst\" OR \"mbox\"",
      "size": 15}),
    # Universal threat-tooling indicators — well-known names only.
    ("suspicious_indicators_universal", "BOUNDED_ES",
     {"index": "forensic-*",
      "query": "mimikatz OR meterpreter OR cobaltstrike OR \"cobalt strike\" OR empire OR powersploit OR nishang OR sliver OR \"brute ratel\" OR powercat OR responder OR procdump OR psexec OR netcat OR \"nc.exe\"",
      "size": 12}),
]


def build_evidence(case_key, anchors=None):
    """Build evidence dump for one case using the v2 anchor catalog.
    Output schema identical to v1 so downstream scorer is unchanged.
    """
    anchors = anchors if anchors is not None else ANCHORS_V2
    case_name, case_id = CASES[case_key]
    es = BaseAnalyzer(es_url="http://localhost:9200", case_id=case_id)

    evidence_by_anchor = {}
    total = 0
    errors = 0
    SEC_EVENT_BUCKETS = (
        "account_management", "authentication", "privilege",
        "service_install", "audit_clear", "suspicious_events",
    )
    GENERIC_BUCKETS = (
        "results", "events", "activities", "records",
        "registry_entries", "browser_records",
        "run_keys", "runonce_keys", "services", "tasks",
        "usbstor", "user_assist", "bam", "firewall_rules",
        "startup", "downloads", "searches", "visits",
        "persistence_keys", "user_activity", "network", "other",
        "browser_history", "browser_downloads", "browser_searches",
        "domains", "urls",
    )

    def _flatten(result):
        if isinstance(result, list):
            return result
        if not isinstance(result, dict):
            return []
        out = []
        for k in GENERIC_BUCKETS:
            v = result.get(k)
            if isinstance(v, list) and v:
                out.extend(v)
        for k in SEC_EVENT_BUCKETS:
            v = result.get(k)
            if isinstance(v, list) and v:
                for ev in v:
                    if isinstance(ev, dict):
                        ev.setdefault("_bucket", k)
                out.extend(v)
        if out:
            return out
        return [result]

    def _ts_key(r):
        if not isinstance(r, dict):
            return "zzz"
        ts = str(r.get("timestamp", "")).strip()
        return ts if ts else "zzz"

    def _es_raw_search(index_pattern, size=30):
        """Plain _es_search wrapper used for prefetch/shimcache/amcache/lnk/jumplist."""
        body = {
            "size": size,
            "query": {
                "bool": {
                    "filter": [{"term": {"case_id.keyword": case_id}}],
                    # Phase-4 hallucination-investigation fix (root-cause B):
                    # without this, asc-sort on timestamp.keyword surfaces 100%
                    # empty-timestamp records for amcache/shimcache/jumplist/
                    # usnjrnl indices, starving downstream chains of
                    # program-execution anchors.
                    "must_not": [{"term": {"timestamp.keyword": ""}}]
                }
            },
            "sort": [{"timestamp.keyword": {
                "order": "asc", "unmapped_type": "keyword"}}],
        }
        try:
            r = requests.post(f"http://localhost:9200/{index_pattern}/_search",
                              json=body, timeout=15)
            if r.status_code != 200:
                return []
            return [h["_source"] for h in r.json().get("hits", {}).get("hits", [])]
        except Exception:
            return []

    # ---- typed Event-ID retrieval -------------------------------------------
    # Anchors named after a Windows Event ID used to reach it through a
    # FULL-TEXT search for the digits, which matches any record containing that
    # digit string anywhere - a timestamp fraction, a file size, another field.
    # Measured over the published pools, 47.6% of records returned under a
    # numeric anchor did not carry that event_id, while real events were missed
    # (Hunter app_hangs_1002 returned 6 unrelated records although the index
    # holds 69 genuine 1002 events). Because every record is labelled with its
    # `_anchor`, the model was handed an authoritative-looking wrong ID beside
    # the record - the sole cause of every unsupported Event ID claim measured
    # in the published chains.
    #
    # Numeric queries are therefore resolved against the typed `event_id` field.
    # Non-numeric text in the same query is preserved with its original
    # AND/OR semantics so anchor coverage is not narrowed.
    _NUM_TOKEN = re.compile(r'(?<![\w.])(\d{3,5})(?![\w.])')

    def _split_numeric_query(q):
        """Return (event_ids, leftover_text, joins_with_or)."""
        ids = _NUM_TOKEN.findall(q or "")
        leftover = _NUM_TOKEN.sub(" ", q or "")
        leftover = re.sub(r'\b(AND|OR|NOT)\b', ' ', leftover)
        leftover = leftover.replace('"', ' ').strip()
        leftover = re.sub(r'\s+', ' ', leftover)
        return ids, leftover, bool(re.search(r'\bOR\b', q or ""))

    def _es_search_eventid(event_ids, leftover, or_join, size):
        should = [{"terms": {"event_id": [int(i) for i in event_ids]}}]
        must = []
        if leftover:
            clause = {"query_string": {"query": leftover, "default_field": "*",
                                       "lenient": True}}
            (should if or_join else must).append(clause)
        body = {
            "size": size,
            "query": {"bool": {
                # The incident window and the empty-timestamp guard are the same ones the two
                # sibling helpers apply. Omitting them here left 57.7% of the KDFS pool outside the
                # declared window, with the most common date four days before it opens, because
                # without a range filter the size cap takes whatever Lucene returns first.
                "filter": [
                    {"term": {"case_id.keyword": case_id}},
                    {"range": {"timestamp.keyword": {
                        "gte": start_d,
                        "lte": f"{end_d}T23:59:59",
                    }}},
                ],
                "must": must,
                "must_not": [{"term": {"timestamp.keyword": ""}}],
                "should": should,
                "minimum_should_match": 1,
            }},
            "sort": [{"timestamp.keyword": {"order": "asc",
                                            "unmapped_type": "keyword"}}],
        }
        try:
            r = requests.post(f"http://localhost:9200/forensic-eventlog/_search",
                              json=body, timeout=15)
            if r.status_code != 200:
                return None
            return [h["_source"] for h in r.json().get("hits", {}).get("hits", [])]
        except Exception:
            return None

    start_d, end_d = INCIDENT_WINDOWS[case_key]

    for anchor_id, tool_name, kwargs in anchors:
        # Resolving Event IDs against the typed field removed the records that only matched the
        # digits by accident, which cut the pool by about a fifth and cost some tactic breadth.
        # About half the anchors sit at their cap, so the freed budget is returned to them - the
        # extra records are now correct ones. Anchors that already return everything they match are
        # unaffected by the scale.
        if ANCHOR_LIMIT_SCALE != 1.0:
            kwargs = dict(kwargs)
            for _k in ('limit', 'size'):
                if isinstance(kwargs.get(_k), int):
                    kwargs[_k] = int(round(kwargs[_k] * ANCHOR_LIMIT_SCALE))
        try:
            if (tool_name == "_tool_search_artifacts"
                    and kwargs.get("artifact_type") == "eventlog"
                    and _NUM_TOKEN.search(kwargs.get("query", ""))):
                ids, leftover, or_join = _split_numeric_query(kwargs.get("query", ""))
                records = _es_search_eventid(ids, leftover, or_join,
                                             kwargs.get("limit", 30))
                if records is None:          # fall back rather than lose an anchor
                    tool = getattr(es, tool_name)
                    records = _flatten(tool(**kwargs))
            elif tool_name == "BOUNDED_ES":
                records = _es_search_bounded(
                    case_id=case_id,
                    index_pattern=kwargs.get("index", "forensic-eventlog"),
                    query_string=kwargs.get("query", ""),
                    start_date=start_d, end_date=end_d,
                    size=kwargs.get("size", 30), sort_asc=True)
            elif tool_name == "_es_search":
                records = _es_raw_search(
                    index_pattern=kwargs.get("index", "forensic-prefetch"),
                    size=kwargs.get("size", 30))
            else:
                tool = getattr(es, tool_name)
                result = tool(**kwargs)
                records = _flatten(result)
            records = sorted(records, key=_ts_key)
            evidence_by_anchor[anchor_id] = [
                compress_record(r, anchor_id) for r in records]
            total += len(records)
            print(f"  {anchor_id:40s} -> {len(records):4d} records")
        except Exception as exc:
            errors += 1
            evidence_by_anchor[anchor_id] = []
            print(f"  {anchor_id:40s} -> ERROR: {exc}")

    out_dir = Path("benchmark_results/mode2_v2")
    out_dir.mkdir(parents=True, exist_ok=True)
    out_path = out_dir / f"evidence_{case_name}.json"
    payload = {
        "case_id": case_id,
        "case_name": case_name,
        "incident_window": {"start": start_d, "end": end_d},
        "anchors_used": [a[0] for a in anchors],
        "total_records": total,
        "errors": errors,
        "evidence_by_anchor": evidence_by_anchor,
    }
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(payload, f, indent=2, ensure_ascii=False, default=str)
    print(f"\n  TOTAL: {total} records across {len(anchors)} anchors "
          f"({errors} errors) -> {out_path}")
    return payload


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--case",
                        choices=list(CASES.keys()) + ["all"],
                        default="all",
                        help="Which case to build evidence for")
    args = parser.parse_args()

    if args.case == "all":
        for c in CASES:
            print(f"\n=== Building evidence for {c} (v2 catalog) ===")
            build_evidence(c)
    else:
        build_evidence(args.case)


if __name__ == "__main__":
    main()
