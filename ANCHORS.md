# The 98 Case-Agnostic Retrieval Anchors

Autonomous attack-chain reconstruction runs in two stages. **Stage 1**
(`retrieve_evidence_v2.py`) issues a fixed catalog of **98 case-agnostic anchor
queries** against the case index to build a comprehensive evidence pool (about
1,000 records). **Stage 2** (`reconstruct_timeline.py`) gives that pool to a
language model, which synthesizes a chronologically ordered attack chain.

This document lists all 98 anchors. The exact query for each anchor (tool method
or bounded Elasticsearch query plus parameters) is defined in `ANCHORS_V2` in
`retrieve_evidence_v2.py`; the identifiers below are the keys of that list.

## Design principles

The catalog is **case-agnostic by construction** so that the same 98 anchors
transfer across cases without per-case tuning:

1. **No case-specific identifiers.** No anchor contains a file name, user name,
   IP address, hash, or domain string taken from any evaluation case.
2. **Documented primitives only.** Anchors rely on Microsoft-documented Windows
   Event IDs and channel names, and on industry-wide artifact families
   (Prefetch, Shimcache, Amcache, MFT, USN journal, SRUM, browser, LNK).
3. **Generic indicator lists.** Domain-category anchors use generic
   threat-tooling lists (for example remote-access or anti-forensic tool
   families) rather than instances observed in a specific case.
4. **Bounded scope.** Every anchor is bounded to the case and its incident
   window, and each record is compressed to its diagnostic fields to fit the
   reconstruction prompt budget.

## The ten DFIR domains (98 anchors)

| Domain | Anchors | Coverage |
|--------|:------:|----------|
| A. Identity & Access | 19 | Authentication and account lifecycle (logon types, failures, explicit credentials, account/group changes, Kerberos, NTLM) |
| B. Process & Execution | 16 | Process creation/termination, services, scheduled tasks, PowerShell logging, WMI persistence, AppLocker |
| C. Defense Status & Tampering | 10 | Defender actions, real-time protection, audit-policy changes, log clearing, firewall stop, time change |
| D. Network & Connectivity | 6 | Filtering-platform connections, firewall-rule changes, DHCP authentication |
| E. Removable Media & USB | 4 | USB attach detection across DriverFrameworks, kernel PnP, device install, SetupAPI |
| F. RDP & Lateral Movement | 4 | RDP session lifecycle, connection manager, disconnect reasons, SMB share access |
| G. File & Registry Audit | 5 | Object-access trail when audit policy is enabled |
| H. MFT / File-System Activity | 10 | File-creation patterns (scripts, drivers, installers, archives, executables, user-writable dirs, ADS, USN journal) |
| I. Persistence & Configuration | 6 | Registry persistence (Run/RunOnce, IFEO, AppInit_DLLs, Winlogon, startup folders, user context) |
| J. Application Errors, Execution Traces & Domain Indicators | 18 | App crashes/hangs, WER, Prefetch/Shimcache/Amcache, SRUM, browser, and generic threat-tooling indicator lists |
| **Total** | **98** | |

## Full anchor list


### A. IDENTITY & ACCESS
- `auth_logon_interactive_type2`
- `auth_logon_network_type3`
- `auth_logon_rdp_type10`
- `auth_logon_service_type5`
- `auth_logon_unlock_type7`
- `auth_logon_failures_4625`
- `auth_explicit_cred_4648`
- `auth_priv_assigned_4672`
- `auth_account_created_4720`
- `auth_account_enabled_4722`
- `auth_account_disabled_4725`
- `auth_account_deleted_4726`
- `auth_account_modified_4738`
- `auth_group_added_4732`
- `auth_account_lockout_4740`
- `auth_kerberos_tgt_4768`
- `auth_kerberos_service_4769`
- `auth_ntlm_4776`
- `auth_logoff`

### B. PROCESS & EXECUTION
- `proc_creation_4688`
- `proc_termination_4689`
- `svc_install_7045`
- `svc_crashed_7034`
- `svc_state_change`
- `svc_starttype_changed_7040`
- `tasks_created_4698`
- `tasks_deleted_4699`
- `tasks_lifecycle`
- `ps_scriptblock_4104`
- `ps_module_4103`
- `ps_errors_4100`
- `ps_engine_lifecycle`
- `wmi_subscription`
- `applocker_audited`
- `applocker_blocked`

### C. DEFENSE STATUS & TAMPERING
- `def_threat_detected_1116`
- `def_action_taken_1117`
- `def_action_failed_1118`
- `def_config_change_5007`
- `def_realtime_disabled`
- `def_engine_update`
- `audit_log_cleared_1102`
- `audit_policy_changed_4719`
- `fw_stopped_5025`
- `time_changed_4616`

### D. NETWORK & CONNECTIVITY
- `net_connections_5156`
- `fw_rule_added_4946`
- `fw_rule_modified_4947`
- `fw_rule_deleted_4948`
- `fw_setting_changed`
- `dhcp_auth_50036_50037`

### E. REMOVABLE MEDIA & USB
- `usb_attach_driverframeworks`
- `usb_kernel_pnp_install`
- `device_install_recognition`
- `device_setupapi_events`

### F. RDP & LATERAL MOVEMENT
- `rdp_session_lifecycle`
- `rdp_connection_manager`
- `rdp_disconnect_reasons`
- `smb_share_access`

### G. FILE & REGISTRY AUDIT
- `file_audit_access_4663`
- `object_handle_request_4656`
- `object_deleted_4660`
- `permissions_changed_4670`
- `registry_audit_4657`

### H. MFT / FILE-SYSTEM ACTIVITY
- `mft_ps1_files`
- `mft_bat_files`
- `mft_lnk_files`
- `mft_sys_drivers`
- `mft_msi_installers`
- `mft_archive_files`
- `mft_exe_files`
- `mft_user_writable_dirs`
- `mft_alternate_data_streams`
- `usnjrnl_recent_changes`

### I. PERSISTENCE & CONFIGURATION
- `reg_persistence_master`
- `reg_image_file_execution_options`
- `reg_appinit_dlls`
- `reg_winlogon_helpers`
- `mft_startup_folders`
- `reg_user_context`

### J. APPLICATION ERRORS, EXECUTION TRACES & DOMAIN INDICATORS.
- `app_crashes_1000`
- `app_hangs_1002`
- `wer_reports_1001`
- `prefetch_top`
- `shimcache_top`
- `amcache_top`
- `lnk_recent_files`
- `jumplist_recent`
- `srum_network_usage`
- `browser_raw_history`
- `browser_downloads_searches`
- `app_communication`
- `app_crypto_finance`
- `app_remote_access`
- `app_antiforensic`
- `app_archive_tools`
- `app_email_client`
- `suspicious_indicators_universal`
