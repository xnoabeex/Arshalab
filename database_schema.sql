-- Database Schema for Forensic Artifacts
-- SQLite schema for storing parsed forensic data

-- Cases table
CREATE TABLE IF NOT EXISTS cases (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    case_id TEXT UNIQUE NOT NULL,
    image_path TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    status TEXT DEFAULT 'processing'
);

-- Prefetch files (program execution history)
CREATE TABLE IF NOT EXISTS prefetch (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    case_id TEXT NOT NULL,
    timestamp TEXT,
    executable_name TEXT,
    executable_path TEXT,
    prefetch_hash TEXT,
    source_file TEXT,
    run_count INTEGER DEFAULT 0,
    files_loaded TEXT,
    volume_info TEXT,
    FOREIGN KEY (case_id) REFERENCES cases(case_id)
);

-- Event logs (Windows events)
CREATE TABLE IF NOT EXISTS eventlog (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    case_id TEXT NOT NULL,
    timestamp TEXT,
    event_id INTEGER DEFAULT 0,
    provider TEXT,
    channel TEXT,
    level TEXT,
    severity TEXT,
    computer_name TEXT,
    user_id TEXT,
    message TEXT,
    record_id INTEGER DEFAULT 0,
    FOREIGN KEY (case_id) REFERENCES cases(case_id)
);

-- Registry entries
CREATE TABLE IF NOT EXISTS registry (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    case_id TEXT NOT NULL,
    timestamp TEXT,
    hive_type TEXT,
    key_path TEXT,
    value_name TEXT,
    value_data TEXT,
    value_type TEXT,
    category TEXT,
    description TEXT,
    FOREIGN KEY (case_id) REFERENCES cases(case_id)
);

-- Browser history
CREATE TABLE IF NOT EXISTS browser_history (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    case_id TEXT NOT NULL,
    timestamp TEXT,
    browser TEXT,
    url TEXT,
    domain TEXT,
    title TEXT,
    visit_count INTEGER DEFAULT 0,
    typed_count INTEGER DEFAULT 0,
    hidden INTEGER DEFAULT 0,
    FOREIGN KEY (case_id) REFERENCES cases(case_id)
);

-- LNK (shortcut) files
CREATE TABLE IF NOT EXISTS lnk_files (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    case_id TEXT NOT NULL,
    timestamp TEXT,
    lnk_name TEXT,
    target_path TEXT,
    target_name TEXT,
    target_extension TEXT,
    working_directory TEXT,
    arguments TEXT,
    target_created TEXT,
    target_modified TEXT,
    target_accessed TEXT,
    source_created TEXT,
    source_modified TEXT,
    source_accessed TEXT,
    file_size INTEGER DEFAULT 0,
    drive_type TEXT,
    volume_label TEXT,
    volume_serial TEXT,
    machine_id TEXT,
    FOREIGN KEY (case_id) REFERENCES cases(case_id)
);

-- SRUM (System Resource Usage Monitor)
CREATE TABLE IF NOT EXISTS srum (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    case_id TEXT NOT NULL,
    timestamp TEXT,
    record_type TEXT,
    app_id TEXT,
    app_name TEXT,
    user_sid TEXT,
    user_name TEXT,
    bytes_sent INTEGER DEFAULT 0,
    bytes_received INTEGER DEFAULT 0,
    interface_luid TEXT,
    profile_id INTEGER DEFAULT 0,
    background_bytes_read INTEGER DEFAULT 0,
    background_bytes_written INTEGER DEFAULT 0,
    foreground_bytes_read INTEGER DEFAULT 0,
    foreground_bytes_written INTEGER DEFAULT 0,
    background_cycle_time INTEGER DEFAULT 0,
    foreground_cycle_time INTEGER DEFAULT 0,
    face_time INTEGER DEFAULT 0,
    FOREIGN KEY (case_id) REFERENCES cases(case_id)
);

-- PowerShell command history
CREATE TABLE IF NOT EXISTS powershell (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    case_id TEXT NOT NULL,
    timestamp TEXT,
    command TEXT,
    line_number INTEGER,
    user TEXT,
    source_file TEXT,
    is_suspicious INTEGER DEFAULT 0,
    FOREIGN KEY (case_id) REFERENCES cases(case_id)
);

-- USN Journal (file system changes)
CREATE TABLE IF NOT EXISTS usnjrnl (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    case_id TEXT NOT NULL,
    timestamp TEXT,
    filename TEXT,
    extension TEXT,
    file_path TEXT,
    entry_number INTEGER DEFAULT 0,
    parent_entry INTEGER DEFAULT 0,
    usn INTEGER DEFAULT 0,
    operation TEXT,
    update_reasons TEXT,
    file_attributes TEXT,
    FOREIGN KEY (case_id) REFERENCES cases(case_id)
);

-- MFT (Master File Table - file system metadata)
CREATE TABLE IF NOT EXISTS mft (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    case_id TEXT NOT NULL,
    timestamp TEXT,
    entry_number INTEGER,
    sequence_number INTEGER,
    filename TEXT,
    extension TEXT,
    file_path TEXT,
    file_size INTEGER DEFAULT 0,
    is_directory INTEGER DEFAULT 0,
    is_deleted INTEGER DEFAULT 0,
    created TEXT,
    modified TEXT,
    accessed TEXT,
    entry_modified TEXT,
    attributes TEXT,
    is_ads INTEGER DEFAULT 0,
    zone_id TEXT,
    FOREIGN KEY (case_id) REFERENCES cases(case_id)
);

-- Jump Lists (recent files per application)
CREATE TABLE IF NOT EXISTS jumplist (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    case_id TEXT NOT NULL,
    timestamp TEXT,
    list_type TEXT,
    app_id TEXT,
    app_name TEXT,
    target_path TEXT,
    target_name TEXT,
    extension TEXT,
    arguments TEXT,
    target_created TEXT,
    target_modified TEXT,
    target_accessed TEXT,
    file_size INTEGER DEFAULT 0,
    drive_type TEXT,
    volume_label TEXT,
    volume_serial TEXT,
    machine_id TEXT,
    interaction_count INTEGER DEFAULT 0,
    FOREIGN KEY (case_id) REFERENCES cases(case_id)
);

-- Recycle Bin (deleted files metadata)
CREATE TABLE IF NOT EXISTS recyclebin (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    case_id TEXT NOT NULL,
    timestamp TEXT,
    filename TEXT,
    original_path TEXT,
    extension TEXT,
    file_size INTEGER DEFAULT 0,
    user_sid TEXT,
    recycle_file TEXT,
    FOREIGN KEY (case_id) REFERENCES cases(case_id)
);

-- Shimcache (program execution evidence)
CREATE TABLE IF NOT EXISTS shimcache (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    case_id TEXT NOT NULL,
    timestamp TEXT,
    path TEXT,
    filename TEXT,
    extension TEXT,
    cache_position INTEGER DEFAULT 0,
    executed INTEGER,
    controlset TEXT,
    FOREIGN KEY (case_id) REFERENCES cases(case_id)
);

-- Amcache (program execution with SHA1 hashes)
CREATE TABLE IF NOT EXISTS amcache (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    case_id TEXT NOT NULL,
    timestamp TEXT,
    record_type TEXT,
    path TEXT,
    filename TEXT,
    extension TEXT,
    sha1 TEXT,
    file_size INTEGER DEFAULT 0,
    publisher TEXT,
    product_name TEXT,
    product_version TEXT,
    binary_type TEXT,
    link_date TEXT,
    is_os_component INTEGER DEFAULT 0,
    FOREIGN KEY (case_id) REFERENCES cases(case_id)
);

-- Create indexes for faster queries
CREATE INDEX IF NOT EXISTS idx_prefetch_case ON prefetch(case_id);
CREATE INDEX IF NOT EXISTS idx_prefetch_executable ON prefetch(executable_name);
CREATE INDEX IF NOT EXISTS idx_prefetch_timestamp ON prefetch(timestamp);
CREATE INDEX IF NOT EXISTS idx_eventlog_case ON eventlog(case_id);
CREATE INDEX IF NOT EXISTS idx_eventlog_event_id ON eventlog(event_id);
CREATE INDEX IF NOT EXISTS idx_eventlog_timestamp ON eventlog(timestamp);
CREATE INDEX IF NOT EXISTS idx_registry_case ON registry(case_id);
CREATE INDEX IF NOT EXISTS idx_registry_timestamp ON registry(timestamp);
CREATE INDEX IF NOT EXISTS idx_browser_case ON browser_history(case_id);
CREATE INDEX IF NOT EXISTS idx_browser_domain ON browser_history(domain);
CREATE INDEX IF NOT EXISTS idx_lnk_case ON lnk_files(case_id);
CREATE INDEX IF NOT EXISTS idx_lnk_target ON lnk_files(target_path);
CREATE INDEX IF NOT EXISTS idx_srum_case ON srum(case_id);
CREATE INDEX IF NOT EXISTS idx_srum_app ON srum(app_name);
CREATE INDEX IF NOT EXISTS idx_powershell_case ON powershell(case_id);
CREATE INDEX IF NOT EXISTS idx_powershell_suspicious ON powershell(is_suspicious);
CREATE INDEX IF NOT EXISTS idx_usnjrnl_case ON usnjrnl(case_id);
CREATE INDEX IF NOT EXISTS idx_usnjrnl_operation ON usnjrnl(operation);
CREATE INDEX IF NOT EXISTS idx_mft_case ON mft(case_id);
CREATE INDEX IF NOT EXISTS idx_mft_filename ON mft(filename);
CREATE INDEX IF NOT EXISTS idx_mft_deleted ON mft(is_deleted);
CREATE INDEX IF NOT EXISTS idx_jumplist_case ON jumplist(case_id);
CREATE INDEX IF NOT EXISTS idx_jumplist_app ON jumplist(app_name);
CREATE INDEX IF NOT EXISTS idx_recyclebin_case ON recyclebin(case_id);
CREATE INDEX IF NOT EXISTS idx_shimcache_case ON shimcache(case_id);
CREATE INDEX IF NOT EXISTS idx_shimcache_path ON shimcache(path);
CREATE INDEX IF NOT EXISTS idx_amcache_case ON amcache(case_id);
CREATE INDEX IF NOT EXISTS idx_amcache_sha1 ON amcache(sha1);
