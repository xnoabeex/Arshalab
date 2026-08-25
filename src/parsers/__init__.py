# src/parsers/__init__.py
"""
Forensic Artifact Parsers
=========================

Unified parser module for Windows forensic artifacts.
All parsers are in parsers.py and inherit from BaseParser.

Naming Convention: {Artifact}_{Tool}_Parser

To add a new parser:
1. Create a class in parsers.py inheriting BaseParser
2. Implement: name, description, index_name, fields, artifact_type, database_table,
   _parse_impl, _normalize_record
3. Add to PARSERS dict below
"""

from .base import BaseParser
from .parsers import (
    # Core parsers
    Prefetch_PECmd_Parser,
    EventLog_EvtxECmd_Parser,
    Registry_RECmd_Parser,
    Browser_SQLite_Parser,
    LNK_LECmd_Parser,
    # High-priority parsers
    MFT_MFTECmd_Parser,
    JumpList_JLECmd_Parser,
    RecycleBin_RBCmd_Parser,
    Shimcache_AppCompat_Parser,
    Amcache_Parser,
    # Enterprise-level parsers
    SRUM_SrumECmd_Parser,
    PowerShellHistory_Parser,
    UsnJrnl_MFTECmd_Parser,
    # Legacy aliases
    PrefetchParser,
    EventLogParser,
    RegistryParser,
    BrowserHistoryParser,
    LnkParser,
    MFTParser,
    JumpListParser,
    RecycleBinParser,
    ShimcacheParser,
    SRUMParser,
    PowerShellHistoryParser,
    UsnJrnlParser,
)

# Parser registry by artifact type
PARSERS = {
    # Core artifacts
    "prefetch": Prefetch_PECmd_Parser,
    "eventlog": EventLog_EvtxECmd_Parser,
    "registry": Registry_RECmd_Parser,
    "browser": Browser_SQLite_Parser,
    "lnk": LNK_LECmd_Parser,
    # High-priority artifacts
    "mft": MFT_MFTECmd_Parser,
    "jumplist": JumpList_JLECmd_Parser,
    "recyclebin": RecycleBin_RBCmd_Parser,
    "shimcache": Shimcache_AppCompat_Parser,
    "amcache": Amcache_Parser,
    # Enterprise-level artifacts
    "srum": SRUM_SrumECmd_Parser,
    "powershell": PowerShellHistory_Parser,
    "usnjrnl": UsnJrnl_MFTECmd_Parser,
}

__all__ = [
    # Base class
    "BaseParser",
    # Main parsers
    "Prefetch_PECmd_Parser",
    "EventLog_EvtxECmd_Parser",
    "Registry_RECmd_Parser",
    "Browser_SQLite_Parser",
    "LNK_LECmd_Parser",
    # New high-priority parsers
    "MFT_MFTECmd_Parser",
    "JumpList_JLECmd_Parser",
    "RecycleBin_RBCmd_Parser",
    "Shimcache_AppCompat_Parser",
    "Amcache_Parser",
    # Enterprise level parsers
    "SRUM_SrumECmd_Parser",
    "PowerShellHistory_Parser",
    "UsnJrnl_MFTECmd_Parser",
    # Legacy aliases
    "PrefetchParser",
    "EventLogParser",
    "RegistryParser",
    "BrowserHistoryParser",
    "LnkParser",
    "MFTParser",
    "JumpListParser",
    "RecycleBinParser",
    "ShimcacheParser",
    "SRUMParser",
    "PowerShellHistoryParser",
    "UsnJrnlParser",
    # Registry
    "PARSERS",
]
