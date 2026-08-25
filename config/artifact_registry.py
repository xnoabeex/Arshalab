# config/artifact_registry.py
"""
Artifact Registry - centralized registry of supported forensic artifacts.

Used for:
- Validating artifact types in LLM tools
- Dynamic artifact loading during analysis
- Extensibility for new artifact types
"""

import os
import yaml
from typing import Dict, Optional


def _get_russian_name(artifact_type: str) -> str:
    """Get Russian name for artifact type."""
    names = {
        "prefetch": "Prefetch (program execution history)",
        "eventlog": "Windows Event Logs",
        "registry": "Windows Registry",
        "browser": "Browser history",
        "lnk": "LNK shortcuts",
        "mft": "Master File Table ($MFT)",
        "jumplist": "Jump Lists (recent files)",
        "recyclebin": "Recycle Bin ($Recycle.Bin)",
        "shimcache": "Shimcache (program execution)",
        "amcache": "Amcache (program hashes)",
        "srum": "SRUM (resource usage)",
        "powershell": "PowerShell history",
        "usnjrnl": "USN Journal (file-system changes)"
    }
    return names.get(artifact_type, artifact_type)


def _build_registry() -> Dict[str, dict]:
    """Build artifact registry from YAML config."""
    config_path = os.path.join(os.path.dirname(__file__), "artifacts.yaml")

    with open(config_path, encoding='utf-8') as f:
        config = yaml.safe_load(f)

    registry = {}
    for artifact_type, art_config in config.get('artifacts', {}).items():
        registry[artifact_type] = {
            "index": f"forensic-{art_config.get('database_table', artifact_type)}",
            "description": art_config.get('description', ''),
            "description_ru": _get_russian_name(artifact_type),
            "capabilities": art_config.get('capabilities', []),
            "requires_image": True
        }

    return registry


# Global registry instance
ARTIFACT_REGISTRY: Dict[str, dict] = _build_registry()


def get_artifact_info(artifact_type: str) -> Optional[dict]:
    """Get info about an artifact type."""
    return ARTIFACT_REGISTRY.get(artifact_type)


def is_known_artifact(artifact_type: str) -> bool:
    """Check if artifact type is supported."""
    return artifact_type in ARTIFACT_REGISTRY


def get_index_name(artifact_type: str) -> Optional[str]:
    """Get ES index name for artifact type."""
    info = ARTIFACT_REGISTRY.get(artifact_type)
    return info["index"] if info else None


def list_artifact_types() -> list:
    """Get list of all supported artifact types."""
    return list(ARTIFACT_REGISTRY.keys())


def register_artifact(artifact_type: str, config: dict):
    """
    Register a new artifact type at runtime.

    Args:
        artifact_type: Unique identifier (e.g., "telegram")
        config: Configuration dict with keys:
            - index: ES index name
            - description: English description
            - description_ru: Russian description
            - capabilities: List of capabilities
            - requires_image: Whether disk image is needed
    """
    ARTIFACT_REGISTRY[artifact_type] = config
