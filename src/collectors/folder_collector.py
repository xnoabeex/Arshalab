# src/collectors/folder_collector.py
"""
FolderCollector - Collects forensic artifacts from extracted folder structure.

Use this when you have:
- Files extracted from AD1 via FTK Imager
- Mounted disk image
- Any folder with Windows file structure

Usage:
    collector = FolderCollector("C:/extracted_files")
    files = collector.collect_files("/Windows/Prefetch/*.pf", "output/prefetch")
"""

import os
import shutil
import glob
import fnmatch
from pathlib import Path
from typing import List, Optional


class FolderCollector:
    """
    Collects forensic artifacts from a folder containing extracted files.
    Works with Windows folder structure (Users, Windows, etc.)
    """

    def __init__(self, source_folder: str):
        """
        Initialize collector with source folder path.

        Args:
            source_folder: Path to folder with extracted files (e.g., from AD1 export)
        """
        self.source_folder = os.path.abspath(source_folder)

        if not os.path.isdir(self.source_folder):
            raise ValueError(f"Source folder does not exist: {self.source_folder}")

        # Detect root - might be directly Windows or have drive letter subfolder
        self.root_path = self._detect_root()
        print(f"[FolderCollector] Source: {self.source_folder}")
        print(f"[FolderCollector] Detected root: {self.root_path}")

    def _detect_root(self) -> str:
        """
        Detect the actual root of Windows filesystem.
        Handles cases like:
        - Direct: source_folder/Windows/...
        - With drive: source_folder/C/Windows/...
        - FTK export: source_folder/[root]/Windows/...
        """
        # Check if Windows folder exists directly
        if os.path.isdir(os.path.join(self.source_folder, "Windows")):
            return self.source_folder

        # Check for drive letter subfolder (C, D, etc.)
        for item in os.listdir(self.source_folder):
            item_path = os.path.join(self.source_folder, item)
            if os.path.isdir(item_path):
                if os.path.isdir(os.path.join(item_path, "Windows")):
                    return item_path
                # Check one level deeper for [root] style exports
                for subitem in os.listdir(item_path):
                    subitem_path = os.path.join(item_path, subitem)
                    if os.path.isdir(subitem_path):
                        if os.path.isdir(os.path.join(subitem_path, "Windows")):
                            return subitem_path

        # Fallback to source folder
        print(f"[FolderCollector] Warning: Could not detect Windows root, using source folder")
        return self.source_folder

    def collect_files(self, artifact_path: str, output_dir: str) -> List[str]:
        """
        Collect files matching artifact path pattern.

        Args:
            artifact_path: Path pattern like "/Windows/Prefetch/*.pf" or "/Users/*/NTUSER.DAT"
            output_dir: Directory to copy collected files

        Returns:
            List of collected file paths
        """
        os.makedirs(output_dir, exist_ok=True)

        # Convert artifact path to local path
        # Remove leading slash and convert to OS path
        local_pattern = artifact_path.lstrip("/").replace("/", os.sep)
        full_pattern = os.path.join(self.root_path, local_pattern)

        print(f"  Searching for: {artifact_path}")
        print(f"    Pattern: {full_pattern}")

        # Handle wildcards in path
        if "*" in full_pattern:
            matching_files = self._glob_with_wildcards(full_pattern)
        else:
            # Single file
            if os.path.isfile(full_pattern):
                matching_files = [full_pattern]
            else:
                matching_files = []

        collected = []
        for src_file in matching_files:
            if os.path.isfile(src_file):
                filename = os.path.basename(src_file)
                # Handle duplicate filenames by adding parent folder
                if filename in [os.path.basename(f) for f in collected]:
                    parent = os.path.basename(os.path.dirname(src_file))
                    filename = f"{parent}_{filename}"

                dst_file = os.path.join(output_dir, filename)
                try:
                    shutil.copy2(src_file, dst_file)
                    collected.append(dst_file)
                    print(f"      + Collected: {filename}")
                except Exception as e:
                    print(f"      ! Error copying {filename}: {e}")

        print(f"    Found {len(collected)} files")
        return collected

    def _glob_with_wildcards(self, pattern: str) -> List[str]:
        """
        Handle glob patterns including ** and * in directory names.
        """
        # Use glob for simple patterns
        results = glob.glob(pattern, recursive=True)

        # Also handle /Users/*/... patterns manually
        if "/Users/*/" in pattern.replace("\\", "/") or "\\Users\\*\\" in pattern:
            results.extend(self._expand_user_wildcard(pattern))

        return list(set(results))  # Remove duplicates

    def _expand_user_wildcard(self, pattern: str) -> List[str]:
        """
        Expand /Users/*/ patterns to actual user folders.
        """
        results = []

        # Normalize pattern
        pattern = pattern.replace("\\", "/")

        # Find Users folder
        users_path = os.path.join(self.root_path, "Users")
        if not os.path.isdir(users_path):
            return results

        # Get pattern parts after Users/*/
        if "/Users/*/" in pattern:
            after_users = pattern.split("/Users/*/", 1)[1]
        else:
            return results

        # List user folders
        for user in os.listdir(users_path):
            user_path = os.path.join(users_path, user)
            if os.path.isdir(user_path) and user not in ["Default", "Default User", "Public", "All Users"]:
                user_pattern = os.path.join(user_path, after_users.replace("/", os.sep))
                matches = glob.glob(user_pattern)
                results.extend(matches)

        return results

    def list_users(self) -> List[str]:
        """List user folders found in the extracted files."""
        users_path = os.path.join(self.root_path, "Users")
        if not os.path.isdir(users_path):
            return []

        users = []
        for item in os.listdir(users_path):
            if item not in ["Default", "Default User", "Public", "All Users"]:
                item_path = os.path.join(users_path, item)
                if os.path.isdir(item_path):
                    users.append(item)
        return users

    def check_artifact_exists(self, artifact_path: str) -> bool:
        """Check if artifact path exists in the extracted files."""
        local_path = artifact_path.lstrip("/").replace("/", os.sep)
        full_path = os.path.join(self.root_path, local_path)

        if "*" in full_path:
            matches = glob.glob(full_path)
            return len(matches) > 0
        return os.path.exists(full_path)

    def get_stats(self) -> dict:
        """Get statistics about the extracted folder."""
        stats = {
            "source_folder": self.source_folder,
            "root_path": self.root_path,
            "users": self.list_users(),
            "has_windows": os.path.isdir(os.path.join(self.root_path, "Windows")),
            "has_users": os.path.isdir(os.path.join(self.root_path, "Users")),
            "artifacts_available": {}
        }

        # Check common artifacts
        artifact_checks = {
            "prefetch": "/Windows/Prefetch/*.pf",
            "eventlog": "/Windows/System32/winevt/Logs/*.evtx",
            "registry_system": "/Windows/System32/config/SYSTEM",
            "registry_software": "/Windows/System32/config/SOFTWARE",
            "mft": "/$MFT",
            "usnjrnl": "/$Extend/$UsnJrnl:$J",
        }

        for name, path in artifact_checks.items():
            stats["artifacts_available"][name] = self.check_artifact_exists(path)

        return stats
