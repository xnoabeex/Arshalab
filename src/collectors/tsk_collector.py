# src/collectors/tsk_collector.py
import subprocess
import os
import re

class TSKCollector:
    """
    Extracts files from disk image using The Sleuth Kit.
    Supports both disk images (E01, RAW) and logical folders (extracted from AD1).
    """

    def __init__(self, image_path: str):
        self.image_path = os.path.abspath(image_path)
        self.tsk_path = os.path.abspath("tools/sleuthkit/bin")
        self.partition_offset = None

        # Check if source is a folder (logical image)
        self.is_logical = os.path.isdir(image_path)

        if self.is_logical:
            print(f"  [TSK] Logical mode: {image_path}")
        else:
            # Find main partition only for disk images
            self._find_main_partition()

    def _get_image_args(self) -> str:
        """Returns TSK image arguments based on source type."""
        if self.is_logical:
            return f'-i logical "{self.image_path}"'
        else:
            return f'-o {self.partition_offset} "{self.image_path}"'
    
    def _run_command(self, cmd: str) -> str:
        """Executes command and returns output"""
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            shell=True,
            encoding='utf-8',
            errors='ignore'
        )
        return result.stdout
    
    def _find_main_partition(self):
        """Finds main NTFS partition"""
        mmls_exe = os.path.join(self.tsk_path, "mmls.exe")
        cmd = f'"{mmls_exe}" "{self.image_path}"'
        
        output = self._run_command(cmd)
        print(f"  mmls output: {len(output)} bytes")
        
        # Find largest NTFS partition
        best_offset = None
        best_size = 0
        
        for line in output.split('\n'):
            # Skip headers and meta lines
            if 'Meta' in line or '---' in line or 'Slot' in line or 'Unallocated' in line:
                continue
            
            # Format: 003:  000:001   0000104448   0124734354   0124629907   NTFS / exFAT (0x07)
            parts = line.split()
            
            if len(parts) >= 5:
                try:
                    offset = int(parts[2])
                    length = int(parts[4])
                    
                    # Skip small partitions (< 1GB)
                    size_gb = (length * 512) / (1024**3)
                    
                    if size_gb < 1:
                        print(f"  Skipping small partition: offset={offset}, size={size_gb:.1f} GB")
                        continue
                    
                    # Check if NTFS / Basic data (GPT labels NTFS as "Basic data partition")
                    if 'NTFS' in line or 'exFAT' in line or 'Basic data' in line:
                        if length > best_size:
                            best_size = length
                            best_offset = offset
                            print(f"  Found partition: offset={offset}, size={size_gb:.1f} GB")
                    elif length > best_size:
                        # Fallback: pick largest partition if type unknown
                        best_size = length
                        best_offset = offset
                        print(f"  Found partition (unknown type): offset={offset}, size={size_gb:.1f} GB")
                except (ValueError, IndexError):
                    continue
        
        if best_offset:
            self.partition_offset = best_offset
            print(f"  + Selected main partition at offset: {best_offset}")
        else:
            self.partition_offset = 0
            print(f"  ! Warning: No partition found, using offset 0")
    
    def _find_inode_by_path(self, path: str) -> str:
        """Finds inode of a directory by path"""
        fls_exe = os.path.join(self.tsk_path, "fls.exe")
        
        # Start from root
        current_inode = None
        path_parts = [p for p in path.strip('/').split('/') if p]
        
        for part in path_parts:
            if current_inode:
                cmd = f'"{fls_exe}" {self._get_image_args()} {current_inode}'
            else:
                cmd = f'"{fls_exe}" {self._get_image_args()}'
            
            output = self._run_command(cmd)
            
            # Find directory with matching name (case-insensitive)
            found = False
            for line in output.split('\n'):
                if 'd/d' in line and part.lower() in line.lower():
                    if ':' in line:
                        name = line.split(':', 1)[1].strip()
                        if name.lower() == part.lower():
                            # Match both formats: "d/d 1234-128-3:" (disk) and "d/d 62586263437312:" (logical)
                            match = re.search(r'd/d\s+(\S+):', line)
                            if match:
                                current_inode = match.group(1)
                                found = True
                                break
            
            if not found:
                return None
        
        return current_inode
    
    def _find_user_folders(self) -> list:
        """Finds all user profile folders in /Users/"""
        print("  Finding user folders...")
        
        user_folders = []
        
        try:
            # Find Users directory inode
            users_inode = self._find_inode_by_path("/Users")
            
            if not users_inode:
                print("  ! Users folder not found")
                return []
            
            print(f"  Users folder inode: {users_inode}")
            
            # List contents of Users folder
            fls_exe = os.path.join(self.tsk_path, "fls.exe")
            cmd = f'"{fls_exe}" {self._get_image_args()} {users_inode}'
            output = self._run_command(cmd)
            
            for line in output.split('\n'):
                if 'd/d' in line:  # Directory entry
                    if ':' in line:
                        folder_name = line.split(':', 1)[1].strip()
                        
                        # Skip system folders
                        skip_folders = ['Default', 'Default User', 'Public', 'All Users', 
                                      'desktop.ini', '.', '..', '$Recycle.Bin']
                        
                        if folder_name and folder_name not in skip_folders:
                            user_folders.append(folder_name)
                            print(f"    Found user: {folder_name}")
        
        except Exception as e:
            print(f"  ! Error finding users: {e}")
            import traceback
            traceback.print_exc()
        
        return user_folders
    
    def _search_files_in_directory(self, dir_inode: str, filename_pattern: str) -> list:
        """Searches for files in a specific directory by inode"""
        fls_exe = os.path.join(self.tsk_path, "fls.exe")

        # List directory contents
        cmd = f'"{fls_exe}" {self._get_image_args()} {dir_inode}'
        output = self._run_command(cmd)
        
        matches = []
        for line in output.split('\n'):
            # Match both active (r/r) and deleted (r/-) files
            if 'r/r' not in line and 'r/-' not in line:
                continue
            
            if ':' not in line:
                continue
            
            parts = line.split(':', 1)
            if len(parts) != 2:
                continue
            
            file_info = parts[0].strip()
            filename = parts[1].strip()
            
            # Check if filename matches pattern
            if filename_pattern == '*':
                matches.append((file_info, filename))
            elif filename_pattern.startswith('*.'):
                # Extension match
                ext = filename_pattern[2:]
                if filename.lower().endswith('.' + ext.lower()):
                    matches.append((file_info, filename))
            else:
                # Exact filename match
                if filename.lower() == filename_pattern.lower():
                    matches.append((file_info, filename))
        
        return matches
    
    def extract_files(self, patterns: list, output_dir: str, log_callback=None) -> list:
        """
        Extracts files matching patterns from disk image

        Supports wildcard * in paths:
        - /Windows/Prefetch/*.pf
        - /Users/*/AppData/Roaming/Microsoft/Windows/Recent/*.lnk
        - /Users/*/AppData/Local/*/*/History

        Special system files:
        - /$MFT - Master File Table (inode 0)
        - /$Recycle.Bin - Recycle Bin folder
        """
        log = log_callback if log_callback else print

        os.makedirs(output_dir, exist_ok=True)

        icat_exe = os.path.join(self.tsk_path, "icat.exe")

        # Find user folders once if needed
        user_folders = None
        needs_users = any('/Users/*/' in p for p in patterns)

        if needs_users:
            user_folders = self._find_user_folders()
            if not user_folders:
                log("  ! No user folders found")
                # Don't return empty - continue with non-user patterns
                user_folders = []

        extracted = []

        for pattern in patterns:
            log(f"  Searching for: {pattern}")

            # Special handling for $MFT (root system file, always inode 0)
            if pattern == '/$MFT' or pattern == '$MFT':
                log(f"    Extracting $MFT (inode 0)...")
                mft_file = self._extract_mft(icat_exe, output_dir, log)
                if mft_file:
                    extracted.append(mft_file)
                continue

            # Special handling for $Recycle.Bin
            if '/$Recycle.Bin' in pattern or '$Recycle.Bin' in pattern:
                log(f"    Extracting $Recycle.Bin files...")
                recycle_files = self._extract_recycle_bin(output_dir, icat_exe, log)
                extracted.extend(recycle_files)
                continue

            # Expand patterns with /Users/*/
            if '/Users/*/' in pattern and user_folders:
                for user in user_folders:
                    expanded_pattern = pattern.replace('/Users/*/', f'/Users/{user}/')
                    log(f"    Trying: {expanded_pattern}")
                    extracted.extend(self._extract_pattern(expanded_pattern, output_dir, icat_exe, log))
            elif '/Users/*/' in pattern and not user_folders:
                # Skip user patterns if no users found
                log(f"    ! Skipping (no users found): {pattern}")
            else:
                extracted.extend(self._extract_pattern(pattern, output_dir, icat_exe, log))

        return extracted

    def _extract_mft(self, icat_exe: str, output_dir: str, log=None) -> str:
        """Extract $MFT file (always inode 0 on NTFS)."""
        if log is None:
            log = print

        # $MFT not available in logical mode
        if self.is_logical:
            log(f"      ! $MFT not available in logical mode")
            return None

        output_path = os.path.join(output_dir, "$MFT")

        # $MFT is always inode 0 on NTFS
        cmd = f'"{icat_exe}" {self._get_image_args()} 0 > "{output_path}"'

        result = subprocess.run(cmd, shell=True, capture_output=True)

        if os.path.exists(output_path) and os.path.getsize(output_path) > 0:
            size_mb = os.path.getsize(output_path) / (1024 * 1024)
            log(f"      + Extracted: $MFT ({size_mb:.1f} MB)")
            return output_path

        log(f"      ! Failed to extract $MFT")
        return None

    def _extract_recycle_bin(self, output_dir: str, icat_exe: str, log=None) -> list:
        """Extract $I files from $Recycle.Bin (deleted file metadata)."""
        if log is None:
            log = print

        extracted = []

        # Find $Recycle.Bin in root directory
        fls_exe = os.path.join(self.tsk_path, "fls.exe")
        cmd = f'"{fls_exe}" {self._get_image_args()}'
        output = self._run_command(cmd)

        recycle_inode = None
        for line in output.split('\n'):
            if '$Recycle.Bin' in line and 'd/d' in line:
                match = re.search(r'd/d\s+(\S+):', line)
                if match:
                    recycle_inode = match.group(1)
                    break

        if not recycle_inode:
            log(f"      ! $Recycle.Bin not found")
            return []

        log(f"      Found $Recycle.Bin (inode: {recycle_inode})")

        # Search for $I files recursively (metadata files contain original path, deletion time)
        matches = self._search_recursive(recycle_inode, '$I*', max_depth=3)

        log(f"      Found {len(matches)} $I files")

        for file_info, filename in matches:
            # Only extract $I files (metadata), not $R files (actual content)
            if filename.startswith('$I'):
                inode_match = re.search(r'r/r\s+\*?\s*(\S+)', file_info)
                if inode_match:
                    inode = inode_match.group(1)
                    extracted_file = self._extract_file(icat_exe, inode, filename, output_dir, log)
                    if extracted_file:
                        extracted.append(extracted_file)

        return extracted
    
    def _extract_pattern(self, pattern: str, output_dir: str, icat_exe: str, log=None) -> list:
        """Extracts files matching a single pattern"""
        if log is None:
            log = print
        extracted = []

        try:
            # Split pattern into directory path and filename
            dir_path = os.path.dirname(pattern)
            filename_pattern = os.path.basename(pattern)

            # Count wildcards in directory path
            # Check both /*/  (middle) and /* (end of path)
            wildcard_count = dir_path.count('/*/')
            if dir_path.endswith('/*'):
                wildcard_count += 1

            if wildcard_count >= 2:
                # Multiple wildcards: /AppData/*/*/History
                # Search recursively from base path
                base_path = dir_path.split('/*/')[0]

                base_inode = self._find_inode_by_path(base_path)
                if not base_inode:
                    log(f"    ! Path not found: {base_path}")
                    return []

                log(f"    Searching recursively in: {base_path}")
                matches = self._search_recursive(base_inode, filename_pattern, max_depth=4)

            elif wildcard_count == 1:
                # Single wildcard: /path/*/subpath or /path/*
                if dir_path.endswith('/*'):
                    base_path = dir_path[:-2]  # Strip trailing /*
                else:
                    base_path = dir_path.split('/*/')[0]

                base_inode = self._find_inode_by_path(base_path)
                if not base_inode:
                    log(f"    ! Path not found: {base_path}")
                    return []

                matches = self._search_recursive(base_inode, filename_pattern, max_depth=3)

            else:
                # No wildcard in middle, only in filename
                dir_inode = self._find_inode_by_path(dir_path)

                if not dir_inode:
                    log(f"    ! Path not found: {dir_path}")
                    return []

                matches = self._search_files_in_directory(dir_inode, filename_pattern)

            log(f"    Found {len(matches)} files")

            # Extract each match
            for file_info, filename in matches:
                # Extract inode: active (r/r 83740-128-3) or deleted (r/- * 83787)
                # Note: file_info has no colon (removed by split)
                inode_match = re.search(r'r/[r\-]\s+\*?\s*(\S+)', file_info)
                if inode_match:
                    inode = inode_match.group(1)
                    extracted_file = self._extract_file(icat_exe, inode, filename, output_dir, log)
                    if extracted_file:
                        extracted.append(extracted_file)

        except Exception as e:
            log(f"    ! Error extracting pattern: {e}")
            import traceback
            traceback.print_exc()

        return extracted
    
    def _search_recursive(self, start_inode: str, target_filename: str, max_depth: int = 5) -> list:
        """Recursively searches for a file in subdirectories"""
        matches = []
        visited = set()
        
        def search_dir(inode, depth):
            if depth > max_depth or inode in visited:
                return
            
            visited.add(inode)
            
            fls_exe = os.path.join(self.tsk_path, "fls.exe")
            cmd = f'"{fls_exe}" {self._get_image_args()} {inode}'
            output = self._run_command(cmd)
            
            for line in output.split('\n'):
                if ':' not in line:
                    continue
                
                parts = line.split(':', 1)
                if len(parts) != 2:
                    continue
                
                info = parts[0].strip()
                name = parts[1].strip()
                
                # Check if it's the target file (active r/r or deleted r/-)
                if 'r/r' in info or 'r/-' in info:
                    if target_filename == '*' or name.lower() == target_filename.lower():
                        matches.append((info, name))
                    elif target_filename.startswith('*.'):
                        ext = target_filename[2:]
                        if name.lower().endswith('.' + ext.lower()):
                            matches.append((info, name))
                
                # Recursively search subdirectories
                if 'd/d' in info:
                    match = re.search(r'd/d\s+(\S+)', info)
                    if match:
                        subdir_inode = match.group(1)
                        search_dir(subdir_inode, depth + 1)
        
        search_dir(start_inode, 0)
        return matches
    
    def _extract_file(self, icat_exe: str, inode: str, filename: str, output_dir: str, log=None) -> str:
        """Extracts file by inode"""
        if log is None:
            log = print

        # Create safe filename
        safe_name = os.path.basename(filename)
        safe_name = re.sub(r'[<>:"/\\|?*]', '_', safe_name)

        output_path = os.path.join(output_dir, safe_name)

        # Add counter if file exists
        if os.path.exists(output_path):
            base, ext = os.path.splitext(safe_name)
            counter = 1
            while os.path.exists(output_path):
                output_path = os.path.join(output_dir, f"{base}_{counter}{ext}")
                counter += 1

        cmd = f'"{icat_exe}" {self._get_image_args()} {inode} > "{output_path}"'

        result = subprocess.run(cmd, shell=True, capture_output=True)

        if os.path.exists(output_path) and os.path.getsize(output_path) > 0:
            log(f"      + Extracted: {safe_name}")
            return output_path

        return None