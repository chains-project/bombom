#!/usr/bin/env python3
"""
Debian System Binary Integrity Checker

Also works on Ubuntu.

Checks all binaries in /bin, /usr/bin, /sbin, /usr/sbin for:
1. Not being symbolic links
2. Belonging to a dpkg package
3. Matching package checksums

To check for integrity of all files.
"""

import os
import subprocess
import hashlib
from pathlib import Path
from typing import Dict, List, Set, Tuple


class IntegrityChecker:
    def __init__(self):
        self.directories = ['/bin', '/usr/bin', '/sbin', '/usr/sbin']
        self.violations = {
            'symlinks': [],
            'not_in_package': [],
            'checksum_mismatch': []
        }
    
    def get_all_binaries(self) -> List[Path]:
        """Get all files from target directories."""
        binaries = []
        # print("Scanning directories for binaries...")
        for directory in self.directories:
            dir_path = Path(directory)
            if dir_path.is_symlink():
                print(f"Warning: {directory} is a symbolic link, skipping")
                continue
            if not dir_path.exists():
                print(f"Warning: {directory} does not exist")
                continue
            
            try:
                for item in dir_path.iterdir():
                    if item.is_file() and not item.is_symlink():  # Limit to 10k files for performance
                        binaries.append(item)
                    if  item.is_symlink():
                        binaries.append(self.follow_symlink_recursive(item))
                    # if len(binaries) > 400:
                    #     break
            except PermissionError:
                print(f"Warning: Permission denied accessing {directory}")
        
        return binaries
    
    def follow_symlink_recursive(self, path: Path) -> Path:
        """Follow symbolic links recursively to find the final target."""
        seen = set()
        current = path
        while current.is_symlink():
            if current in seen:
                print(f"Warning: Detected symlink loop at {current}")
                return current  # Return the symlink itself if loop detected
            seen.add(current)
            try:
                current = current.resolve(strict=True)
            except FileNotFoundError:
                print(f"Warning: Symlink {current} points to non-existent file")
                return current  # Return the symlink itself if target doesn't exist
        return current
    def check_symlink(self, binary: Path) -> bool:
        """Check if binary is a symbolic link."""
        # return os.path.islink(str(binary))
        return binary.is_symlink()
    
    def get_package_for_file(self, binary: Path) -> str | None:
        """Get the package that owns this file using dpkg -S."""
        try:
            result = subprocess.run(
                ['dpkg', '-S', str(binary)],
                capture_output=True,
                text=True,
                timeout=5
            )
            
            if result.returncode == 0:
                # Output format: "package: /path/to/file"
                output = result.stdout.strip()
                if ':' in output:
                    package = output.split(':')[0]
                    return package
            
            return None
        except (subprocess.TimeoutExpired, FileNotFoundError):
            return None
    
    def get_package_checksum(self, package: str, filepath: Path) -> str | None:
        """Get the expected checksum from package md5sums."""
        md5sums_path = Path(f'/var/lib/dpkg/info/{package}.md5sums')
        
        print(f"Checking package '{package}' for file '{filepath}'")
        if not md5sums_path.exists():
            # Try with :arch suffix
            try:
                result = subprocess.run(
                    ['dpkg', '-l', package],
                    capture_output=True,
                    text=True,
                    timeout=5
                )
                # Package might have architecture suffix
                for arch in ['amd64', 'i386', 'all']:
                    alt_path = Path(f'/var/lib/dpkg/info/{package}:{arch}.md5sums')
                    if alt_path.exists():
                        md5sums_path = alt_path
                        break
            except:
                pass
        
        if not md5sums_path.exists():
            return None
        
        try:
            with open(md5sums_path, 'r') as f:
                # Format: "checksum  path/to/file"
                # Path in md5sums is relative (without leading /)
                relative_path = str(filepath).lstrip('/')
                
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    
                    parts = line.split(None, 1)
                    if len(parts) == 2:
                        checksum, path = parts
                        if path == relative_path:
                            return checksum
            
            return None
        except (PermissionError, IOError):
            return None
    
    def calculate_md5(self, filepath: Path) -> str | None:
        """Calculate MD5 checksum of a file."""
        try:
            md5_hash = hashlib.md5()
            with open(filepath, 'rb') as f:
                for chunk in iter(lambda: f.read(4096), b''):
                    md5_hash.update(chunk)
            return md5_hash.hexdigest()
        except (PermissionError, IOError):
            return None
    
    def check_hardlinks_copies(self, binary: Path) -> bool:
        """Check if binary is a hard link to another file.
        by checkinh in self.directories.
        """
        try:
            stat_info = binary.stat()
            # # A file is a hard link if its link count is greater than 1
            # if stat_info.st_nlink <= 1:
            #     return []
            
            # Get the inode of the current binary
            binary_inode = stat_info.st_ino
            
            hardlinks = []
            # Search for other files with the same inode in the directories
            for directory in self.directories:
                dir_path = Path(directory)
                if not dir_path.exists():
                    continue
                # print(f"Checking for hardlinks in {directory}..."   )
                try:
                    for item in dir_path.iterdir():
                        if item.is_file() and str(item) != str(binary):
                            try:
                                if item.stat().st_ino == binary_inode:
                                    # Verify it's actually the same file by comparing checksums
                                    item_checksum = self.calculate_md5(item)
                                    binary_checksum = self.calculate_md5(binary)
                                    if item_checksum and binary_checksum and item_checksum == binary_checksum:
                                        hardlinks.append(item)
                            except (PermissionError, OSError):
                                continue
                except PermissionError:
                    continue
            
            return hardlinks
        except (PermissionError, OSError):
            return []
        
    def check_binary(self, binary: Path):
        """Perform all checks on a single binary."""
        print(f"Checking: {binary}")
        # Check 1: Symbolic link
        if self.check_symlink(binary):
            # print(f"Symbolic link found: {binary}")
            self.violations['symlinks'].append(str(binary))
            return  # Don't check further if it's a symlink
                
        # Check 2: In a package
        package = self.get_package_for_file(binary)
        # print(f"File: {binary}, Package: {package}")
        not_in_package = False
        if package is None:
            not_in_package = True
            # print(f"File {binary} not found in any package, checking for hardlinks...")
            # Check if this is a hardlink
            alternatives = self.check_hardlinks_copies(binary)
            # print(f"Found {len(alternatives)} hardlink(s) for {binary}")
            if alternatives:
                # Check if any hardlink is in a package
                for alternative in alternatives:
                    print(f"Found hardlink: {binary} <-> {alternative}")
                    alternative_package = self.get_package_for_file(alternative)
                    if alternative_package is not None:
                        # Found a hardlink that's in a package, use that package
                        package = alternative_package
                        not_in_package = False
                        break
        
        actual_checksum = self.calculate_md5(binary)
        if actual_checksum is None:
            # Could not read file
            return

        if not_in_package:
            self.violations['not_in_package'].append(str(binary))
            return  # Can't check checksum without package
        
        
        # Check: Checksum match
        expected_checksum = self.get_package_checksum(package, binary)
        if expected_checksum is None:
            # No checksum available, skip this check
            return
        
        
        if expected_checksum != actual_checksum:
            self.violations['checksum_mismatch'].append({
                'file': str(binary),
                'package': package,
                'expected': expected_checksum,
                'actual': actual_checksum
            })
    
    def run_check(self):
        """Run integrity check on all binaries."""
        print("Debian System Binary Integrity Check")
        print("=" * 50)
        print()
        
        binaries = self.get_all_binaries()
        print(f"Found {len(binaries)} files to check")
        print()
        
        for i, binary in enumerate(binaries, 1):
            if i % 100 == 0:
                print(f"Progress: {i}/{len(binaries)}")
            
            self.check_binary(binary)
        
        print(f"\nCompleted checking {len(binaries)} files")
        print()
    
    def print_report(self):
        """Print the final violation report."""
        print("=" * 50)
        print("INTEGRITY CHECK REPORT")
        print("=" * 50)
        print()
        
        # Symbolic links
        if self.violations['symlinks']:
            print(f"[FYI] Symbolic Links Found: {len(self.violations['symlinks'])}")
            print()
        else:
            print("[✓] No symbolic links found")
            print()
        
        # Not in package
        if self.violations['not_in_package']:
            print(f"[!] Files Not in Any Package: {len(self.violations['not_in_package'])}")
            for file in sorted(self.violations['not_in_package']):
                print(f"    - {file}")
            print()
        else:
            print("[✓] All files belong to packages")
            print()
        
        # Checksum mismatches
        if self.violations['checksum_mismatch']:
            print(f"[!] Checksum Mismatches: {len(self.violations['checksum_mismatch'])}")
            for item in self.violations['checksum_mismatch']:
                print(f"    - {item['file']}")
                print(f"      Package: {item['package']}")
                print(f"      Expected: {item['expected']}")
                print(f"      Actual:   {item['actual']}")
                print()
        else:
            print("[✓] All checksums match")
            print()
        
        # Summary
        total_violations = (
            len(self.violations['symlinks']) +
            len(self.violations['not_in_package']) +
            len(self.violations['checksum_mismatch'])
        )
        
        print("=" * 50)
        if total_violations == 0:
            print("RESULT: All checks passed! System integrity verified.")
        else:
            print(f"RESULT: {total_violations} violation(s) detected!")
        print("=" * 50)


def main():
    # Check if running as root
    if os.geteuid() != 0:
        print("Warning: Not running as root. Some files may not be accessible.")
        print()
    
    checker = IntegrityChecker()
    checker.run_check()
    checker.print_report()


if __name__ == '__main__':
    main()