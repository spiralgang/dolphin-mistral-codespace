#!/usr/bin/env python3
"""
FileSecurityDirector - File integrity and security monitoring

This director provides comprehensive file security monitoring including
integrity checks, malware detection patterns, suspicious file monitoring,
and file system security validation.
"""

import os
import hashlib
import time
import json
import stat
from pathlib import Path
from typing import Dict, List, Set, Tuple, Optional
from dataclasses import dataclass
from enum import Enum


class Status(Enum):
    PASS = "PASS"
    WARN = "WARN"
    FAIL = "FAIL"
    ERROR = "ERROR"


@dataclass
class DirectorResult:
    status: Status
    message: str
    details: Dict = None
    
    def __post_init__(self):
        if self.details is None:
            self.details = {}


class FileSecurityDirector:
    """File security monitoring and integrity validation"""
    
    def __init__(self):
        self.name = "FileSecurityDirector"
        self.hub = None
        self.critical_files: Set[str] = set()
        self.file_hashes: Dict[str, str] = {}
        self.monitored_directories: Set[str] = set()
        self.suspicious_extensions: Set[str] = {
            '.exe', '.scr', '.bat', '.cmd', '.com', '.pif',
            '.vbs', '.vbe', '.js', '.jse', '.jar', '.ps1'
        }
        self.malware_patterns: List[bytes] = []
        self.quarantine_dir: Optional[str] = None
        
    def get_name(self) -> str:
        return self.name
    
    def initialize(self, hub) -> None:
        """Initialize the director with hub reference"""
        self.hub = hub
        
        # Setup default critical files
        home_dir = os.path.expanduser("~")
        self.critical_files.update([
            "/etc/passwd",
            "/etc/shadow", 
            "/etc/hosts",
            "/etc/sudoers",
            os.path.join(home_dir, ".ssh/authorized_keys"),
            os.path.join(home_dir, ".bashrc"),
            os.path.join(home_dir, ".profile")
        ])
        
        # Setup monitored directories
        self.monitored_directories.update([
            "/tmp",
            "/var/tmp",
            home_dir,
            "/usr/local/bin"
        ])
        
        # Initialize quarantine directory
        self.quarantine_dir = hub.get_config("file_security.quarantine_dir") if hub else None
        if not self.quarantine_dir:
            self.quarantine_dir = os.path.join(home_dir, ".quarantine")
        
        if not os.path.exists(self.quarantine_dir):
            os.makedirs(self.quarantine_dir, mode=0o700, exist_ok=True)
        
        # Load malware patterns
        self._load_malware_patterns()
        
        # Initialize file hashes for critical files
        self._initialize_file_hashes()
        
        print(f"[{self.name}] Initialized with {len(self.critical_files)} critical files")
    
    def perform_security_check(self) -> DirectorResult:
        """Perform comprehensive file security check"""
        issues = []
        details = {}
        
        try:
            # Check critical file integrity
            integrity_issues = self._check_file_integrity()
            if integrity_issues:
                issues.extend(integrity_issues)
                details["integrity_issues"] = integrity_issues
            
            # Scan for suspicious files
            suspicious_files = self._scan_for_suspicious_files()
            if suspicious_files:
                issues.append(f"Found {len(suspicious_files)} suspicious files")
                details["suspicious_files"] = suspicious_files[:10]  # Limit output
            
            # Check for malware patterns
            malware_matches = self._scan_for_malware_patterns()
            if malware_matches:
                issues.append(f"Detected {len(malware_matches)} potential malware files")
                details["malware_matches"] = malware_matches[:5]
            
            # Check file permissions
            permission_issues = self._check_dangerous_permissions()
            if permission_issues:
                issues.extend(permission_issues)
                details["permission_issues"] = permission_issues[:10]
            
            # Check for hidden files in sensitive locations
            hidden_files = self._scan_for_hidden_files()
            if hidden_files:
                issues.append(f"Found {len(hidden_files)} suspicious hidden files")
                details["hidden_files"] = hidden_files[:10]
            
            details.update({
                "critical_files_checked": len(self.critical_files),
                "directories_monitored": len(self.monitored_directories),
                "file_hashes_tracked": len(self.file_hashes)
            })
            
            # Determine overall status
            if any("malware" in issue.lower() or "integrity" in issue.lower() for issue in issues):
                return DirectorResult(
                    Status.FAIL,
                    f"Critical file security threats detected: {'; '.join(issues[:3])}",
                    details
                )
            elif issues:
                return DirectorResult(
                    Status.WARN,
                    f"File security issues found: {'; '.join(issues[:3])}",
                    details
                )
            else:
                return DirectorResult(
                    Status.PASS,
                    "All file security checks passed",
                    details
                )
                
        except Exception as e:
            return DirectorResult(
                Status.ERROR,
                f"File security check failed: {str(e)}",
                {"exception": type(e).__name__}
            )
    
    def add_critical_file(self, file_path: str) -> None:
        """Add a file to critical files list"""
        self.critical_files.add(file_path)
        if os.path.exists(file_path):
            self.file_hashes[file_path] = self._calculate_file_hash(file_path)
    
    def remove_critical_file(self, file_path: str) -> None:
        """Remove a file from critical files list"""
        self.critical_files.discard(file_path)
        self.file_hashes.pop(file_path, None)
    
    def add_monitored_directory(self, dir_path: str) -> None:
        """Add a directory to monitor"""
        self.monitored_directories.add(dir_path)
    
    def quarantine_file(self, file_path: str) -> bool:
        """Move a suspicious file to quarantine"""
        try:
            if not os.path.exists(file_path):
                return False
            
            filename = os.path.basename(file_path)
            timestamp = int(time.time())
            quarantine_path = os.path.join(
                self.quarantine_dir, 
                f"{filename}.{timestamp}.quarantined"
            )
            
            # Move file to quarantine
            os.rename(file_path, quarantine_path)
            
            # Create metadata file
            metadata = {
                "original_path": file_path,
                "quarantined_at": timestamp,
                "reason": "Suspicious file detected by FileSecurityDirector"
            }
            
            metadata_path = quarantine_path + ".metadata"
            with open(metadata_path, 'w') as f:
                json.dump(metadata, f, indent=2)
            
            print(f"[{self.name}] Quarantined file: {file_path} -> {quarantine_path}")
            return True
            
        except Exception as e:
            print(f"[{self.name}] Failed to quarantine {file_path}: {e}")
            return False
    
    def _initialize_file_hashes(self) -> None:
        """Initialize hash database for critical files"""
        for file_path in self.critical_files:
            if os.path.exists(file_path):
                self.file_hashes[file_path] = self._calculate_file_hash(file_path)
    
    def _calculate_file_hash(self, file_path: str) -> str:
        """Calculate SHA256 hash of a file"""
        try:
            hash_sha256 = hashlib.sha256()
            with open(file_path, "rb") as f:
                for chunk in iter(lambda: f.read(4096), b""):
                    hash_sha256.update(chunk)
            return hash_sha256.hexdigest()
        except Exception as e:
            print(f"[{self.name}] Error calculating hash for {file_path}: {e}")
            return ""
    
    def _check_file_integrity(self) -> List[str]:
        """Check integrity of critical files"""
        issues = []
        
        for file_path in self.critical_files:
            if not os.path.exists(file_path):
                issues.append(f"Critical file missing: {file_path}")
                continue
            
            current_hash = self._calculate_file_hash(file_path)
            stored_hash = self.file_hashes.get(file_path)
            
            if stored_hash and current_hash != stored_hash:
                issues.append(f"File integrity violation: {file_path}")
                # Update hash for future checks
                self.file_hashes[file_path] = current_hash
            elif not stored_hash:
                # First time seeing this file
                self.file_hashes[file_path] = current_hash
        
        return issues
    
    def _scan_for_suspicious_files(self) -> List[str]:
        """Scan monitored directories for suspicious files"""
        suspicious_files = []
        
        for dir_path in self.monitored_directories:
            if not os.path.exists(dir_path):
                continue
                
            try:
                for root, dirs, files in os.walk(dir_path):
                    # Limit depth to prevent performance issues
                    if root.count(os.sep) - dir_path.count(os.sep) > 3:
                        continue
                    
                    for filename in files[:100]:  # Limit files per directory
                        file_path = os.path.join(root, filename)
                        
                        # Check for suspicious extensions
                        if any(filename.lower().endswith(ext) for ext in self.suspicious_extensions):
                            suspicious_files.append(f"{file_path} (suspicious extension)")
                        
                        # Check for suspicious naming patterns
                        if self._is_suspicious_filename(filename):
                            suspicious_files.append(f"{file_path} (suspicious name)")
                        
                        # Check file size (very large or very small)
                        try:
                            file_size = os.path.getsize(file_path)
                            if file_size > 100 * 1024 * 1024:  # > 100MB
                                suspicious_files.append(f"{file_path} (unusually large)")
                        except OSError:
                            pass
            
            except Exception as e:
                print(f"[{self.name}] Error scanning {dir_path}: {e}")
        
        return suspicious_files
    
    def _scan_for_malware_patterns(self) -> List[str]:
        """Scan files for known malware patterns"""
        matches = []
        
        if not self.malware_patterns:
            return matches
        
        for dir_path in self.monitored_directories:
            if not os.path.exists(dir_path):
                continue
            
            try:
                for root, dirs, files in os.walk(dir_path):
                    if root.count(os.sep) - dir_path.count(os.sep) > 2:  # Limit depth
                        continue
                    
                    for filename in files[:50]:  # Limit files
                        file_path = os.path.join(root, filename)
                        
                        try:
                            if self._file_contains_malware_pattern(file_path):
                                matches.append(file_path)
                        except Exception as e:
                            pass  # Skip files that can't be read
            
            except Exception as e:
                print(f"[{self.name}] Error scanning for malware in {dir_path}: {e}")
        
        return matches
    
    def _check_dangerous_permissions(self) -> List[str]:
        """Check for files with dangerous permissions"""
        issues = []
        
        for dir_path in self.monitored_directories:
            if not os.path.exists(dir_path):
                continue
            
            try:
                for root, dirs, files in os.walk(dir_path):
                    if root.count(os.sep) - dir_path.count(os.sep) > 2:
                        continue
                    
                    for filename in files[:100]:
                        file_path = os.path.join(root, filename)
                        
                        try:
                            file_stat = os.stat(file_path)
                            mode = file_stat.st_mode
                            
                            # Check for world-writable files
                            if mode & stat.S_IWOTH:
                                issues.append(f"World-writable file: {file_path}")
                            
                            # Check for executable files in temp directories
                            if (mode & stat.S_IXUSR) and ("/tmp" in dir_path or "/var/tmp" in dir_path):
                                issues.append(f"Executable in temp directory: {file_path}")
                        
                        except OSError:
                            pass  # Skip files we can't stat
            
            except Exception as e:
                print(f"[{self.name}] Error checking permissions in {dir_path}: {e}")
        
        return issues
    
    def _scan_for_hidden_files(self) -> List[str]:
        """Scan for suspicious hidden files"""
        hidden_files = []
        
        sensitive_dirs = ["/tmp", "/var/tmp", os.path.expanduser("~")]
        
        for dir_path in sensitive_dirs:
            if not os.path.exists(dir_path):
                continue
            
            try:
                for item in os.listdir(dir_path):
                    if item.startswith('.') and item not in ['.', '..', '.bashrc', '.profile', '.ssh']:
                        item_path = os.path.join(dir_path, item)
                        
                        # Check if it's a regular file (not directory)
                        if os.path.isfile(item_path):
                            # Check if it's recently created or modified
                            stat_info = os.stat(item_path)
                            current_time = time.time()
                            
                            if (current_time - stat_info.st_mtime) < 86400:  # Modified in last 24 hours
                                hidden_files.append(item_path)
            
            except Exception as e:
                print(f"[{self.name}] Error scanning hidden files in {dir_path}: {e}")
        
        return hidden_files
    
    def _is_suspicious_filename(self, filename: str) -> bool:
        """Check if filename matches suspicious patterns"""
        suspicious_patterns = [
            # Common malware naming patterns
            r'.*\.(exe|scr|bat|cmd)\..*',  # Double extensions
            r'.*[0-9]{8,}.*',              # Many consecutive digits
            r'.*\s+\.(exe|scr|bat)',       # Space before extension
            r'.*[^\w\-\.].*\.(exe|scr)',   # Non-alphanumeric chars
        ]
        
        import re
        return any(re.match(pattern, filename, re.IGNORECASE) for pattern in suspicious_patterns)
    
    def _file_contains_malware_pattern(self, file_path: str) -> bool:
        """Check if file contains known malware patterns"""
        try:
            file_size = os.path.getsize(file_path)
            if file_size > 10 * 1024 * 1024:  # Skip files larger than 10MB
                return False
            
            with open(file_path, 'rb') as f:
                content = f.read()
                
                for pattern in self.malware_patterns:
                    if pattern in content:
                        return True
            
            return False
            
        except Exception:
            return False
    
    def _load_malware_patterns(self) -> None:
        """Load known malware patterns"""
        # Simple example patterns - in production, use proper malware signatures
        self.malware_patterns = [
            b'cmd.exe /c',
            b'powershell -e',
            b'exec("',
            b'eval(base64_decode',
            b'system("rm -rf',
            b'wget http',
            b'curl -o /tmp'
        ]
    
    def startup(self) -> None:
        """Startup hook"""
        print(f"[{self.name}] Starting file security monitoring")
        self._initialize_file_hashes()
    
    def shutdown(self) -> None:
        """Shutdown hook"""
        print(f"[{self.name}] Shutting down file security monitoring")
        
        # Save current hashes for next startup
        hash_file = os.path.join(self.quarantine_dir, "file_hashes.json")
        try:
            with open(hash_file, 'w') as f:
                json.dump(self.file_hashes, f, indent=2)
        except Exception as e:
            print(f"[{self.name}] Error saving hashes: {e}")


# Integration helpers for the ToolHub system
class FileSecurityDirectorAdapter:
    """Adapter to integrate Python director with Kotlin ToolHub"""
    
    def __init__(self):
        self.director = FileSecurityDirector()
    
    def initialize(self, config: Dict) -> None:
        """Initialize with configuration dictionary"""
        # Simulate ToolHub interface
        class ConfigHub:
            def __init__(self, config_dict):
                self.config = config_dict
            
            def get_config(self, key):
                return self.config.get(key)
        
        hub = ConfigHub(config)
        self.director.initialize(hub)
    
    def get_name(self) -> str:
        return self.director.get_name()
    
    def perform_security_check(self) -> Dict:
        """Perform security check and return result as dictionary"""
        result = self.director.perform_security_check()
        return {
            "status": result.status.value,
            "message": result.message,
            "details": result.details
        }


if __name__ == "__main__":
    # Test the director
    director = FileSecurityDirector()
    director.initialize(None)
    result = director.perform_security_check()
    print(f"Security Check Result: {result.status.value}")
    print(f"Message: {result.message}")
    if result.details:
        print("Details:", json.dumps(result.details, indent=2))