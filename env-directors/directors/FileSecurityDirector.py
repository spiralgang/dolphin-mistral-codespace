#!/usr/bin/env python3
"""
Director responsible for file security, poison pill detection, and malware scanning.
Provides comprehensive file validation, content analysis, and security quarantine.
"""

import os
import hashlib
import mimetypes
import subprocess
import shutil
import tempfile
import time
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Dict, List, Optional, Set, Any, Tuple
import json
import re


class SecurityLevel(Enum):
    """Security level enumeration"""
    INFO = "info"
    WARNING = "warning" 
    ERROR = "error"
    CRITICAL = "critical"


class ThreatType(Enum):
    """Types of threats that can be detected"""
    MALWARE = "malware"
    POISON_PILL = "poison_pill"
    SUSPICIOUS_EXTENSION = "suspicious_extension"
    OVERSIZED_FILE = "oversized_file"
    HIDDEN_CONTENT = "hidden_content"
    SCRIPT_INJECTION = "script_injection"
    EXECUTABLE_DISGUISE = "executable_disguise"


@dataclass
class ScanResult:
    """Result of a file security scan"""
    success: bool
    file_path: str
    threats: List[ThreatType] = field(default_factory=list)
    risk_score: int = 0  # 0-100
    message: str = ""
    details: Dict[str, Any] = field(default_factory=dict)
    timestamp: float = field(default_factory=time.time)


@dataclass
class SecurityContext:
    """Security context for operations"""
    operation: str
    target: str
    user: Optional[str] = None
    environment: str = "production"
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class DirectorResult:
    """Result from a director execution"""
    success: bool
    message: str
    level: SecurityLevel = SecurityLevel.INFO
    details: Dict[str, Any] = field(default_factory=dict)
    timestamp: float = field(default_factory=time.time)


class FileSecurityDirector:
    """
    Director responsible for file security and poison pill detection.
    Provides comprehensive file validation and malware detection capabilities.
    """
    
    def __init__(self):
        self.enabled = True
        self.scan_extensions = {'.exe', '.bat', '.sh', '.py', '.js', '.vbs', '.ps1'}
        self.quarantine_path = "/tmp/quarantine"
        self.max_file_size = 100 * 1024 * 1024  # 100MB
        self.virus_db_path = "/tmp/virus_signatures.db"
        self.last_run: Optional[float] = None
        
        # Initialize threat detection patterns
        self.poison_pill_patterns = [
            rb'#!/bin/sh.*rm\s+-rf\s+/',  # Malicious shell scripts
            rb'eval\s*\(\s*base64_decode',  # PHP code injection
            rb'<script[^>]*>.*</script>',   # Script injection
            rb'powershell.*-encodedcommand', # PowerShell attacks
            rb'cmd\.exe.*\/c.*del',         # Windows deletion commands
        ]
        
        # Known malware signatures (simplified for demo)
        self.malware_signatures = {
            "eicar": b'X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*',
            "test_virus": b'VIRUS-TEST-SIGNATURE-DO-NOT-REMOVE',
        }

    def get_name(self) -> str:
        return "file_security"

    def initialize(self, config: Dict[str, Any]) -> bool:
        """Initialize the director with configuration"""
        try:
            self.enabled = config.get("enabled", True)
            self.scan_extensions = set(config.get("scan_extensions", ['.exe', '.bat', '.sh', '.py']))
            self.quarantine_path = config.get("quarantine_path", "/tmp/quarantine")
            self.max_file_size = config.get("max_file_size_mb", 100) * 1024 * 1024
            
            # Create quarantine directory
            os.makedirs(self.quarantine_path, exist_ok=True)
            
            print(f"FileSecurityDirector initialized - Quarantine: {self.quarantine_path}")
            return True
        except Exception as e:
            print(f"Failed to initialize FileSecurityDirector: {e}")
            return False

    def is_enabled(self) -> bool:
        return self.enabled

    def is_applicable(self, context: SecurityContext) -> bool:
        """Check if this director applies to the given context"""
        return context.operation in [
            "file_upload", "file_write", "file_execute", "file_scan",
            "directory_scan", "malware_check"
        ]

    def execute(self, context: SecurityContext) -> DirectorResult:
        """Execute security check based on context"""
        self.last_run = time.time()
        
        try:
            if context.operation == "file_scan":
                return self._scan_file(context.target)
            elif context.operation == "directory_scan":
                return self._scan_directory(context.target)
            elif context.operation in ["file_upload", "file_write"]:
                return self._validate_file_operation(context)
            elif context.operation == "file_execute":
                return self._validate_execution(context.target)
            elif context.operation == "malware_check":
                return self._malware_scan(context.target)
            else:
                return DirectorResult(
                    success=True,
                    message="Operation not applicable to file security director",
                    level=SecurityLevel.INFO
                )
        except Exception as e:
            return DirectorResult(
                success=False,
                message=f"File security check failed: {e}",
                level=SecurityLevel.ERROR
            )

    def health_check(self) -> bool:
        """Check if director is healthy"""
        try:
            return (
                self.enabled and
                os.path.exists(self.quarantine_path) and
                os.access(self.quarantine_path, os.W_OK)
            )
        except Exception:
            return False

    def get_last_run_time(self) -> Optional[float]:
        return self.last_run

    def _scan_file(self, file_path: str) -> DirectorResult:
        """Perform comprehensive file security scan"""
        if not os.path.exists(file_path):
            return DirectorResult(
                success=False,
                message=f"File not found: {file_path}",
                level=SecurityLevel.ERROR
            )

        scan_result = self._perform_security_scan(file_path)
        
        if not scan_result.success:
            # Quarantine suspicious files
            if scan_result.threats and scan_result.risk_score > 50:
                quarantined_path = self._quarantine_file(file_path)
                scan_result.details["quarantined_to"] = quarantined_path

        level = self._determine_security_level(scan_result.risk_score, scan_result.threats)
        
        return DirectorResult(
            success=scan_result.success,
            message=scan_result.message,
            level=level,
            details=scan_result.details
        )

    def _scan_directory(self, dir_path: str) -> DirectorResult:
        """Scan entire directory for security threats"""
        if not os.path.isdir(dir_path):
            return DirectorResult(
                success=False,
                message=f"Directory not found: {dir_path}",
                level=SecurityLevel.ERROR
            )

        total_files = 0
        suspicious_files = 0
        quarantined_files = []
        threat_summary = {}

        try:
            for root, dirs, files in os.walk(dir_path):
                for file in files:
                    file_path = os.path.join(root, file)
                    total_files += 1
                    
                    scan_result = self._perform_security_scan(file_path)
                    
                    if scan_result.threats:
                        suspicious_files += 1
                        
                        # Count threats
                        for threat in scan_result.threats:
                            threat_summary[threat.value] = threat_summary.get(threat.value, 0) + 1
                        
                        # Quarantine if high risk
                        if scan_result.risk_score > 70:
                            quarantined_path = self._quarantine_file(file_path)
                            quarantined_files.append({
                                "original": file_path,
                                "quarantine": quarantined_path,
                                "risk_score": scan_result.risk_score
                            })

            success = suspicious_files == 0 or suspicious_files < total_files * 0.1  # Less than 10%
            level = SecurityLevel.INFO if success else SecurityLevel.WARNING
            
            if quarantined_files:
                level = SecurityLevel.CRITICAL

            return DirectorResult(
                success=success,
                message=f"Directory scan complete: {suspicious_files}/{total_files} files flagged",
                level=level,
                details={
                    "total_files": total_files,
                    "suspicious_files": suspicious_files,
                    "quarantined_files": quarantined_files,
                    "threat_summary": threat_summary
                }
            )

        except Exception as e:
            return DirectorResult(
                success=False,
                message=f"Directory scan failed: {e}",
                level=SecurityLevel.ERROR
            )

    def _validate_file_operation(self, context: SecurityContext) -> DirectorResult:
        """Validate file upload or write operation"""
        file_path = context.target
        metadata = context.metadata

        # Check file size
        if os.path.exists(file_path):
            file_size = os.path.getsize(file_path)
            if file_size > self.max_file_size:
                return DirectorResult(
                    success=False,
                    message=f"File too large: {file_size} bytes (max: {self.max_file_size})",
                    level=SecurityLevel.WARNING,
                    details={"file_size": file_size, "max_size": self.max_file_size}
                )

        # Check file extension
        _, ext = os.path.splitext(file_path)
        if ext.lower() in self.scan_extensions:
            scan_result = self._perform_security_scan(file_path)
            
            if scan_result.threats:
                return DirectorResult(
                    success=False,
                    message=f"Security threats detected in file: {scan_result.message}",
                    level=SecurityLevel.CRITICAL,
                    details=scan_result.details
                )

        return DirectorResult(
            success=True,
            message="File operation validated",
            level=SecurityLevel.INFO
        )

    def _validate_execution(self, file_path: str) -> DirectorResult:
        """Validate file execution request"""
        if not os.path.exists(file_path):
            return DirectorResult(
                success=False,
                message=f"Executable not found: {file_path}",
                level=SecurityLevel.ERROR
            )

        # Always scan executables before allowing execution
        scan_result = self._perform_security_scan(file_path)
        
        if scan_result.threats:
            # Quarantine malicious executables immediately
            quarantined_path = self._quarantine_file(file_path)
            
            return DirectorResult(
                success=False,
                message=f"Execution blocked - malicious file quarantined",
                level=SecurityLevel.CRITICAL,
                details={
                    "threats": [t.value for t in scan_result.threats],
                    "quarantined_to": quarantined_path,
                    "risk_score": scan_result.risk_score
                }
            )

        return DirectorResult(
            success=True,
            message="Executable validation passed",
            level=SecurityLevel.INFO,
            details={"risk_score": scan_result.risk_score}
        )

    def _malware_scan(self, file_path: str) -> DirectorResult:
        """Dedicated malware scanning"""
        scan_result = self._perform_security_scan(file_path)
        
        malware_threats = [t for t in scan_result.threats if t in [ThreatType.MALWARE, ThreatType.POISON_PILL]]
        
        if malware_threats:
            return DirectorResult(
                success=False,
                message=f"Malware detected: {[t.value for t in malware_threats]}",
                level=SecurityLevel.CRITICAL,
                details=scan_result.details
            )

        return DirectorResult(
            success=True,
            message="No malware detected",
            level=SecurityLevel.INFO,
            details={"risk_score": scan_result.risk_score}
        )

    def _perform_security_scan(self, file_path: str) -> ScanResult:
        """Perform comprehensive security scan on a file"""
        threats = []
        risk_score = 0
        details = {}

        try:
            # Basic file info
            file_stat = os.stat(file_path)
            file_size = file_stat.st_size
            details["file_size"] = file_size
            details["file_mode"] = oct(file_stat.st_mode)

            # MIME type detection
            mime_type, _ = mimetypes.guess_type(file_path)
            details["mime_type"] = mime_type

            # Read file content (limited for large files)
            content = b""
            try:
                with open(file_path, "rb") as f:
                    content = f.read(min(file_size, 1024 * 1024))  # Read max 1MB
            except Exception as e:
                details["read_error"] = str(e)
                risk_score += 10

            # Check file extension
            _, ext = os.path.splitext(file_path)
            if ext.lower() in {'.exe', '.bat', '.com', '.scr', '.vbs'}:
                threats.append(ThreatType.SUSPICIOUS_EXTENSION)
                risk_score += 20

            # Check for oversized files
            if file_size > self.max_file_size:
                threats.append(ThreatType.OVERSIZED_FILE)
                risk_score += 15

            # Check for hidden files or disguised extensions
            filename = os.path.basename(file_path)
            if filename.startswith('.') or filename.count('.') > 2:
                threats.append(ThreatType.HIDDEN_CONTENT)
                risk_score += 10

            # Poison pill detection
            poison_detected = self._detect_poison_pills(content)
            if poison_detected:
                threats.append(ThreatType.POISON_PILL)
                risk_score += 40
                details["poison_patterns"] = poison_detected

            # Malware signature detection
            malware_detected = self._detect_malware_signatures(content)
            if malware_detected:
                threats.append(ThreatType.MALWARE)
                risk_score += 50
                details["malware_signatures"] = malware_detected

            # Script injection detection
            script_threats = self._detect_script_injection(content)
            if script_threats:
                threats.append(ThreatType.SCRIPT_INJECTION)
                risk_score += 30
                details["script_threats"] = script_threats

            # Executable disguise detection
            if self._is_executable_disguised(file_path, content, mime_type):
                threats.append(ThreatType.EXECUTABLE_DISGUISE)
                risk_score += 25

            # Calculate final risk score
            risk_score = min(risk_score, 100)
            details["risk_score"] = risk_score

            success = len(threats) == 0 or risk_score < 30
            message = f"File scan {'passed' if success else 'failed'} - Risk score: {risk_score}"
            
            if threats:
                message += f" - Threats: {[t.value for t in threats]}"

            return ScanResult(
                success=success,
                file_path=file_path,
                threats=threats,
                risk_score=risk_score,
                message=message,
                details=details
            )

        except Exception as e:
            return ScanResult(
                success=False,
                file_path=file_path,
                threats=[],
                risk_score=100,
                message=f"Scan error: {e}",
                details={"error": str(e)}
            )

    def _detect_poison_pills(self, content: bytes) -> List[str]:
        """Detect poison pill patterns in file content"""
        detected = []
        
        for i, pattern in enumerate(self.poison_pill_patterns):
            if re.search(pattern, content, re.IGNORECASE):
                detected.append(f"poison_pattern_{i}")
        
        return detected

    def _detect_malware_signatures(self, content: bytes) -> List[str]:
        """Detect known malware signatures"""
        detected = []
        
        for name, signature in self.malware_signatures.items():
            if signature in content:
                detected.append(name)
        
        return detected

    def _detect_script_injection(self, content: bytes) -> List[str]:
        """Detect script injection attempts"""
        detected = []
        
        # Common script injection patterns
        patterns = [
            rb'<script[^>]*>.*javascript:',
            rb'eval\s*\(',
            rb'document\.write\s*\(',
            rb'innerHTML\s*=',
            rb'on\w+\s*=\s*["\'][^"\']*["\']'  # Event handlers
        ]
        
        for i, pattern in enumerate(patterns):
            if re.search(pattern, content, re.IGNORECASE | re.DOTALL):
                detected.append(f"script_injection_{i}")
        
        return detected

    def _is_executable_disguised(self, file_path: str, content: bytes, mime_type: Optional[str]) -> bool:
        """Check if file is an executable disguised as another file type"""
        _, ext = os.path.splitext(file_path)
        
        # Check for PE header (Windows executables)
        if content.startswith(b'MZ') and ext.lower() not in {'.exe', '.dll', '.sys'}:
            return True
        
        # Check for ELF header (Linux executables)
        if content.startswith(b'\x7fELF') and ext.lower() not in {'.bin', '.so', ''}:
            return True
        
        # Check for shell script in non-script file
        if content.startswith(b'#!/') and ext.lower() not in {'.sh', '.py', '.pl', '.rb'}:
            return True
        
        return False

    def _quarantine_file(self, file_path: str) -> str:
        """Move suspicious file to quarantine"""
        try:
            filename = os.path.basename(file_path)
            timestamp = int(time.time())
            quarantine_filename = f"{timestamp}_{filename}.quarantined"
            quarantine_full_path = os.path.join(self.quarantine_path, quarantine_filename)
            
            shutil.move(file_path, quarantine_full_path)
            
            # Create metadata file
            metadata = {
                "original_path": file_path,
                "quarantine_time": timestamp,
                "reason": "Security threat detected"
            }
            
            with open(f"{quarantine_full_path}.meta", 'w') as f:
                json.dump(metadata, f, indent=2)
            
            print(f"File quarantined: {file_path} -> {quarantine_full_path}")
            return quarantine_full_path
            
        except Exception as e:
            print(f"Failed to quarantine file {file_path}: {e}")
            return file_path

    def _determine_security_level(self, risk_score: int, threats: List[ThreatType]) -> SecurityLevel:
        """Determine security level based on risk score and threats"""
        if ThreatType.MALWARE in threats or ThreatType.POISON_PILL in threats:
            return SecurityLevel.CRITICAL
        elif risk_score >= 70:
            return SecurityLevel.ERROR
        elif risk_score >= 40 or threats:
            return SecurityLevel.WARNING
        else:
            return SecurityLevel.INFO

    def get_stats(self) -> Dict[str, Any]:
        """Get current statistics"""
        quarantine_files = []
        if os.path.exists(self.quarantine_path):
            quarantine_files = [f for f in os.listdir(self.quarantine_path) 
                              if f.endswith('.quarantined')]
        
        return {
            "enabled": self.enabled,
            "quarantine_path": self.quarantine_path,
            "quarantined_files": len(quarantine_files),
            "max_file_size": self.max_file_size,
            "scan_extensions": list(self.scan_extensions),
            "last_run": self.last_run
        }


# Example usage and integration
if __name__ == "__main__":
    director = FileSecurityDirector()
    director.initialize({
        "enabled": True,
        "scan_extensions": [".py", ".sh", ".exe"],
        "quarantine_path": "/tmp/test_quarantine",
        "max_file_size_mb": 10
    })
    
    # Test with current file
    context = SecurityContext(
        operation="file_scan",
        target=__file__
    )
    
    result = director.execute(context)
    print(f"Scan result: {result.success}")
    print(f"Message: {result.message}")
    print(f"Level: {result.level}")
    print(f"Details: {result.details}")