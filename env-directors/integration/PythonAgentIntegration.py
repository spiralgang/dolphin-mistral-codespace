#!/usr/bin/env python3
"""
Sample Python integration for the environment director system.
Provides Python-based security services and integration with existing Python infrastructure.
"""

import asyncio
import json
import logging
import time
import threading
from abc import ABC, abstractmethod
from dataclasses import dataclass, field, asdict
from enum import Enum
from pathlib import Path
from typing import Dict, List, Optional, Any, Callable, Union
import hashlib
import socket
import subprocess
import sys
import os


class SecurityLevel(Enum):
    """Security level enumeration"""
    INFO = "info"
    WARNING = "warning"
    ERROR = "error"
    CRITICAL = "critical"


class IntegrationStatus(Enum):
    """Integration status enumeration"""
    INACTIVE = "inactive"
    INITIALIZING = "initializing"
    ACTIVE = "active"
    ERROR = "error"
    SHUTTING_DOWN = "shutting_down"


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


@dataclass
class PythonSecurityEvent:
    """Security event for Python integration"""
    event_type: str
    severity: SecurityLevel
    source: str
    target: str
    details: Dict[str, Any] = field(default_factory=dict)
    timestamp: float = field(default_factory=time.time)
    
    def to_dict(self) -> Dict[str, Any]:
        result = asdict(self)
        result['severity'] = self.severity.value
        return result


class PythonAgentIntegration:
    """
    Python agent integration for the environment director system.
    Provides Python-specific security services and seamless integration.
    """
    
    def __init__(self):
        self.enabled = False
        self.module_path = "env_directors.integration.python_agent"
        self.auto_import = True
        self.status = IntegrationStatus.INACTIVE
        self.event_handlers: Dict[str, List[Callable]] = {}
        self.security_hooks: Dict[str, Callable] = {}
        self.metrics: Dict[str, Any] = {}
        self.logger = self._setup_logger()
        self._lock = threading.RLock()
        self._shutdown_event = threading.Event()
        
        # Built-in security services
        self.file_monitor = None
        self.process_monitor = None
        self.network_monitor = None

    def initialize(self, config: Dict[str, Any]) -> bool:
        """Initialize the Python agent integration"""
        try:
            self.status = IntegrationStatus.INITIALIZING
            
            self.enabled = config.get("enabled", False)
            self.module_path = config.get("module_path", self.module_path)
            self.auto_import = config.get("auto_import", True)
            
            if not self.enabled:
                self.logger.info("PythonAgentIntegration disabled by configuration")
                self.status = IntegrationStatus.INACTIVE
                return True

            # Initialize built-in services
            self._initialize_services(config)
            
            # Set up security hooks
            self._setup_security_hooks()
            
            # Start monitoring threads
            self._start_monitoring()
            
            self.status = IntegrationStatus.ACTIVE
            self.logger.info("PythonAgentIntegration initialized successfully")
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to initialize PythonAgentIntegration: {e}")
            self.status = IntegrationStatus.ERROR
            return False

    def is_enabled(self) -> bool:
        return self.enabled

    def get_status(self) -> IntegrationStatus:
        return self.status

    def register_event_handler(self, event_type: str, handler: Callable[[PythonSecurityEvent], None]):
        """Register an event handler for specific event types"""
        with self._lock:
            if event_type not in self.event_handlers:
                self.event_handlers[event_type] = []
            self.event_handlers[event_type].append(handler)
        
        self.logger.info(f"Registered event handler for: {event_type}")

    def emit_security_event(self, event: PythonSecurityEvent) -> bool:
        """Emit a security event to registered handlers"""
        try:
            with self._lock:
                handlers = self.event_handlers.get(event.event_type, []) + \
                          self.event_handlers.get("*", [])  # Wildcard handlers
            
            for handler in handlers:
                try:
                    handler(event)
                except Exception as e:
                    self.logger.error(f"Event handler error: {e}")
            
            # Update metrics
            self.metrics["events_emitted"] = self.metrics.get("events_emitted", 0) + 1
            self.metrics["last_event_time"] = event.timestamp
            
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to emit security event: {e}")
            return False

    def execute_security_check(self, context: SecurityContext) -> DirectorResult:
        """Execute a security check using Python-based logic"""
        try:
            if context.operation == "python_scan":
                return self._python_code_scan(context.target)
            elif context.operation == "pip_security":
                return self._check_pip_packages(context)
            elif context.operation == "import_security":
                return self._check_import_security(context.target)
            elif context.operation == "process_monitor":
                return self._monitor_python_processes()
            elif context.operation == "network_check":
                return self._check_network_security()
            else:
                return DirectorResult(
                    success=True,
                    message="Operation not handled by Python integration",
                    level=SecurityLevel.INFO
                )
                
        except Exception as e:
            return DirectorResult(
                success=False,
                message=f"Python security check failed: {e}",
                level=SecurityLevel.ERROR
            )

    def install_import_hook(self) -> bool:
        """Install import hook to monitor module loading"""
        try:
            import sys
            
            class SecurityImportHook:
                def __init__(self, agent):
                    self.agent = agent
                    self.original_import = __builtins__['__import__']
                
                def __call__(self, name, globals=None, locals=None, fromlist=(), level=0):
                    # Check if module is on blacklist
                    if self.agent._is_module_blacklisted(name):
                        event = PythonSecurityEvent(
                            event_type="blocked_import",
                            severity=SecurityLevel.WARNING,
                            source="import_hook",
                            target=name,
                            details={"reason": "Module on security blacklist"}
                        )
                        self.agent.emit_security_event(event)
                        raise ImportError(f"Import of {name} blocked by security policy")
                    
                    # Log suspicious imports
                    if self.agent._is_module_suspicious(name):
                        event = PythonSecurityEvent(
                            event_type="suspicious_import",
                            severity=SecurityLevel.INFO,
                            source="import_hook",
                            target=name,
                            details={"caller": globals.get('__name__') if globals else 'unknown'}
                        )
                        self.agent.emit_security_event(event)
                    
                    return self.original_import(name, globals, locals, fromlist, level)
            
            __builtins__['__import__'] = SecurityImportHook(self)
            self.logger.info("Import security hook installed")
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to install import hook: {e}")
            return False

    def scan_python_environment(self) -> Dict[str, Any]:
        """Scan the Python environment for security issues"""
        scan_results = {
            "python_version": sys.version,
            "executable_path": sys.executable,
            "installed_packages": [],
            "security_issues": [],
            "recommendations": []
        }
        
        try:
            # Check Python version
            version_info = sys.version_info
            if version_info.major == 2:
                scan_results["security_issues"].append({
                    "type": "deprecated_python",
                    "severity": "critical",
                    "message": "Python 2 is deprecated and has security vulnerabilities"
                })
            elif version_info < (3, 8):
                scan_results["security_issues"].append({
                    "type": "old_python_version",
                    "severity": "warning", 
                    "message": f"Python {version_info.major}.{version_info.minor} has known security issues"
                })
            
            # Check installed packages
            try:
                import pkg_resources
                packages = []
                for dist in pkg_resources.working_set:
                    packages.append({
                        "name": dist.project_name,
                        "version": dist.version,
                        "location": dist.location
                    })
                scan_results["installed_packages"] = packages
                
                # Check for known vulnerable packages
                vulnerable_packages = self._get_vulnerable_packages()
                for package in packages:
                    if package["name"].lower() in vulnerable_packages:
                        scan_results["security_issues"].append({
                            "type": "vulnerable_package",
                            "severity": "warning",
                            "package": package["name"],
                            "version": package["version"],
                            "message": f"Package {package['name']} has known vulnerabilities"
                        })
                        
            except ImportError:
                scan_results["security_issues"].append({
                    "type": "missing_pkg_resources",
                    "severity": "info",
                    "message": "Cannot check installed packages - pkg_resources not available"
                })
            
            # Check sys.path for suspicious entries
            suspicious_paths = []
            for path in sys.path:
                if path and (
                    path.startswith('/tmp/') or 
                    path.startswith('/dev/shm/') or
                    '/..' in path
                ):
                    suspicious_paths.append(path)
            
            if suspicious_paths:
                scan_results["security_issues"].append({
                    "type": "suspicious_sys_path",
                    "severity": "warning",
                    "paths": suspicious_paths,
                    "message": "Suspicious entries in sys.path detected"
                })
            
            # Generate recommendations
            if len(scan_results["security_issues"]) == 0:
                scan_results["recommendations"].append("Python environment appears secure")
            else:
                scan_results["recommendations"].extend([
                    "Update Python to latest stable version",
                    "Regularly update packages using pip",
                    "Use virtual environments to isolate dependencies",
                    "Monitor package vulnerabilities with safety or similar tools"
                ])
                
        except Exception as e:
            scan_results["security_issues"].append({
                "type": "scan_error",
                "severity": "error",
                "message": f"Environment scan failed: {e}"
            })
        
        return scan_results

    def _initialize_services(self, config: Dict[str, Any]):
        """Initialize built-in security services"""
        # File monitoring service
        if config.get("file_monitoring", {}).get("enabled", True):
            self.file_monitor = PythonFileMonitor(self)
        
        # Process monitoring service
        if config.get("process_monitoring", {}).get("enabled", True):
            self.process_monitor = PythonProcessMonitor(self)
        
        # Network monitoring service
        if config.get("network_monitoring", {}).get("enabled", False):
            self.network_monitor = PythonNetworkMonitor(self)

    def _setup_security_hooks(self):
        """Set up various security hooks"""
        if self.auto_import:
            self.install_import_hook()

    def _start_monitoring(self):
        """Start background monitoring threads"""
        if self.file_monitor:
            threading.Thread(target=self.file_monitor.start, daemon=True).start()
        
        if self.process_monitor:
            threading.Thread(target=self.process_monitor.start, daemon=True).start()
            
        if self.network_monitor:
            threading.Thread(target=self.network_monitor.start, daemon=True).start()

    def _python_code_scan(self, file_path: str) -> DirectorResult:
        """Scan Python code file for security issues"""
        if not os.path.exists(file_path):
            return DirectorResult(
                success=False,
                message=f"File not found: {file_path}",
                level=SecurityLevel.ERROR
            )
        
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                content = f.read()
            
            issues = []
            risk_score = 0
            
            # Check for dangerous patterns
            dangerous_patterns = [
                (r'eval\s*\(', "eval() usage detected", 30),
                (r'exec\s*\(', "exec() usage detected", 30),
                (r'__import__\s*\(', "Dynamic import detected", 15),
                (r'subprocess\.call\s*\(', "Subprocess call detected", 20),
                (r'os\.system\s*\(', "os.system() usage detected", 40),
                (r'input\s*\(.*\)', "input() usage detected", 10),
                (r'pickle\.loads?\s*\(', "Pickle loading detected", 25),
            ]
            
            import re
            for pattern, message, score in dangerous_patterns:
                if re.search(pattern, content, re.IGNORECASE):
                    issues.append(message)
                    risk_score += score
            
            # Check imports
            try:
                import ast
                tree = ast.parse(content)
                for node in ast.walk(tree):
                    if isinstance(node, ast.Import):
                        for alias in node.names:
                            if self._is_module_suspicious(alias.name):
                                issues.append(f"Suspicious import: {alias.name}")
                                risk_score += 15
            except SyntaxError:
                issues.append("Python syntax error in file")
                risk_score += 50
            
            success = risk_score < 50
            level = SecurityLevel.INFO
            if risk_score >= 75:
                level = SecurityLevel.CRITICAL
            elif risk_score >= 50:
                level = SecurityLevel.ERROR
            elif risk_score >= 25:
                level = SecurityLevel.WARNING
            
            return DirectorResult(
                success=success,
                message=f"Python code scan {'passed' if success else 'failed'} - Risk score: {risk_score}",
                level=level,
                details={
                    "risk_score": risk_score,
                    "issues": issues,
                    "file_path": file_path
                }
            )
            
        except Exception as e:
            return DirectorResult(
                success=False,
                message=f"Python code scan failed: {e}",
                level=SecurityLevel.ERROR
            )

    def _check_pip_packages(self, context: SecurityContext) -> DirectorResult:
        """Check pip packages for security vulnerabilities"""
        try:
            result = subprocess.run([sys.executable, "-m", "pip", "list", "--format=json"], 
                                  capture_output=True, text=True, timeout=30)
            
            if result.returncode != 0:
                return DirectorResult(
                    success=False,
                    message="Failed to get pip package list",
                    level=SecurityLevel.ERROR
                )
            
            packages = json.loads(result.stdout)
            vulnerable_packages = self._get_vulnerable_packages()
            
            vulnerable_found = []
            for package in packages:
                if package["name"].lower() in vulnerable_packages:
                    vulnerable_found.append(package)
            
            success = len(vulnerable_found) == 0
            level = SecurityLevel.WARNING if vulnerable_found else SecurityLevel.INFO
            
            return DirectorResult(
                success=success,
                message=f"Pip security check: {len(vulnerable_found)} vulnerable packages found",
                level=level,
                details={
                    "total_packages": len(packages),
                    "vulnerable_packages": vulnerable_found
                }
            )
            
        except Exception as e:
            return DirectorResult(
                success=False,
                message=f"Pip security check failed: {e}",
                level=SecurityLevel.ERROR
            )

    def _check_import_security(self, module_name: str) -> DirectorResult:
        """Check if a module import is secure"""
        if self._is_module_blacklisted(module_name):
            return DirectorResult(
                success=False,
                message=f"Module {module_name} is blacklisted",
                level=SecurityLevel.CRITICAL
            )
        
        if self._is_module_suspicious(module_name):
            return DirectorResult(
                success=True,
                message=f"Module {module_name} flagged as suspicious",
                level=SecurityLevel.WARNING,
                details={"module": module_name, "reason": "Potentially dangerous functionality"}
            )
        
        return DirectorResult(
            success=True,
            message=f"Module {module_name} import approved",
            level=SecurityLevel.INFO
        )

    def _monitor_python_processes(self) -> DirectorResult:
        """Monitor running Python processes"""
        try:
            import psutil
            python_processes = []
            
            for proc in psutil.process_iter(['pid', 'name', 'cmdline', 'cpu_percent', 'memory_percent']):
                try:
                    if proc.info['name'] and 'python' in proc.info['name'].lower():
                        python_processes.append({
                            "pid": proc.info['pid'],
                            "name": proc.info['name'],
                            "cmdline": proc.info['cmdline'][:3] if proc.info['cmdline'] else [],
                            "cpu_percent": proc.info['cpu_percent'],
                            "memory_percent": proc.info['memory_percent']
                        })
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue
            
            # Check for suspicious patterns
            suspicious_processes = []
            for proc in python_processes:
                cmdline = ' '.join(proc['cmdline']) if proc['cmdline'] else ''
                if any(pattern in cmdline.lower() for pattern in ['eval(', 'exec(', '--hidden', 'temp']):
                    suspicious_processes.append(proc)
            
            level = SecurityLevel.WARNING if suspicious_processes else SecurityLevel.INFO
            
            return DirectorResult(
                success=True,
                message=f"Found {len(python_processes)} Python processes, {len(suspicious_processes)} suspicious",
                level=level,
                details={
                    "python_processes": len(python_processes),
                    "suspicious_processes": suspicious_processes
                }
            )
            
        except ImportError:
            return DirectorResult(
                success=False,
                message="psutil not available for process monitoring",
                level=SecurityLevel.ERROR
            )
        except Exception as e:
            return DirectorResult(
                success=False,
                message=f"Process monitoring failed: {e}",
                level=SecurityLevel.ERROR
            )

    def _check_network_security(self) -> DirectorResult:
        """Check network security for Python processes"""
        try:
            # Check for open sockets
            import socket
            hostname = socket.gethostname()
            local_ip = socket.gethostbyname(hostname)
            
            # Simple port scan of common Python ports
            python_ports = [8000, 8080, 5000, 8888, 3000, 8081]
            open_ports = []
            
            for port in python_ports:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(1)
                result = sock.connect_ex((local_ip, port))
                if result == 0:
                    open_ports.append(port)
                sock.close()
            
            level = SecurityLevel.WARNING if open_ports else SecurityLevel.INFO
            
            return DirectorResult(
                success=True,
                message=f"Network check: {len(open_ports)} Python-related ports open",
                level=level,
                details={
                    "hostname": hostname,
                    "local_ip": local_ip,
                    "open_ports": open_ports
                }
            )
            
        except Exception as e:
            return DirectorResult(
                success=False,
                message=f"Network security check failed: {e}",
                level=SecurityLevel.ERROR
            )

    def _is_module_blacklisted(self, module_name: str) -> bool:
        """Check if module is on the blacklist"""
        blacklisted_modules = {
            'ctypes', 'subprocess', 'os', 'importlib', 'sys'
        }
        return module_name.split('.')[0] in blacklisted_modules

    def _is_module_suspicious(self, module_name: str) -> bool:
        """Check if module is suspicious"""
        suspicious_modules = {
            'requests', 'urllib', 'socket', 'pickle', 'marshal', 
            'base64', 'codecs', 'tempfile', 'shutil'
        }
        return module_name.split('.')[0] in suspicious_modules

    def _get_vulnerable_packages(self) -> set:
        """Get list of known vulnerable packages"""
        # In a real implementation, this would fetch from a vulnerability database
        return {
            'pyyaml', 'pillow', 'urllib3', 'requests', 'jinja2',
            'django', 'flask', 'cryptography', 'paramiko'
        }

    def _setup_logger(self) -> logging.Logger:
        """Set up logger for the integration"""
        logger = logging.getLogger('PythonAgentIntegration')
        handler = logging.StreamHandler()
        formatter = logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        )
        handler.setFormatter(formatter)
        logger.addHandler(handler)
        logger.setLevel(logging.INFO)
        return logger

    def get_metrics(self) -> Dict[str, Any]:
        """Get current metrics"""
        return {
            **self.metrics,
            "status": self.status.value,
            "enabled": self.enabled,
            "event_handlers": len(self.event_handlers),
            "uptime": time.time() - self.metrics.get("start_time", time.time())
        }

    def shutdown(self):
        """Shutdown the integration"""
        self.status = IntegrationStatus.SHUTTING_DOWN
        self._shutdown_event.set()
        self.logger.info("PythonAgentIntegration shutting down")


# Supporting monitor classes
class PythonFileMonitor:
    def __init__(self, agent):
        self.agent = agent
        
    def start(self):
        # File monitoring implementation would go here
        pass


class PythonProcessMonitor:
    def __init__(self, agent):
        self.agent = agent
        
    def start(self):
        # Process monitoring implementation would go here
        pass


class PythonNetworkMonitor:
    def __init__(self, agent):
        self.agent = agent
        
    def start(self):
        # Network monitoring implementation would go here
        pass


# Example usage
if __name__ == "__main__":
    integration = PythonAgentIntegration()
    
    config = {
        "enabled": True,
        "module_path": "env_directors.integration.python_agent",
        "auto_import": True,
        "file_monitoring": {"enabled": True},
        "process_monitoring": {"enabled": True},
        "network_monitoring": {"enabled": False}
    }
    
    if integration.initialize(config):
        print("Python integration initialized successfully")
        
        # Register event handler
        def security_event_handler(event: PythonSecurityEvent):
            print(f"Security Event: {event.event_type} - {event.severity.value} - {event.message if hasattr(event, 'message') else 'No message'}")
        
        integration.register_event_handler("*", security_event_handler)
        
        # Example: Scan environment
        env_scan = integration.scan_python_environment()
        print(f"Environment scan completed: {len(env_scan.get('security_issues', []))} issues found")
        
        # Example: Check a Python file
        context = SecurityContext(
            operation="python_scan",
            target=__file__
        )
        
        result = integration.execute_security_check(context)
        print(f"Code scan result: {result.success} - {result.message}")
        
        time.sleep(5)
        integration.shutdown()