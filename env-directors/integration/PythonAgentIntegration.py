#!/usr/bin/env python3
"""
PythonAgentIntegration - Integration layer for Python-based AI agents

This integration provides a bridge between the ToolHub director system
and Python applications, enabling comprehensive security monitoring,
file system protection, and resource management for Python AI agents.
"""

import os
import sys
import json
import time
import threading
import subprocess
from pathlib import Path
from typing import Dict, List, Optional, Any, Callable
from dataclasses import dataclass, asdict
from enum import Enum
import importlib.util

# Import the FileSecurityDirector we created
sys.path.append(os.path.dirname(os.path.dirname(__file__)))
from directors.FileSecurityDirector import FileSecurityDirector, FileSecurityDirectorAdapter


class PythonSecurityLevel(Enum):
    MINIMAL = "minimal"
    STANDARD = "standard" 
    HARDENED = "hardened"


@dataclass
class PythonAgentConfig:
    """Configuration for Python agent security"""
    security_level: PythonSecurityLevel = PythonSecurityLevel.STANDARD
    max_memory_mb: int = 512
    allowed_modules: List[str] = None
    restricted_modules: List[str] = None
    sandbox_mode: bool = False
    network_access: bool = True
    file_system_access: bool = True
    temp_dir_access: bool = True
    
    def __post_init__(self):
        if self.allowed_modules is None:
            self.allowed_modules = []
        if self.restricted_modules is None:
            self.restricted_modules = ['os', 'subprocess', 'sys', '__builtin__', 'builtins']


@dataclass
class PythonEnvironmentInfo:
    """Information about Python environment"""
    python_version: str
    virtual_env: Optional[str]
    installed_packages: List[str]
    sys_path: List[str]
    working_directory: str
    user_home: str
    temp_directory: str


class PythonAgentIntegration:
    """Integration layer for Python AI agents with ToolHub directors"""
    
    def __init__(self, config: Optional[PythonAgentConfig] = None):
        self.config = config or PythonAgentConfig()
        self.file_security = FileSecurityDirectorAdapter()
        self.environment_info = self._gather_environment_info()
        self.hooks: Dict[str, List[Callable]] = {}
        self.monitoring_active = False
        self.monitor_thread: Optional[threading.Thread] = None
        
        # Security state
        self.quarantined_files: List[str] = []
        self.blocked_operations: List[str] = []
        self.security_violations: List[str] = []
        
    def initialize(self) -> bool:
        """Initialize the Python agent integration"""
        try:
            print(f"[PythonAgentIntegration] Initializing with {self.config.security_level.value} security level")
            
            # Initialize file security director
            file_config = {
                "file_security.quarantine_dir": self._get_quarantine_dir(),
                "file_security.scan_directories": self._get_scan_directories(),
                "file_security.max_file_size": 10 * 1024 * 1024  # 10MB
            }
            
            self.file_security.initialize(file_config)
            
            # Setup security policies based on configuration
            self._setup_security_policies()
            
            # Setup monitoring based on security level
            self._setup_monitoring()
            
            # Install import hooks if in sandbox mode
            if self.config.sandbox_mode:
                self._install_import_hooks()
            
            # Setup memory monitoring
            self._setup_memory_monitoring()
            
            print("[PythonAgentIntegration] Initialization complete")
            return True
            
        except Exception as e:
            print(f"[PythonAgentIntegration] Initialization failed: {e}")
            return False
    
    def perform_security_check(self) -> Dict[str, Any]:
        """Perform comprehensive security check for Python environment"""
        print("[PythonAgentIntegration] Performing security check...")
        
        results = {
            "timestamp": time.time(),
            "file_security": {},
            "module_security": {},
            "environment_security": {},
            "memory_security": {},
            "overall_status": "unknown"
        }
        
        try:
            # File security check
            file_result = self.file_security.perform_security_check()
            results["file_security"] = file_result
            
            # Module security check
            results["module_security"] = self._check_module_security()
            
            # Environment security check
            results["environment_security"] = self._check_environment_security()
            
            # Memory security check
            results["memory_security"] = self._check_memory_security()
            
            # Determine overall status
            results["overall_status"] = self._calculate_overall_status(results)
            
            print(f"[PythonAgentIntegration] Security check complete: {results['overall_status']}")
            return results
            
        except Exception as e:
            print(f"[PythonAgentIntegration] Security check failed: {e}")
            results["error"] = str(e)
            results["overall_status"] = "error"
            return results
    
    def register_hook(self, event: str, callback: Callable) -> None:
        """Register a security event hook"""
        if event not in self.hooks:
            self.hooks[event] = []
        self.hooks[event].append(callback)
        print(f"[PythonAgentIntegration] Registered hook for event: {event}")
    
    def execute_hooks(self, event: str, *args, **kwargs) -> None:
        """Execute hooks for a specific event"""
        if event in self.hooks:
            for callback in self.hooks[event]:
                try:
                    callback(*args, **kwargs)
                except Exception as e:
                    print(f"[PythonAgentIntegration] Hook execution failed for {event}: {e}")
    
    def sandbox_eval(self, code: str, allowed_names: Optional[Dict[str, Any]] = None) -> Any:
        """Safely evaluate Python code in sandboxed environment"""
        if not self.config.sandbox_mode:
            raise SecurityError("Sandbox mode not enabled")
        
        # Create restricted namespace
        safe_globals = {
            '__builtins__': self._get_safe_builtins(),
            'len': len,
            'str': str,
            'int': int,
            'float': float,
            'bool': bool,
            'list': list,
            'dict': dict,
            'tuple': tuple,
            'set': set,
        }
        
        if allowed_names:
            safe_globals.update(allowed_names)
        
        try:
            # Execute hooks before evaluation
            self.execute_hooks('before_eval', code=code)
            
            result = eval(code, safe_globals, {})
            
            # Execute hooks after evaluation
            self.execute_hooks('after_eval', code=code, result=result)
            
            return result
            
        except Exception as e:
            self.security_violations.append(f"Sandbox eval failed: {str(e)}")
            self.execute_hooks('eval_error', code=code, error=e)
            raise
    
    def validate_module_import(self, module_name: str) -> bool:
        """Validate if a module import is allowed"""
        # Check against explicitly allowed modules
        if self.config.allowed_modules and module_name not in self.config.allowed_modules:
            return False
        
        # Check against restricted modules
        if module_name in self.config.restricted_modules:
            return False
        
        # Additional security checks based on security level
        if self.config.security_level == PythonSecurityLevel.HARDENED:
            dangerous_modules = [
                'subprocess', 'os', 'sys', 'socket', 'urllib',
                'http', 'ftplib', 'smtplib', 'telnetlib',
                'exec', 'eval', 'compile', '__import__'
            ]
            if any(dangerous in module_name for dangerous in dangerous_modules):
                return False
        
        return True
    
    def quarantine_file(self, file_path: str, reason: str = "Security violation") -> bool:
        """Quarantine a suspicious file"""
        success = self.file_security.director.quarantine_file(file_path)
        if success:
            self.quarantined_files.append(file_path)
            self.execute_hooks('file_quarantined', file_path=file_path, reason=reason)
        return success
    
    def get_quarantined_files(self) -> List[str]:
        """Get list of quarantined files"""
        return self.quarantined_files.copy()
    
    def get_security_violations(self) -> List[str]:
        """Get list of security violations"""
        return self.security_violations.copy()
    
    def cleanup_resources(self) -> Dict[str, Any]:
        """Clean up resources and perform garbage collection"""
        import gc
        
        before_objects = len(gc.get_objects())
        before_memory = self._get_memory_usage()
        
        # Force garbage collection
        gc.collect()
        
        after_objects = len(gc.get_objects())
        after_memory = self._get_memory_usage()
        
        cleanup_result = {
            "objects_freed": before_objects - after_objects,
            "memory_freed_mb": (before_memory - after_memory) / (1024 * 1024),
            "gc_stats": gc.get_stats() if hasattr(gc, 'get_stats') else None
        }
        
        self.execute_hooks('resource_cleanup', result=cleanup_result)
        return cleanup_result
    
    def start_monitoring(self) -> None:
        """Start background security monitoring"""
        if self.monitoring_active:
            return
        
        self.monitoring_active = True
        self.monitor_thread = threading.Thread(target=self._monitoring_loop, daemon=True)
        self.monitor_thread.start()
        print("[PythonAgentIntegration] Background monitoring started")
    
    def stop_monitoring(self) -> None:
        """Stop background security monitoring"""
        self.monitoring_active = False
        if self.monitor_thread:
            self.monitor_thread.join(timeout=5.0)
        print("[PythonAgentIntegration] Background monitoring stopped")
    
    def shutdown(self) -> None:
        """Shutdown the integration"""
        print("[PythonAgentIntegration] Shutting down...")
        
        self.stop_monitoring()
        self.execute_hooks('shutdown')
        
        # Clean up resources
        self.cleanup_resources()
        
        print("[PythonAgentIntegration] Shutdown complete")
    
    def _gather_environment_info(self) -> PythonEnvironmentInfo:
        """Gather information about the Python environment"""
        try:
            # Get installed packages
            packages = []
            try:
                result = subprocess.run([sys.executable, '-m', 'pip', 'list'], 
                                     capture_output=True, text=True, timeout=10)
                if result.returncode == 0:
                    packages = [line.split()[0] for line in result.stdout.strip().split('\n')[2:] 
                               if line.strip()]
            except:
                pass
            
            return PythonEnvironmentInfo(
                python_version=sys.version,
                virtual_env=os.environ.get('VIRTUAL_ENV'),
                installed_packages=packages,
                sys_path=sys.path.copy(),
                working_directory=os.getcwd(),
                user_home=str(Path.home()),
                temp_directory=os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..', 'tmp'))
            )
        except Exception as e:
            print(f"[PythonAgentIntegration] Error gathering environment info: {e}")
            return PythonEnvironmentInfo(
                python_version=sys.version,
                virtual_env=None,
                installed_packages=[],
                sys_path=sys.path.copy(),
                working_directory=os.getcwd(),
                user_home=str(Path.home()),
                temp_directory="/tmp"
            )
    
    def _get_quarantine_dir(self) -> str:
        """Get quarantine directory path"""
        return os.path.join(self.environment_info.user_home, ".python_agent_quarantine")
    
    def _get_scan_directories(self) -> List[str]:
        """Get directories to scan for security issues"""
        dirs = [
            self.environment_info.working_directory,
            self.environment_info.temp_directory,
        ]
        
        if self.config.temp_dir_access:
            dirs.extend(["/tmp", "/var/tmp"])
        
        return dirs
    
    def _setup_security_policies(self) -> None:
        """Setup security policies based on configuration"""
        if self.config.security_level == PythonSecurityLevel.MINIMAL:
            # Minimal security - basic file monitoring only
            pass
        elif self.config.security_level == PythonSecurityLevel.STANDARD:
            # Standard security - moderate restrictions
            self.config.restricted_modules.extend(['ctypes', 'ctypes.util'])
        elif self.config.security_level == PythonSecurityLevel.HARDENED:
            # Hardened security - strict restrictions
            self.config.restricted_modules.extend([
                'ctypes', 'ctypes.util', 'multiprocessing', 'threading',
                'asyncio', 'concurrent.futures', 'pickle', 'marshal'
            ])
    
    def _setup_monitoring(self) -> None:
        """Setup monitoring based on security level"""
        if self.config.security_level in [PythonSecurityLevel.STANDARD, PythonSecurityLevel.HARDENED]:
            self.start_monitoring()
    
    def _install_import_hooks(self) -> None:
        """Install import hooks for sandbox mode"""
        original_import = __builtins__['__import__']
        
        def secure_import(name, globals=None, locals=None, fromlist=(), level=0):
            if not self.validate_module_import(name):
                self.security_violations.append(f"Blocked import: {name}")
                self.execute_hooks('import_blocked', module=name)
                raise ImportError(f"Import of module '{name}' is not allowed")
            
            return original_import(name, globals, locals, fromlist, level)
        
        __builtins__['__import__'] = secure_import
    
    def _setup_memory_monitoring(self) -> None:
        """Setup memory monitoring and limits"""
        # This would integrate with system memory monitoring
        # For now, just register hooks
        self.register_hook('memory_warning', self._handle_memory_warning)
    
    def _handle_memory_warning(self, usage_mb: int) -> None:
        """Handle memory warning"""
        print(f"[PythonAgentIntegration] Memory warning: {usage_mb}MB used")
        if usage_mb > self.config.max_memory_mb:
            self.cleanup_resources()
    
    def _check_module_security(self) -> Dict[str, Any]:
        """Check module-related security issues"""
        issues = []
        
        # Check for dangerous modules in sys.modules
        dangerous_modules = ['os', 'subprocess', 'ctypes', 'marshal', 'pickle']
        loaded_dangerous = [mod for mod in dangerous_modules if mod in sys.modules]
        
        if loaded_dangerous and self.config.security_level == PythonSecurityLevel.HARDENED:
            issues.extend([f"Dangerous module loaded: {mod}" for mod in loaded_dangerous])
        
        return {
            "status": "FAIL" if issues else "PASS",
            "issues": issues,
            "loaded_modules": len(sys.modules),
            "dangerous_modules_loaded": loaded_dangerous
        }
    
    def _check_environment_security(self) -> Dict[str, Any]:
        """Check environment-related security issues"""
        issues = []
        
        # Check for suspicious environment variables
        suspicious_vars = ['LD_PRELOAD', 'DYLD_INSERT_LIBRARIES', 'PYTHONPATH']
        found_suspicious = [var for var in suspicious_vars if var in os.environ]
        
        if found_suspicious:
            issues.extend([f"Suspicious environment variable: {var}" for var in found_suspicious])
        
        # Check working directory permissions
        try:
            cwd_stat = os.stat(self.environment_info.working_directory)
            if cwd_stat.st_mode & 0o002:  # World writable
                issues.append("Working directory is world-writable")
        except OSError:
            pass
        
        return {
            "status": "WARN" if issues else "PASS",
            "issues": issues,
            "suspicious_env_vars": found_suspicious,
            "python_version": self.environment_info.python_version
        }
    
    def _check_memory_security(self) -> Dict[str, Any]:
        """Check memory-related security issues"""
        current_usage = self._get_memory_usage()
        current_mb = current_usage / (1024 * 1024)
        
        issues = []
        if current_mb > self.config.max_memory_mb:
            issues.append(f"Memory usage exceeds limit: {current_mb:.1f}MB > {self.config.max_memory_mb}MB")
        
        return {
            "status": "FAIL" if issues else "PASS",
            "issues": issues,
            "current_usage_mb": current_mb,
            "max_allowed_mb": self.config.max_memory_mb
        }
    
    def _get_memory_usage(self) -> int:
        """Get current memory usage in bytes"""
        try:
            import psutil
            process = psutil.Process()
            return process.memory_info().rss
        except ImportError:
            # Fallback method
            import resource
            return resource.getrusage(resource.RUSAGE_SELF).ru_maxrss * 1024
    
    def _calculate_overall_status(self, results: Dict[str, Any]) -> str:
        """Calculate overall security status"""
        statuses = []
        for category, result in results.items():
            if isinstance(result, dict) and 'status' in result:
                statuses.append(result['status'])
        
        if 'FAIL' in statuses or 'ERROR' in statuses:
            return 'FAIL'
        elif 'WARN' in statuses:
            return 'WARN'
        else:
            return 'PASS'
    
    def _get_safe_builtins(self) -> Dict[str, Any]:
        """Get safe builtins for sandbox execution"""
        safe_builtins = {
            'abs': abs,
            'all': all,
            'any': any,
            'bin': bin,
            'bool': bool,
            'chr': chr,
            'dict': dict,
            'enumerate': enumerate,
            'filter': filter,
            'float': float,
            'hex': hex,
            'int': int,
            'len': len,
            'list': list,
            'map': map,
            'max': max,
            'min': min,
            'oct': oct,
            'ord': ord,
            'range': range,
            'reversed': reversed,
            'round': round,
            'set': set,
            'slice': slice,
            'sorted': sorted,
            'str': str,
            'sum': sum,
            'tuple': tuple,
            'type': type,
            'zip': zip,
        }
        
        return safe_builtins
    
    def _monitoring_loop(self) -> None:
        """Background monitoring loop"""
        while self.monitoring_active:
            try:
                # Perform periodic security checks
                self.perform_security_check()
                
                # Sleep for monitoring interval
                time.sleep(60)  # Check every minute
                
            except Exception as e:
                print(f"[PythonAgentIntegration] Monitoring error: {e}")
                time.sleep(30)  # Shorter sleep on error


class SecurityError(Exception):
    """Custom security exception"""
    pass


# Convenience functions and helpers
def create_minimal_integration() -> PythonAgentIntegration:
    """Create integration with minimal security"""
    config = PythonAgentConfig(
        security_level=PythonSecurityLevel.MINIMAL,
        sandbox_mode=False,
        max_memory_mb=1024
    )
    return PythonAgentIntegration(config)


def create_standard_integration() -> PythonAgentIntegration:
    """Create integration with standard security"""
    config = PythonAgentConfig(
        security_level=PythonSecurityLevel.STANDARD,
        sandbox_mode=True,
        max_memory_mb=512,
        network_access=True,
        file_system_access=True
    )
    return PythonAgentIntegration(config)


def create_hardened_integration() -> PythonAgentIntegration:
    """Create integration with hardened security"""
    config = PythonAgentConfig(
        security_level=PythonSecurityLevel.HARDENED,
        sandbox_mode=True,
        max_memory_mb=256,
        network_access=False,
        file_system_access=False,
        temp_dir_access=False
    )
    return PythonAgentIntegration(config)


# Example usage
if __name__ == "__main__":
    print("Python Agent Integration Example")
    
    # Create standard integration
    integration = create_standard_integration()
    
    if integration.initialize():
        print("Integration initialized successfully")
        
        # Perform security check
        result = integration.perform_security_check()
        print(f"Security check result: {result['overall_status']}")
        
        # Example of sandbox evaluation
        if integration.config.sandbox_mode:
            try:
                result = integration.sandbox_eval("1 + 2 + 3")
                print(f"Sandbox eval result: {result}")
            except Exception as e:
                print(f"Sandbox eval error: {e}")
        
        # Cleanup
        integration.shutdown()
    else:
        print("Integration initialization failed")