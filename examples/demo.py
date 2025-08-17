#!/usr/bin/env python3
"""
Demo script for Environment Directors - showcases key functionality
"""

import sys
import os
import tempfile
import json

sys.path.append(os.path.join(os.path.dirname(__file__), '..', 'env-directors'))

def demo_file_security():
    print("🔒 FileSecurityDirector Demo")
    print("-" * 30)
    
    from directors.FileSecurityDirector import FileSecurityDirector, Status
    
    # Create a minimal director for demo
    director = FileSecurityDirector()
    director.name = "FileSecurityDirector"
    
    # Override with safe demo configuration
    director.critical_files = set()
    director.monitored_directories = set()
    director.suspicious_extensions = {'.exe', '.scr', '.bat'}
    
    print("✓ Director created with minimal configuration")
    print(f"  Name: {director.get_name()}")
    print(f"  Suspicious extensions: {director.suspicious_extensions}")
    
    # Test the pattern matching
    test_files = ["document.txt", "malware.exe", "script.py", "suspicious.scr"]
    
    print("\n🔍 Testing suspicious file detection:")
    for filename in test_files:
        is_suspicious = any(filename.lower().endswith(ext) for ext in director.suspicious_extensions)
        status = "⚠️  SUSPICIOUS" if is_suspicious else "✅ SAFE"
        print(f"  {filename:15} -> {status}")
    
    # Test malware patterns
    print("\n🦠 Testing malware pattern detection:")
    test_patterns = [
        b"This is normal text",
        b"cmd.exe /c malicious_command",
        b"powershell -e encoded_payload",
        b"Regular file content"
    ]
    
    for pattern in test_patterns:
        contains_malware = any(mal_pattern in pattern for mal_pattern in director.malware_patterns)
        status = "⚠️  MALWARE DETECTED" if contains_malware else "✅ CLEAN"
        text_preview = pattern.decode('utf-8', errors='ignore')[:30] + "..."
        print(f"  '{text_preview}' -> {status}")

def demo_python_integration():
    print("\n\n🐍 PythonAgentIntegration Demo")
    print("-" * 30)
    
    from integration.PythonAgentIntegration import (
        PythonAgentConfig, PythonSecurityLevel, PythonEnvironmentInfo
    )
    
    # Create different security configurations
    configs = {
        "Minimal": PythonAgentConfig(
            security_level=PythonSecurityLevel.MINIMAL,
            max_memory_mb=1024,
            sandbox_mode=False,
            network_access=True
        ),
        "Standard": PythonAgentConfig(
            security_level=PythonSecurityLevel.STANDARD,
            max_memory_mb=512,
            sandbox_mode=True,
            network_access=True
        ),
        "Hardened": PythonAgentConfig(
            security_level=PythonSecurityLevel.HARDENED,
            max_memory_mb=256,
            sandbox_mode=True,
            network_access=False
        )
    }
    
    print("🛡️  Security Level Configurations:")
    for name, config in configs.items():
        print(f"\n  {name} Security:")
        print(f"    Security Level: {config.security_level.value}")
        print(f"    Max Memory: {config.max_memory_mb}MB")
        print(f"    Sandbox Mode: {config.sandbox_mode}")
        print(f"    Network Access: {config.network_access}")
        print(f"    Restricted Modules: {len(config.restricted_modules)} modules")
    
    # Demo environment detection
    print("\n🌍 Environment Information:")
    env_info = PythonEnvironmentInfo(
        python_version=sys.version.split()[0],
        virtual_env=os.environ.get('VIRTUAL_ENV'),
        installed_packages=["numpy", "pandas", "requests"],  # Mock data
        sys_path=sys.path[:3],  # First 3 paths only
        working_directory=os.getcwd(),
        user_home=os.path.expanduser("~"),
        temp_directory="/tmp"
    )
    
    print(f"  Python Version: {env_info.python_version}")
    print(f"  Virtual Environment: {env_info.virtual_env or 'None'}")
    print(f"  Working Directory: {env_info.working_directory}")
    print(f"  System Path Entries: {len(env_info.sys_path)}")

def demo_configuration():
    print("\n\n⚙️  Configuration System Demo")
    print("-" * 30)
    
    try:
        config_path = os.path.join(os.path.dirname(__file__), '..', 'env-directors', 'config', 'directors.yaml')
        
        if os.path.exists(config_path):
            # Read just the first few lines to avoid loading full YAML
            with open(config_path, 'r') as f:
                lines = f.readlines()[:20]
            
            print("📋 Configuration file structure (first 20 lines):")
            for i, line in enumerate(lines, 1):
                print(f"  {i:2}: {line.rstrip()}")
            
            print(f"\n📊 Configuration file stats:")
            print(f"  Total lines: {len(open(config_path).readlines())}")
            print(f"  File size: {os.path.getsize(config_path)} bytes")
            
        else:
            print("❌ Configuration file not found")
            
    except Exception as e:
        print(f"❌ Error reading configuration: {e}")

def demo_security_report():
    print("\n\n📊 Security Report Demo")
    print("-" * 30)
    
    # Mock security report data
    security_report = {
        "timestamp": "2024-01-15T10:30:00Z",
        "directors": {
            "PermissionsDirector": {
                "status": "PASS",
                "message": "All permission checks passed",
                "details": {
                    "critical_paths_checked": 5,
                    "world_writable_files": 0,
                    "suid_files": 3
                }
            },
            "SymlinkDirector": {
                "status": "WARN",
                "message": "Found 2 potentially malicious symlinks",
                "details": {
                    "malicious_symlinks": ["/tmp/suspicious_link"],
                    "max_depth": 5,
                    "protected_paths": 4
                }
            },
            "FileSecurityDirector": {
                "status": "PASS", 
                "message": "All file security checks passed",
                "details": {
                    "files_scanned": 1247,
                    "quarantined": 0,
                    "integrity_violations": 0
                }
            },
            "MemoryDirector": {
                "status": "WARN",
                "message": "Memory usage high: 87%",
                "details": {
                    "heap_usage_percent": 87,
                    "memory_leaks_detected": 0,
                    "cleanup_performed": True
                }
            }
        },
        "overall_status": "WARN"
    }
    
    print("🔍 Sample Security Report:")
    print(f"  Overall Status: {security_report['overall_status']}")
    print(f"  Timestamp: {security_report['timestamp']}")
    print(f"  Directors Checked: {len(security_report['directors'])}")
    
    print("\n📋 Director Results:")
    for director_name, result in security_report['directors'].items():
        status_icon = {
            "PASS": "✅",
            "WARN": "⚠️", 
            "FAIL": "❌",
            "ERROR": "🚨"
        }.get(result['status'], "❓")
        
        print(f"  {status_icon} {director_name}: {result['status']}")
        print(f"     {result['message']}")
        
        if result['details']:
            key_details = list(result['details'].items())[:2]  # Show first 2 details
            for key, value in key_details:
                print(f"     • {key}: {value}")

def main():
    print("🚀 Environment Directors System Demo")
    print("=" * 50)
    
    try:
        demo_file_security()
        demo_python_integration()
        demo_configuration()
        demo_security_report()
        
        print("\n" + "=" * 50)
        print("✅ Demo completed successfully!")
        print("\n💡 Key Features Demonstrated:")
        print("  • Modular director architecture")
        print("  • Configurable security levels")
        print("  • File security monitoring")
        print("  • Python integration capabilities") 
        print("  • Comprehensive security reporting")
        print("  • YAML-based configuration system")
        
    except Exception as e:
        print(f"\n❌ Demo failed: {e}")
        import traceback
        traceback.print_exc()
        return 1
    
    return 0

if __name__ == "__main__":
    exit_code = main()
    sys.exit(exit_code)