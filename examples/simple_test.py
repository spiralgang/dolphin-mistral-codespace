#!/usr/bin/env python3
"""
Simple test script for the Environment Directors Python implementation
"""

import sys
import os
import tempfile
sys.path.append(os.path.join(os.path.dirname(__file__), '..', 'env-directors'))

def test_basic_functionality():
    print("=== Testing Basic Director Functionality ===")
    
    try:
        from directors.FileSecurityDirector import FileSecurityDirector, Status, DirectorResult
        
        # Create a simple director instance
        director = FileSecurityDirector()
        
        # Create a temporary directory for testing
        with tempfile.TemporaryDirectory() as temp_dir:
            # Override monitored directories to just the temp directory
            director.monitored_directories = {temp_dir}
            director.critical_files = {os.path.join(temp_dir, "test_file.txt")}
            
            # Create a test file
            test_file = os.path.join(temp_dir, "test_file.txt")
            with open(test_file, 'w') as f:
                f.write("This is a test file")
            
            # Initialize with minimal config
            class MockHub:
                def get_config(self, key):
                    if key == "file_security.quarantine_dir":
                        return os.path.join(temp_dir, "quarantine")
                    return None
            
            director.initialize(MockHub())
            print("✓ FileSecurityDirector initialized")
            
            # Perform security check
            result = director.perform_security_check()
            print(f"✓ Security check completed: {result.status.value}")
            print(f"  Message: {result.message}")
            
            return True
            
    except Exception as e:
        print(f"✗ FileSecurityDirector test failed: {e}")
        return False

def test_python_integration_basic():
    print("\n=== Testing Python Integration Basic ===")
    
    try:
        from integration.PythonAgentIntegration import PythonAgentConfig, PythonSecurityLevel
        
        # Create a minimal config
        config = PythonAgentConfig(
            security_level=PythonSecurityLevel.MINIMAL,
            max_memory_mb=128,
            sandbox_mode=False  # Disable sandbox for simpler test
        )
        
        print("✓ PythonAgentConfig created successfully")
        print(f"  Security level: {config.security_level.value}")
        print(f"  Max memory: {config.max_memory_mb}MB")
        print(f"  Sandbox mode: {config.sandbox_mode}")
        
        return True
        
    except Exception as e:
        print(f"✗ Python integration test failed: {e}")
        return False

def test_configuration_loading():
    print("\n=== Testing Configuration Loading ===")
    
    try:
        import yaml
        
        config_path = os.path.join(os.path.dirname(__file__), '..', 'env-directors', 'config', 'directors.yaml')
        
        with open(config_path, 'r') as f:
            config = yaml.safe_load(f)
        
        print("✓ Configuration file loaded successfully")
        print(f"  ToolHub config: {list(config.get('toolhub', {}).keys())}")
        print(f"  Available profiles: {list(config.get('profiles', {}).keys())}")
        print(f"  Director load order: {config.get('load_order', [])}")
        
        return True
        
    except ImportError:
        print("⚠ YAML module not available - config loading test skipped")
        return True
    except Exception as e:
        print(f"✗ Configuration loading test failed: {e}")
        return False

def test_memory_monitoring():
    print("\n=== Testing Memory Monitoring ===")
    
    try:
        import psutil
        
        # Get current memory usage
        process = psutil.Process()
        memory_info = process.memory_info()
        memory_mb = memory_info.rss / (1024 * 1024)
        
        print(f"✓ Current memory usage: {memory_mb:.1f} MB")
        
        # Test memory limits
        max_allowed = 256  # MB
        if memory_mb > max_allowed:
            print(f"⚠ Memory usage exceeds test limit ({max_allowed}MB)")
        else:
            print(f"✓ Memory usage within limits")
        
        return True
        
    except ImportError:
        print("⚠ psutil module not available - using basic memory monitoring")
        
        # Fallback memory check
        import resource
        memory_kb = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
        # Note: On Linux, ru_maxrss is in KB, on macOS it's in bytes
        memory_mb = memory_kb / 1024 if sys.platform.startswith('linux') else memory_kb / (1024 * 1024)
        
        print(f"✓ Basic memory usage: {memory_mb:.1f} MB")
        return True
        
    except Exception as e:
        print(f"✗ Memory monitoring test failed: {e}")
        return False

if __name__ == "__main__":
    print("Environment Directors Simple Test Suite")
    print("=" * 50)
    
    tests = [
        test_basic_functionality,
        test_python_integration_basic,
        test_configuration_loading,
        test_memory_monitoring
    ]
    
    passed = 0
    total = len(tests)
    
    for test in tests:
        try:
            if test():
                passed += 1
        except Exception as e:
            print(f"✗ Test failed with exception: {e}")
    
    print("\n" + "=" * 50)
    print(f"Test Results: {passed}/{total} tests passed")
    
    if passed == total:
        print("✓ All tests passed successfully!")
        sys.exit(0)
    else:
        print(f"✗ {total - passed} test(s) failed")
        sys.exit(1)