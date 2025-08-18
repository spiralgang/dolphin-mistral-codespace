#!/usr/bin/env python3
"""
Test script for the Environment Directors Python implementation
"""

import sys
import os
sys.path.append(os.path.join(os.path.dirname(__file__), '..', 'env-directors'))

from directors.FileSecurityDirector import FileSecurityDirector
from integration.PythonAgentIntegration import PythonAgentIntegration, PythonAgentConfig, PythonSecurityLevel

def test_file_security_director():
    print("=== Testing FileSecurityDirector ===")
    
    director = FileSecurityDirector()
    director.initialize(None)
    
    # Perform security check
    result = director.perform_security_check()
    print(f"Security Check Status: {result.status.value}")
    print(f"Message: {result.message}")
    
    if result.details:
        print("Details:")
        for key, value in result.details.items():
            if isinstance(value, list) and len(value) > 3:
                print(f"  {key}: {value[:3]} ... ({len(value)} total)")
            else:
                print(f"  {key}: {value}")
    
    print()

def test_python_agent_integration():
    print("=== Testing PythonAgentIntegration ===")
    
    config = PythonAgentConfig(
        security_level=PythonSecurityLevel.STANDARD,
        max_memory_mb=256,
        sandbox_mode=True
    )
    
    integration = PythonAgentIntegration(config)
    
    if integration.initialize():
        print("✓ Integration initialized successfully")
        
        # Test security check
        result = integration.perform_security_check()
        print(f"✓ Security check completed: {result['overall_status']}")
        
        # Test sandbox evaluation
        try:
            eval_result = integration.sandbox_eval("2 + 3 * 4")
            print(f"✓ Sandbox eval successful: {eval_result}")
        except Exception as e:
            print(f"✗ Sandbox eval failed: {e}")
        
        # Test module validation
        is_valid = integration.validate_module_import("json")
        print(f"✓ Module 'json' validation: {'allowed' if is_valid else 'blocked'}")
        
        is_valid = integration.validate_module_import("os")
        print(f"✓ Module 'os' validation: {'allowed' if is_valid else 'blocked'}")
        
        # Test cleanup
        cleanup_result = integration.cleanup_resources()
        print(f"✓ Resource cleanup: freed {cleanup_result['objects_freed']} objects")
        
        integration.shutdown()
        print("✓ Integration shutdown completed")
    else:
        print("✗ Integration initialization failed")
    
    print()

def test_different_security_levels():
    print("=== Testing Different Security Levels ===")
    
    levels = [
        (PythonSecurityLevel.MINIMAL, "minimal"),
        (PythonSecurityLevel.STANDARD, "standard"),
        (PythonSecurityLevel.HARDENED, "hardened")
    ]
    
    for level, name in levels:
        config = PythonAgentConfig(
            security_level=level,
            max_memory_mb=128,
            sandbox_mode=(level != PythonSecurityLevel.MINIMAL)
        )
        
        integration = PythonAgentIntegration(config)
        
        if integration.initialize():
            result = integration.perform_security_check()
            print(f"✓ {name.upper()} security level: {result['overall_status']}")
            integration.shutdown()
        else:
            print(f"✗ {name.upper()} security level: initialization failed")

if __name__ == "__main__":
    print("Environment Directors Python Test Suite")
    print("=" * 50)
    
    try:
        test_file_security_director()
        test_python_agent_integration()
        test_different_security_levels()
        
        print("=" * 50)
        print("✓ All tests completed successfully!")
        
    except Exception as e:
        print(f"✗ Test suite failed: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)