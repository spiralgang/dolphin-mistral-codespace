#!/usr/bin/env python3
"""
Integration Example - Shows how to integrate Environment Directors with existing applications
"""

import sys
import os
import time
sys.path.append(os.path.join(os.path.dirname(__file__), '..', 'env-directors'))

from integration.PythonAgentIntegration import (
    create_standard_integration, create_hardened_integration,
    PythonAgentConfig, PythonSecurityLevel
)

class ExampleAIAgent:
    """Example AI Agent that uses Environment Directors for security"""
    
    def __init__(self, security_level="standard"):
        self.name = "ExampleAIAgent"
        self.security_level = security_level
        self.security_integration = None
        self.is_running = False
        
    def initialize(self):
        """Initialize the AI agent with security integration"""
        print(f"🤖 Initializing {self.name} with {self.security_level} security...")
        
        # Choose security integration based on level
        if self.security_level == "hardened":
            self.security_integration = create_hardened_integration()
        else:
            self.security_integration = create_standard_integration()
        
        # Register security event handlers
        self.security_integration.register_hook('file_quarantined', self._handle_file_quarantined)
        self.security_integration.register_hook('memory_warning', self._handle_memory_warning)
        self.security_integration.register_hook('import_blocked', self._handle_import_blocked)
        
        # Initialize the security system
        if self.security_integration.initialize():
            print("✅ Security integration initialized successfully")
            self.is_running = True
            return True
        else:
            print("❌ Security integration failed")
            return False
    
    def perform_ai_task(self, task_name, code=None):
        """Perform an AI task with security monitoring"""
        print(f"\n🔧 Performing AI task: {task_name}")
        
        if not self.is_running:
            print("❌ Agent not initialized")
            return False
        
        try:
            # Pre-task security check
            security_result = self.security_integration.perform_security_check()
            if security_result['overall_status'] == 'FAIL':
                print("⚠️  Security check failed - aborting task")
                return False
            
            # Simulate AI task execution
            if code and self.security_integration.config.sandbox_mode:
                print("🔒 Executing code in sandbox...")
                try:
                    result = self.security_integration.sandbox_eval(code)
                    print(f"✅ Sandbox execution successful: {result}")
                except Exception as e:
                    print(f"⚠️  Sandbox execution blocked: {e}")
                    return False
            
            # Simulate some work
            print("🧠 Processing AI task...")
            time.sleep(0.1)  # Simulate work
            
            # Post-task cleanup
            cleanup_result = self.security_integration.cleanup_resources()
            if cleanup_result['objects_freed'] > 0:
                print(f"🧹 Cleaned up {cleanup_result['objects_freed']} objects")
            
            print("✅ AI task completed successfully")
            return True
            
        except Exception as e:
            print(f"❌ AI task failed: {e}")
            return False
    
    def get_security_status(self):
        """Get current security status"""
        if not self.security_integration:
            return {"status": "not_initialized"}
        
        result = self.security_integration.perform_security_check()
        return {
            "overall_status": result['overall_status'],
            "quarantined_files": len(self.security_integration.get_quarantined_files()),
            "security_violations": len(self.security_integration.get_security_violations()),
            "memory_usage": result.get('memory_security', {}).get('current_usage_mb', 0)
        }
    
    def shutdown(self):
        """Shutdown the AI agent"""
        print(f"\n🛑 Shutting down {self.name}...")
        
        if self.security_integration:
            self.security_integration.shutdown()
        
        self.is_running = False
        print("✅ Agent shutdown complete")
    
    def _handle_file_quarantined(self, file_path, reason):
        """Handle file quarantine event"""
        print(f"🚨 SECURITY ALERT: File quarantined - {file_path} ({reason})")
    
    def _handle_memory_warning(self, usage_mb):
        """Handle memory warning event"""
        print(f"⚠️  MEMORY WARNING: High usage - {usage_mb}MB")
    
    def _handle_import_blocked(self, module):
        """Handle blocked import event"""
        print(f"🚫 IMPORT BLOCKED: Module '{module}' not allowed")

def demo_standard_agent():
    """Demo with standard security agent"""
    print("=" * 60)
    print("🔒 STANDARD SECURITY AGENT DEMO")
    print("=" * 60)
    
    agent = ExampleAIAgent("standard")
    
    if agent.initialize():
        # Test safe operations
        agent.perform_ai_task("Safe Calculation", "2 + 2 * 3")
        agent.perform_ai_task("Data Processing", "sum([1, 2, 3, 4, 5])")
        
        # Check security status
        status = agent.get_security_status()
        print(f"\n📊 Security Status: {status['overall_status']}")
        print(f"   Quarantined files: {status['quarantined_files']}")
        print(f"   Security violations: {status['security_violations']}")
        
        agent.shutdown()
        return True
    
    return False

def demo_hardened_agent():
    """Demo with hardened security agent"""
    print("\n" + "=" * 60)
    print("🛡️  HARDENED SECURITY AGENT DEMO")
    print("=" * 60)
    
    agent = ExampleAIAgent("hardened")
    
    if agent.initialize():
        # Test safe operations
        agent.perform_ai_task("Safe Calculation", "10 * 5 + 2")
        
        # Test potentially unsafe operation (should be blocked)
        print("\n🧪 Testing security restrictions...")
        agent.perform_ai_task("File System Access", "open('/etc/passwd', 'r')")
        
        # Check security status
        status = agent.get_security_status()
        print(f"\n📊 Security Status: {status['overall_status']}")
        
        agent.shutdown()
        return True
    
    return False

def demo_manual_integration():
    """Demo manual integration setup"""
    print("\n" + "=" * 60) 
    print("⚙️  MANUAL INTEGRATION DEMO")
    print("=" * 60)
    
    # Create custom configuration
    custom_config = PythonAgentConfig(
        security_level=PythonSecurityLevel.STANDARD,
        max_memory_mb=128,  # Low memory limit
        sandbox_mode=True,
        allowed_modules=['json', 'math', 'datetime'],
        network_access=False
    )
    
    print("🔧 Custom Configuration:")
    print(f"   Security Level: {custom_config.security_level.value}")
    print(f"   Memory Limit: {custom_config.max_memory_mb}MB")
    print(f"   Allowed Modules: {custom_config.allowed_modules}")
    print(f"   Network Access: {custom_config.network_access}")
    
    # This would create a fully configured integration
    # integration = PythonAgentIntegration(custom_config)
    
    print("✅ Custom configuration ready for use")

def main():
    """Main demo function"""
    print("🚀 Environment Directors Integration Demo")
    print("Demonstrating how to integrate with existing applications\n")
    
    success_count = 0
    
    # Run demos
    if demo_standard_agent():
        success_count += 1
    
    if demo_hardened_agent():
        success_count += 1
    
    demo_manual_integration()  # Always runs
    success_count += 1
    
    # Summary
    print("\n" + "=" * 60)
    print("📈 INTEGRATION DEMO SUMMARY")
    print("=" * 60)
    print(f"✅ Completed {success_count}/3 demos successfully")
    print("\n🎯 Integration Benefits Demonstrated:")
    print("   • Easy integration with existing AI agents")
    print("   • Configurable security levels")
    print("   • Real-time security monitoring")
    print("   • Event-driven security responses")
    print("   • Sandboxed code execution")
    print("   • Memory management and cleanup")
    print("   • Non-intrusive modular design")
    
    print("\n📚 Next Steps:")
    print("   1. Choose appropriate security level for your use case")
    print("   2. Configure allowed modules and resources")
    print("   3. Register custom security event handlers")
    print("   4. Integrate with your existing application startup/shutdown")
    
    return 0

if __name__ == "__main__":
    exit_code = main()
    sys.exit(exit_code)