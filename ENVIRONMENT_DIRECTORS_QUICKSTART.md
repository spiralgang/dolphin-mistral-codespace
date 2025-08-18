# Quick Start Guide - Environment Directors

## 🚀 Getting Started

The Environment Directors system is now ready to use! Here's how to get started quickly.

### 🔧 Basic Setup

1. **For Python Integration:**
```python
from env-directors.integration.PythonAgentIntegration import create_standard_integration

# Create and initialize
integration = create_standard_integration()
integration.initialize()

# Perform security check
result = integration.perform_security_check()
print(f"Security status: {result['overall_status']}")

# Cleanup when done
integration.shutdown()
```

2. **For Kotlin/JVM Integration:**
```kotlin
// Initialize ToolHub
val toolHub = ToolHub.getInstance()

// Register directors
toolHub.registerDirector("permissions", PermissionsDirector())
toolHub.registerDirector("memory", MemoryDirector())

// Start system
toolHub.startup()

// Run security check
val report = toolHub.executeSecurityCheck()
```

### 📋 Key Features Available

✅ **PermissionsDirector.kt** - File system permission monitoring  
✅ **SymlinkDirector.kt** - Symlink attack prevention  
✅ **FileSecurityDirector.py** - File integrity and malware detection  
✅ **MemoryDirector.kt** - Memory management and leak detection  
✅ **Configuration System** - YAML-based configuration  
✅ **Integration Examples** - Android and Python integrations  

### 🛡️ Security Levels

- **Minimal**: Basic monitoring, good for development
- **Standard**: Balanced security, good for most applications  
- **Hardened**: Maximum security, good for sensitive environments

### 📁 File Structure Created

```
env-directors/
├── ToolHub.kt                 # Central coordination system
├── directors/                 # Individual director modules
│   ├── PermissionsDirector.kt
│   ├── SymlinkDirector.kt
│   ├── FileSecurityDirector.py
│   └── MemoryDirector.kt
├── config/
│   └── directors.yaml         # Configuration file
├── integration/               # Integration examples
│   ├── AndroidAgentIntegration.kt
│   └── PythonAgentIntegration.py
└── README.md                  # Full documentation
```

### 🧪 Testing

Run the demo to see it in action:
```bash
python3 examples/demo.py
```

### 📖 Next Steps

1. Read the full README.md in env-directors/
2. Customize directors.yaml for your environment
3. Integrate with your existing applications
4. Set up monitoring and alerting

The system is designed to be **completely modular** and **non-intrusive** - it won't interfere with existing code while providing comprehensive security monitoring.