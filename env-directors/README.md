# Environment Directors - Modular Security & Environment Management System

The Environment Directors system provides a comprehensive, modular approach to security monitoring, resource management, and environmental protection for AI agents and applications. Built around a central ToolHub/DirectorHub API, this system enables pluggable, documented security modules that can be easily integrated into various environments.

## Architecture Overview

```
┌─────────────────────────────────────────────────────────────────┐
│                           ToolHub                               │
│  Central coordination and management system                     │
│  - Director registration and lifecycle                          │
│  - Security reporting aggregation                               │
│  - Configuration management                                      │
│  - Hook system for events                                       │
└─────────────┬───────────────────────────────────────────────────┘
              │
              ├── Directors (Pluggable Modules)
              │   ├── PermissionsDirector (File/System Permissions)
              │   ├── SymlinkDirector (Symlink Attack Prevention)  
              │   ├── FileSecurityDirector (File Integrity & Malware)
              │   └── MemoryDirector (Memory Management & Cleanup)
              │
              ├── Configuration System
              │   └── directors.yaml (Centralized Configuration)
              │
              └── Integration Layer
                  ├── AndroidAgentIntegration (Mobile Agents)
                  └── PythonAgentIntegration (Python-based Agents)
```

## Core Components

### ToolHub.kt - Central Coordination System

The ToolHub serves as the central coordination point for all director modules:

- **Director Management**: Register, unregister, and manage director lifecycles
- **Security Aggregation**: Collect and aggregate security reports from all directors  
- **Configuration**: Centralized configuration management
- **Event Hooks**: Lifecycle event management and notifications
- **Thread Safety**: Concurrent access support for multi-threaded environments

**Key Methods:**
```kotlin
// Register a director
toolHub.registerDirector("permissions", PermissionsDirector())

// Execute comprehensive security check
val report = toolHub.executeSecurityCheck()

// Configuration management
toolHub.setConfig("memory.maxHeapUsagePercent", 85)
val config = toolHub.getConfig("memory.maxHeapUsagePercent")

// Lifecycle management
toolHub.startup()  // Initialize all directors
toolHub.shutdown() // Cleanup all directors
```

## Director Modules

### 1. PermissionsDirector.kt - File System Security

Monitors and enforces proper file system permissions to prevent unauthorized access and privilege escalation.

**Features:**
- Critical file permission monitoring
- World-writable file detection
- SUID/SGID binary tracking
- Automatic permission remediation
- Configurable permission rules

**Example Usage:**
```kotlin
val director = PermissionsDirector()
toolHub.registerDirector("permissions", director)

// Add critical paths
director.addCriticalPath("/etc/sensitive-config")

// Set permission rules
director.setPermissionRule("/app/data", "750")

// Fix permissions
director.fixPermissions("/compromised/file")
```

### 2. SymlinkDirector.kt - Symlink Attack Prevention

Provides comprehensive protection against symlink attacks, directory traversal, and poison pill vulnerabilities.

**Features:**
- Malicious symlink detection
- Directory traversal prevention
- Symlink loop detection
- Poison pill file identification  
- Symlink depth limitation
- Configurable allowed targets

**Example Usage:**
```kotlin
val director = SymlinkDirector()
toolHub.registerDirector("symlink", director)

// Validate a symlink
val result = director.validateSymlink("/suspicious/link")
if (!result.isValid) {
    println("Symlink is malicious: ${result.reason}")
}

// Add protected paths
director.addProtectedPath("/critical/system/files")
```

### 3. FileSecurityDirector.py - File Integrity & Security

Comprehensive file security monitoring including integrity checks, malware detection, and suspicious file monitoring.

**Features:**
- File integrity verification (SHA256 hashing)
- Malware pattern detection
- Suspicious file identification
- Hidden file monitoring
- Automatic file quarantine
- Dangerous permission detection

**Example Usage:**
```python
from directors.FileSecurityDirector import FileSecurityDirector

director = FileSecurityDirector()
director.initialize(hub)

# Add critical files
director.add_critical_file("/etc/passwd")

# Perform security check
result = director.perform_security_check()

# Quarantine suspicious file
director.quarantine_file("/tmp/suspicious.exe", "Malware detected")
```

### 4. MemoryDirector.kt - Memory Management & Cleanup

Advanced memory management with leak detection, pressure monitoring, and automatic cleanup capabilities.

**Features:**
- Heap and non-heap memory monitoring
- Memory leak detection algorithms
- Memory pool monitoring
- Automatic garbage collection optimization
- Memory pressure trend analysis
- Configurable thresholds and cleanup

**Example Usage:**
```kotlin
val director = MemoryDirector()
toolHub.registerDirector("memory", director)

// Get current memory status
val status = director.getMemoryStatus()
if (status.isUnderPressure) {
    // Force cleanup
    val result = director.forceCleanup()
    println("Freed ${result.heapFreedMB}MB")
}

// Track object allocations
director.trackAllocation("LargeDataStructure", 50 * 1024 * 1024)
```

## Configuration System

### directors.yaml - Centralized Configuration

The configuration system provides flexible, hierarchical configuration management:

```yaml
# Example configuration
toolhub:
  security_check_interval: 300
  log_level: INFO

permissions:
  rules:
    "/etc/passwd": "644"
    "/etc/shadow": "600"
  auto_fix_permissions: false

memory:
  maxHeapUsagePercent: 85
  cleanupIntervalMinutes: 5
  
# Environment profiles
profiles:
  production:
    memory:
      maxHeapUsagePercent: 80
    security:
      auto_remediation: true
      
  hardened:
    security:
      default_deny: true
      emergency_shutdown: true
```

## Integration Examples

### Android Integration

The Android integration provides mobile-specific security monitoring and resource management:

```kotlin
// Quick setup for Android AI agent
val context = MyAndroidContext()
val integration = AndroidIntegrationHelper.setupQuickIntegration(context)

// Perform Android-specific security check
val report = integration.performAndroidSecurityCheck()

// Monitor app data directory
val dataReport = integration.monitorAppDataDirectory(context)

// Optimize memory for mobile
val memResult = integration.optimizeAndroidMemory(context)
```

**Key Features:**
- Device root detection
- App data directory monitoring  
- Android permission management
- Mobile-optimized memory management
- Security policy enforcement

### Python Integration

The Python integration enables comprehensive security for Python-based AI agents:

```python
from integration.PythonAgentIntegration import create_hardened_integration

# Create hardened Python integration
integration = create_hardened_integration()

if integration.initialize():
    # Perform security check
    result = integration.perform_security_check()
    
    # Sandbox code execution
    if integration.config.sandbox_mode:
        result = integration.sandbox_eval("safe_calculation()")
    
    # Monitor and cleanup
    integration.start_monitoring()
    integration.cleanup_resources()
```

**Key Features:**
- Sandboxed code execution
- Module import restrictions
- Memory limit enforcement
- File system access control
- Background security monitoring

## Security Levels

The system supports multiple security levels for different environments:

### Minimal Security
- Basic file monitoring
- Standard memory management
- Minimal restrictions

### Standard Security  
- Comprehensive file security
- Module import validation
- Memory optimization
- Symlink protection

### Hardened Security
- Strict sandboxing
- Aggressive access controls
- Emergency shutdown capabilities
- Maximum security policies

## Usage Examples

### Basic Setup

```kotlin
// Initialize ToolHub
val toolHub = ToolHub.getInstance()

// Register directors
toolHub.registerDirector("permissions", PermissionsDirector())
toolHub.registerDirector("symlink", SymlinkDirector())
toolHub.registerDirector("memory", MemoryDirector())

// Start the system
toolHub.startup()

// Perform comprehensive security check
val report = toolHub.executeSecurityCheck()
println(report.toString())

// Shutdown
toolHub.shutdown()
```

### Python Agent with File Security

```python
from integration.PythonAgentIntegration import PythonAgentIntegration, PythonAgentConfig

config = PythonAgentConfig(
    security_level=PythonSecurityLevel.STANDARD,
    max_memory_mb=512,
    sandbox_mode=True,
    allowed_modules=['numpy', 'pandas', 'sklearn']
)

integration = PythonAgentIntegration(config)
integration.initialize()

# Register security event handlers
integration.register_hook('file_quarantined', 
    lambda file_path, reason: print(f"Quarantined: {file_path} - {reason}"))

# Start monitoring
integration.start_monitoring()
```

### Configuration-Driven Setup

```python
import yaml

# Load configuration
with open('config/directors.yaml', 'r') as f:
    config = yaml.safe_load(f)

# Apply configuration to directors
toolhub.apply_config(config)

# Use profile-specific settings
toolhub.apply_profile('production')
```

## Monitoring and Alerts

### Security Reports

The system generates comprehensive security reports:

```
=== Security Report ===
[PermissionsDirector] PASS: All permission checks passed  
[SymlinkDirector] WARN: Found 2 potentially malicious symlinks
[FileSecurityDirector] PASS: All file security checks passed
[MemoryDirector] WARN: Memory usage high: 87%
```

### Event Hooks

Register hooks for security events:

```kotlin
toolHub.registerHook("security_violation") {
    // Handle security violation
    sendAlert("Security violation detected")
}

toolHub.registerHook("memory_warning") {
    // Handle memory pressure
    performEmergencyCleanup()
}
```

## Best Practices

### 1. Layered Security
- Use multiple directors for comprehensive coverage
- Configure appropriate security levels for your environment
- Implement defense in depth

### 2. Configuration Management
- Use environment-specific configurations
- Regularly review and update security policies
- Test configuration changes in development

### 3. Monitoring and Response
- Enable continuous monitoring
- Set up appropriate alerting
- Have incident response procedures

### 4. Performance Considerations
- Configure appropriate scan limits
- Monitor resource usage
- Use background monitoring threads

## Extending the System

### Creating Custom Directors

```kotlin
class CustomSecurityDirector : Director() {
    override fun getName(): String = "CustomSecurityDirector"
    
    override fun initialize(hub: ToolHub) {
        // Custom initialization
    }
    
    override fun performSecurityCheck(): DirectorResult {
        // Custom security logic
        return DirectorResult(Status.PASS, "Custom check passed")
    }
}

// Register custom director
toolHub.registerDirector("custom", CustomSecurityDirector())
```

### Adding New Integration Points

```python
class CustomIntegration:
    def __init__(self):
        self.toolhub = ToolHub()
        
    def integrate_with_framework(self, framework):
        # Custom integration logic
        pass
```

## Dependencies

### Kotlin Components
- Kotlin standard library
- Java management interfaces (`java.lang.management`)
- Java NIO file system APIs

### Python Components  
- Python 3.7+ standard library
- Optional: `psutil` for enhanced memory monitoring
- Optional: `pyyaml` for configuration management

## License

This project is part of the dolphin-mistral-codespace repository. See the repository's license for terms of use.

## Contributing

1. Follow the modular design principles
2. Ensure proper error handling and logging
3. Add comprehensive tests for new features
4. Document new director modules and integration points
5. Maintain backward compatibility with existing configurations

## Support

For questions, issues, or contributions, please refer to the main dolphin-mistral-codespace repository documentation and issue tracker.