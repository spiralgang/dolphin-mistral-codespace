# Environment Directors - Modular Security System

A comprehensive, modular security and environment management system designed to provide robust protection across multiple platforms and environments. The system uses a director-based architecture where specialized components handle different aspects of security monitoring and enforcement.

## Architecture Overview

The Environment Directors system follows a modular, plugin-based architecture with the following core components:

- **ToolHub**: Central coordination and API hub
- **Directors**: Specialized security modules for different domains
- **Integration Layer**: Platform-specific integrations (Android, Python, etc.)
- **Configuration**: Centralized YAML-based configuration management

## Core Components

### ToolHub.kt
The central hub that coordinates all security directors and provides a unified API.

**Key Features:**
- Centralized director registration and management
- Asynchronous security check execution
- Configuration management and hot-reloading
- Comprehensive logging and metrics collection
- Health monitoring for all registered directors

**Usage:**
```kotlin
val toolHub = ToolHub.getInstance()
toolHub.initialize("/path/to/config/directors.yaml")

val context = SecurityContext(
    operation = "file_access",
    target = "/sensitive/file.txt",
    user = "john_doe"
)

val report = toolHub.performSecurityCheck(context).get()
println("Security check result: ${report.overallStatus}")
```

### Directors

#### PermissionsDirector.kt
Handles role-based access control, user authentication, and permission management.

**Features:**
- Role-based permission system with hierarchical inheritance
- Permission caching with configurable TTL
- Support for wildcard permissions and explicit denials
- Strict mode for enhanced security
- Integration with existing authentication systems

**Configuration:**
```yaml
permissions:
  enabled: true
  strict_mode: false
  cache_ttl: 300
  roles:
    admin:
      permissions: ["*"]
    user:
      permissions: ["file_access", "file_write"]
      denials: ["system_command"]
```

#### SymlinkDirector.kt
Provides comprehensive symlink security validation and attack prevention.

**Features:**
- Symlink loop detection and prevention
- Path traversal protection
- Configurable allowed target directories
- Real-time symlink resolution with caching
- Automatic quarantine of dangerous symlinks

**Security Checks:**
- Validates symlink targets are within allowed directories
- Detects potential symlink loops before creation
- Monitors symlink resolution depth
- Caches resolution results for performance

#### FileSecurityDirector.py
Python-based file security scanner with advanced threat detection.

**Features:**
- Multi-signature malware detection
- Poison pill pattern recognition
- Script injection detection
- File type verification and disguise detection
- Automatic quarantine system
- Comprehensive file metadata analysis

**Detection Capabilities:**
- Known malware signatures
- Suspicious script patterns
- Hidden executables
- Oversized files
- Poison pill commands
- Script injection attempts

#### MemoryDirector.kt
Real-time memory monitoring and leak detection system.

**Features:**
- Continuous memory usage monitoring
- Memory leak detection with pattern analysis
- Automatic garbage collection triggering
- Process memory allocation tracking
- Memory limit enforcement
- Historical usage analysis

**Monitoring:**
- Heap and non-heap memory usage
- Garbage collection statistics
- Memory allocation requests validation
- Process-specific memory tracking

## Configuration System

The system uses a centralized YAML configuration file (`directors.yaml`) that controls all aspects of the security system:

### Global Settings
```yaml
global:
  environment: "production"
  log_level: "INFO"
  enable_metrics: true
  max_concurrent_checks: 10
```

### Director-Specific Configuration
Each director has its own configuration section with specific parameters:

```yaml
permissions:
  enabled: true
  strict_mode: false
  cache_ttl: 300

symlink:
  enabled: true
  max_depth: 10
  allowed_targets: ["/tmp", "/var/tmp"]

file_security:
  enabled: true
  quarantine_path: "/tmp/quarantine"
  max_file_size_mb: 100

memory:
  enabled: true
  threshold_mb: 1024
  check_interval: 60
```

## Integration Layer

### AndroidAgentIntegration.kt
Provides seamless integration with Android devices and applications.

**Features:**
- Secure HTTP API communication
- Device registration and authentication
- Remote command execution
- Health monitoring and status reporting
- Configuration synchronization

**API Endpoints:**
- `/register` - Device registration
- `/status` - Health and status check
- `/scan` - Remote security scanning
- `/command` - Remote command execution
- `/config` - Configuration updates

### PythonAgentIntegration.py
Python-specific security services and integration capabilities.

**Features:**
- Python environment security scanning
- Import hook for monitoring module loading
- Package vulnerability checking
- Process and network monitoring
- Event-driven security notifications

**Security Services:**
- Code scanning for dangerous patterns
- PIP package vulnerability assessment
- Import security validation
- Python process monitoring
- Network security checking

## Installation and Setup

### Prerequisites
- Java 8+ (for Kotlin components)
- Python 3.8+ (for Python components)
- YAML configuration files

### Basic Setup
1. Clone the repository and navigate to the `env-directors/` directory
2. Configure your settings in `config/directors.yaml`
3. Initialize the ToolHub:

```kotlin
val toolHub = ToolHub.getInstance()
val initialized = toolHub.initialize("config/directors.yaml").get()
if (initialized) {
    println("Security system active")
}
```

### Python Integration Setup
```python
from integration.PythonAgentIntegration import PythonAgentIntegration

integration = PythonAgentIntegration()
config = {
    "enabled": True,
    "auto_import": True,
    "file_monitoring": {"enabled": True}
}

if integration.initialize(config):
    print("Python integration active")
```

## Usage Examples

### Basic Security Check
```kotlin
val context = SecurityContext(
    operation = "file_write",
    target = "/tmp/newfile.txt",
    user = "alice",
    metadata = mapOf("file_size" to 1024)
)

val result = toolHub.performSecurityCheck(context).get()
when (result.overallStatus) {
    SecurityLevel.INFO -> println("Operation approved")
    SecurityLevel.WARNING -> println("Warning: ${result.results}")
    SecurityLevel.ERROR -> println("Operation denied: ${result.results}")
    SecurityLevel.CRITICAL -> println("Critical security violation!")
}
```

### File Security Scanning
```python
from directors.FileSecurityDirector import FileSecurityDirector

director = FileSecurityDirector()
director.initialize({
    "enabled": True,
    "quarantine_path": "/tmp/quarantine",
    "max_file_size_mb": 100
})

context = SecurityContext(
    operation="file_scan",
    target="/path/to/suspicious/file.exe"
)

result = director.execute(context)
print(f"Scan result: {result.message}")
```

### Memory Monitoring
```kotlin
val memoryDirector = toolHub.getDirector("memory", MemoryDirector::class)
val stats = memoryDirector?.getMemoryStats()
println("Current memory usage: ${stats?.get("current_heap_used_mb")}MB")
```

### Permission Checking
```kotlin
val permissionDirector = toolHub.getDirector("permissions", PermissionsDirector::class)
val result = permissionDirector?.checkPermission("john", "file_delete", "/important/file.txt")
when (result?.status) {
    PermissionStatus.GRANTED -> println("Permission granted")
    PermissionStatus.DENIED -> println("Permission denied: ${result.reason}")
    PermissionStatus.UNKNOWN -> println("Permission unknown")
}
```

## Security Best Practices

### Configuration Security
- Store configuration files with restricted permissions (600)
- Use environment variables for sensitive settings
- Regularly rotate authentication tokens
- Enable audit logging for all security operations

### Director Configuration
- Enable strict mode in production environments
- Configure appropriate cache TTL values
- Set up proper quarantine directories with limited access
- Monitor memory thresholds based on system capacity

### Integration Security
- Use HTTPS for all network communications
- Implement proper authentication and authorization
- Validate all input from external integrations
- Log all security-relevant events

## Monitoring and Alerting

The system provides comprehensive monitoring capabilities:

### Health Checks
- Each director implements health checking
- Automatic recovery from transient failures
- Centralized health status reporting
- Integration with external monitoring systems

### Metrics Collection
- Performance metrics for all operations
- Security event statistics
- Resource usage monitoring
- Historical trend analysis

### Alerting
- Configurable alert thresholds
- Multiple notification channels (email, Slack, webhook)
- Escalation policies for critical issues
- Integration with existing monitoring infrastructure

## Extension Points

### Custom Directors
Implement the `Director` interface to create custom security modules:

```kotlin
class CustomDirector : Director {
    override fun getName(): String = "custom"
    override fun initialize(config: Map<String, Any>): Boolean { /* ... */ }
    override fun execute(context: SecurityContext): DirectorResult { /* ... */ }
    // ... other methods
}
```

### Event Handlers
Register custom event handlers for security events:

```python
def custom_handler(event: PythonSecurityEvent):
    if event.severity == SecurityLevel.CRITICAL:
        # Send alert, quarantine, etc.
        pass

integration.register_event_handler("malware_detected", custom_handler)
```

### Custom Integrations
Create platform-specific integrations following the existing patterns:

```kotlin
class CustomIntegration {
    fun sendSecurityEvent(event: SecurityEvent): Boolean { /* ... */ }
    fun requestSecurityScan(request: ScanRequest): ApiResponse { /* ... */ }
}
```

## Troubleshooting

### Common Issues

1. **Director Initialization Failure**
   - Check configuration file syntax
   - Verify file permissions
   - Review log output for specific errors

2. **Permission Denied Errors**
   - Verify user roles are properly configured
   - Check permission cache TTL settings
   - Review strict mode configuration

3. **Memory Issues**
   - Adjust memory thresholds in configuration
   - Enable automatic garbage collection
   - Monitor for memory leaks

4. **Performance Issues**
   - Tune cache TTL values
   - Adjust thread pool sizes
   - Enable batch processing

### Debug Mode
Enable debug mode for detailed logging:

```yaml
global:
  log_level: "DEBUG"

development:
  debug_mode: true
  performance_profiling: true
```

## Contributing

### Code Style
- Follow existing naming conventions
- Add comprehensive documentation
- Include unit tests for new features
- Implement proper error handling

### Adding New Directors
1. Implement the `Director` interface
2. Add configuration schema
3. Include comprehensive tests
4. Update documentation

### Security Considerations
- All contributions undergo security review
- Follow secure coding practices
- Test against known attack vectors
- Document security implications

## License

This project is licensed under the MIT License. See the LICENSE file for details.

## Support

For support and questions:
- Review this documentation
- Check the troubleshooting section
- File issues on the project repository
- Contact the development team

## Changelog

### Version 1.0.0
- Initial release with core director system
- ToolHub central coordination
- Basic permission and file security directors
- Configuration management system
- Android and Python integrations