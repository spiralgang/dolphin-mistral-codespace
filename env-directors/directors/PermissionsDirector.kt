package dolphin.mistral.envdirectors.directors

import dolphin.mistral.envdirectors.Director
import dolphin.mistral.envdirectors.DirectorResult
import dolphin.mistral.envdirectors.ToolHub
import java.io.File
import java.nio.file.Files
import java.nio.file.Paths
import java.nio.file.attribute.PosixFilePermission

/**
 * PermissionsDirector manages file system permissions and access control
 * 
 * This director monitors and enforces proper file permissions to prevent
 * unauthorized access, privilege escalation, and security vulnerabilities.
 */
class PermissionsDirector : Director() {
    
    private lateinit var hub: ToolHub
    private val criticalPaths = mutableListOf<String>()
    private val permissionRules = mutableMapOf<String, Set<PosixFilePermission>>()
    
    override fun getName(): String = "PermissionsDirector"
    
    override fun initialize(hub: ToolHub) {
        this.hub = hub
        
        // Load default critical paths
        criticalPaths.addAll(listOf(
            "/etc/passwd",
            "/etc/shadow", 
            "/etc/sudoers",
            "/root",
            "/home",
            System.getProperty("user.home")
        ))
        
        // Load permission rules from config if available
        val config = hub.getConfig("permissions.rules") as? Map<String, String>
        config?.forEach { (path, perms) ->
            permissionRules[path] = parsePermissions(perms)
        }
        
        println("[PermissionsDirector] Initialized with ${criticalPaths.size} critical paths")
    }
    
    override fun performSecurityCheck(): DirectorResult {
        val issues = mutableListOf<String>()
        val details = mutableMapOf<String, Any>()
        
        try {
            // Check critical file permissions
            val permissionIssues = checkCriticalPathPermissions()
            if (permissionIssues.isNotEmpty()) {
                issues.addAll(permissionIssues)
            }
            
            // Check for world-writable files
            val worldWritableFiles = findWorldWritableFiles()
            if (worldWritableFiles.isNotEmpty()) {
                issues.add("Found ${worldWritableFiles.size} world-writable files")
                details["worldWritableFiles"] = worldWritableFiles.take(10) // Limit output
            }
            
            // Check for SUID/SGID binaries
            val suidFiles = findSuidFiles()
            if (suidFiles.isNotEmpty()) {
                details["suidFiles"] = suidFiles.take(10)
            }
            
            details["criticalPathsChecked"] = criticalPaths.size
            details["rulesApplied"] = permissionRules.size
            
            return when {
                issues.isEmpty() -> DirectorResult(
                    DirectorResult.Status.PASS, 
                    "All permission checks passed",
                    details
                )
                issues.size < 5 -> DirectorResult(
                    DirectorResult.Status.WARN,
                    "Minor permission issues found: ${issues.joinToString("; ")}",
                    details
                )
                else -> DirectorResult(
                    DirectorResult.Status.FAIL,
                    "Critical permission vulnerabilities detected: ${issues.take(3).joinToString("; ")}",
                    details
                )
            }
            
        } catch (e: Exception) {
            return DirectorResult(
                DirectorResult.Status.ERROR,
                "Permission check failed: ${e.message}",
                mapOf("exception" to e.javaClass.simpleName)
            )
        }
    }
    
    /**
     * Add a critical path to monitor
     */
    fun addCriticalPath(path: String) {
        if (path !in criticalPaths) {
            criticalPaths.add(path)
        }
    }
    
    /**
     * Set permission rule for a path
     */
    fun setPermissionRule(path: String, permissions: String) {
        permissionRules[path] = parsePermissions(permissions)
    }
    
    /**
     * Fix permissions for a specific file or directory
     */
    fun fixPermissions(path: String): Boolean {
        return try {
            val file = File(path)
            if (!file.exists()) {
                return false
            }
            
            val permissions = permissionRules[path]
            if (permissions != null) {
                Files.setPosixFilePermissions(Paths.get(path), permissions)
                println("[PermissionsDirector] Fixed permissions for $path")
                true
            } else {
                // Apply default secure permissions
                val defaultPerms = when {
                    file.isDirectory -> setOf(
                        PosixFilePermission.OWNER_READ,
                        PosixFilePermission.OWNER_WRITE,
                        PosixFilePermission.OWNER_EXECUTE
                    )
                    else -> setOf(
                        PosixFilePermission.OWNER_READ,
                        PosixFilePermission.OWNER_WRITE
                    )
                }
                Files.setPosixFilePermissions(Paths.get(path), defaultPerms)
                true
            }
        } catch (e: Exception) {
            println("[PermissionsDirector] Failed to fix permissions for $path: ${e.message}")
            false
        }
    }
    
    private fun checkCriticalPathPermissions(): List<String> {
        val issues = mutableListOf<String>()
        
        criticalPaths.forEach { path ->
            try {
                val file = File(path)
                if (file.exists()) {
                    val perms = Files.getPosixFilePermissions(Paths.get(path))
                    
                    // Check for dangerous permissions
                    if (PosixFilePermission.OTHERS_WRITE in perms) {
                        issues.add("$path is world-writable")
                    }
                    
                    if (PosixFilePermission.OTHERS_READ in perms && path.contains("shadow")) {
                        issues.add("$path is world-readable")
                    }
                    
                    // Check against configured rules
                    permissionRules[path]?.let { expectedPerms ->
                        if (perms != expectedPerms) {
                            issues.add("$path has incorrect permissions")
                        }
                    }
                }
            } catch (e: Exception) {
                issues.add("Failed to check permissions for $path: ${e.message}")
            }
        }
        
        return issues
    }
    
    private fun findWorldWritableFiles(): List<String> {
        val worldWritable = mutableListOf<String>()
        
        try {
            // Check common directories for world-writable files
            val searchDirs = listOf("/tmp", "/var/tmp", System.getProperty("user.home"))
            
            searchDirs.forEach { dir ->
                val directory = File(dir)
                if (directory.exists() && directory.isDirectory) {
                    directory.walk()
                        .take(1000) // Limit search to prevent performance issues
                        .filter { it.isFile }
                        .forEach { file ->
                            try {
                                val perms = Files.getPosixFilePermissions(file.toPath())
                                if (PosixFilePermission.OTHERS_WRITE in perms) {
                                    worldWritable.add(file.absolutePath)
                                }
                            } catch (e: Exception) {
                                // Skip files we can't check
                            }
                        }
                }
            }
        } catch (e: Exception) {
            println("[PermissionsDirector] Error searching for world-writable files: ${e.message}")
        }
        
        return worldWritable
    }
    
    private fun findSuidFiles(): List<String> {
        // This is a simplified implementation
        // In a real implementation, you'd use system commands or native calls
        val suidFiles = mutableListOf<String>()
        
        try {
            // Common locations for SUID binaries
            val commonSuidPaths = listOf(
                "/usr/bin/sudo",
                "/usr/bin/su", 
                "/bin/ping",
                "/usr/bin/passwd"
            )
            
            commonSuidPaths.forEach { path ->
                val file = File(path)
                if (file.exists()) {
                    // Note: Java doesn't have direct SUID detection
                    // This would need native implementation or system command
                    suidFiles.add(path)
                }
            }
        } catch (e: Exception) {
            println("[PermissionsDirector] Error checking SUID files: ${e.message}")
        }
        
        return suidFiles
    }
    
    private fun parsePermissions(permString: String): Set<PosixFilePermission> {
        val permissions = mutableSetOf<PosixFilePermission>()
        
        // Simple octal parsing (e.g., "755" or "rwxr-xr-x")
        if (permString.matches(Regex("\\d{3}"))) {
            val octal = permString.toInt(8)
            
            // Owner permissions
            if ((octal and 0o400) != 0) permissions.add(PosixFilePermission.OWNER_READ)
            if ((octal and 0o200) != 0) permissions.add(PosixFilePermission.OWNER_WRITE)
            if ((octal and 0o100) != 0) permissions.add(PosixFilePermission.OWNER_EXECUTE)
            
            // Group permissions
            if ((octal and 0o040) != 0) permissions.add(PosixFilePermission.GROUP_READ)
            if ((octal and 0o020) != 0) permissions.add(PosixFilePermission.GROUP_WRITE)
            if ((octal and 0o010) != 0) permissions.add(PosixFilePermission.GROUP_EXECUTE)
            
            // Others permissions
            if ((octal and 0o004) != 0) permissions.add(PosixFilePermission.OTHERS_READ)
            if ((octal and 0o002) != 0) permissions.add(PosixFilePermission.OTHERS_WRITE)
            if ((octal and 0o001) != 0) permissions.add(PosixFilePermission.OTHERS_EXECUTE)
        }
        
        return permissions
    }
}