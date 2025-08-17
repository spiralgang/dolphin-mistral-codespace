package dolphin.mistral.envdirectors.directors

import dolphin.mistral.envdirectors.Director
import dolphin.mistral.envdirectors.DirectorResult
import dolphin.mistral.envdirectors.ToolHub
import java.io.File
import java.nio.file.Files
import java.nio.file.Path
import java.nio.file.Paths

/**
 * SymlinkDirector provides defense against symlink attacks and poison pill vulnerabilities
 * 
 * This director monitors symbolic links, prevents directory traversal attacks,
 * and protects against malicious symlink-based exploits that could compromise
 * file system integrity or bypass security controls.
 */
class SymlinkDirector : Director() {
    
    private lateinit var hub: ToolHub
    private val protectedPaths = mutableSetOf<String>()
    private val suspiciousSymlinks = mutableListOf<String>()
    private val allowedTargets = mutableSetOf<String>()
    private var maxSymlinkDepth = 5
    
    override fun getName(): String = "SymlinkDirector"
    
    override fun initialize(hub: ToolHub) {
        this.hub = hub
        
        // Initialize protected paths
        protectedPaths.addAll(listOf(
            "/etc",
            "/root", 
            "/usr/bin",
            "/usr/sbin",
            System.getProperty("user.home")
        ))
        
        // Load configuration
        val config = hub.getConfig("symlink.maxDepth") as? Int
        if (config != null) {
            maxSymlinkDepth = config
        }
        
        val allowedTargetConfig = hub.getConfig("symlink.allowedTargets") as? List<String>
        if (allowedTargetConfig != null) {
            allowedTargets.addAll(allowedTargetConfig)
        }
        
        println("[SymlinkDirector] Initialized with ${protectedPaths.size} protected paths")
    }
    
    override fun performSecurityCheck(): DirectorResult {
        val issues = mutableListOf<String>()
        val details = mutableMapOf<String, Any>()
        
        try {
            // Clear previous results
            suspiciousSymlinks.clear()
            
            // Check for malicious symlinks
            val maliciousLinks = scanForMaliciousSymlinks()
            if (maliciousLinks.isNotEmpty()) {
                issues.add("Found ${maliciousLinks.size} potentially malicious symlinks")
                details["maliciousSymlinks"] = maliciousLinks.take(10)
            }
            
            // Check for symlink loops
            val loops = detectSymlinkLoops()
            if (loops.isNotEmpty()) {
                issues.add("Detected ${loops.size} symlink loops")
                details["symlinkLoops"] = loops
            }
            
            // Check for excessive symlink depth
            val deepLinks = findExcessivelyDeepSymlinks()
            if (deepLinks.isNotEmpty()) {
                issues.add("Found ${deepLinks.size} symlinks exceeding depth limit")
                details["deepSymlinks"] = deepLinks.take(5)
            }
            
            // Check for poison pill files
            val poisonPills = detectPoisonPillFiles()
            if (poisonPills.isNotEmpty()) {
                issues.add("Detected ${poisonPills.size} potential poison pill files")
                details["poisonPills"] = poisonPills.take(5)
            }
            
            details["protectedPathsChecked"] = protectedPaths.size
            details["maxDepth"] = maxSymlinkDepth
            
            return when {
                issues.isEmpty() -> DirectorResult(
                    DirectorResult.Status.PASS,
                    "All symlink security checks passed",
                    details
                )
                issues.any { it.contains("malicious") || it.contains("poison") } -> DirectorResult(
                    DirectorResult.Status.FAIL,
                    "Critical symlink security threats detected: ${issues.joinToString("; ")}",
                    details
                )
                else -> DirectorResult(
                    DirectorResult.Status.WARN,
                    "Symlink issues found: ${issues.joinToString("; ")}",
                    details
                )
            }
            
        } catch (e: Exception) {
            return DirectorResult(
                DirectorResult.Status.ERROR,
                "Symlink security check failed: ${e.message}",
                mapOf("exception" to e.javaClass.simpleName)
            )
        }
    }
    
    /**
     * Add a path to protect from symlink attacks
     */
    fun addProtectedPath(path: String) {
        protectedPaths.add(path)
    }
    
    /**
     * Remove a protected path
     */
    fun removeProtectedPath(path: String) {
        protectedPaths.remove(path)
    }
    
    /**
     * Add an allowed symlink target pattern
     */
    fun addAllowedTarget(pattern: String) {
        allowedTargets.add(pattern)
    }
    
    /**
     * Validate a symlink path for security
     */
    fun validateSymlink(symlinkPath: String): ValidationResult {
        try {
            val path = Paths.get(symlinkPath)
            
            if (!Files.isSymbolicLink(path)) {
                return ValidationResult(false, "Not a symbolic link")
            }
            
            val target = Files.readSymbolicLink(path)
            val resolvedTarget = path.resolveSibling(target).normalize()
            
            // Check for directory traversal
            if (containsDirectoryTraversal(target.toString())) {
                return ValidationResult(false, "Contains directory traversal sequence")
            }
            
            // Check if target is in protected area
            if (isTargetingProtectedPath(resolvedTarget.toString())) {
                return ValidationResult(false, "Targets protected path")
            }
            
            // Check symlink depth
            val depth = calculateSymlinkDepth(path)
            if (depth > maxSymlinkDepth) {
                return ValidationResult(false, "Exceeds maximum symlink depth ($depth > $maxSymlinkDepth)")
            }
            
            // Check against allowed targets
            if (allowedTargets.isNotEmpty() && !isTargetAllowed(resolvedTarget.toString())) {
                return ValidationResult(false, "Target not in allowed list")
            }
            
            return ValidationResult(true, "Symlink is safe")
            
        } catch (e: Exception) {
            return ValidationResult(false, "Validation error: ${e.message}")
        }
    }
    
    /**
     * Remove a malicious symlink safely
     */
    fun removeMaliciousSymlink(symlinkPath: String): Boolean {
        return try {
            val path = Paths.get(symlinkPath)
            if (Files.isSymbolicLink(path)) {
                Files.delete(path)
                println("[SymlinkDirector] Removed malicious symlink: $symlinkPath")
                true
            } else {
                false
            }
        } catch (e: Exception) {
            println("[SymlinkDirector] Failed to remove symlink $symlinkPath: ${e.message}")
            false
        }
    }
    
    private fun scanForMaliciousSymlinks(): List<String> {
        val maliciousLinks = mutableListOf<String>()
        
        try {
            // Search in common directories
            val searchDirs = listOf(
                System.getProperty("java.io.tmpdir"),
                System.getProperty("user.home"),
                "/tmp",
                "/var/tmp"
            )
            
            searchDirs.forEach { dirPath ->
                val dir = File(dirPath)
                if (dir.exists() && dir.isDirectory) {
                    dir.walk()
                        .take(1000) // Limit for performance
                        .filter { Files.isSymbolicLink(it.toPath()) }
                        .forEach { symlink ->
                            val validation = validateSymlink(symlink.absolutePath)
                            if (!validation.isValid) {
                                maliciousLinks.add("${symlink.absolutePath}: ${validation.reason}")
                                suspiciousSymlinks.add(symlink.absolutePath)
                            }
                        }
                }
            }
        } catch (e: Exception) {
            println("[SymlinkDirector] Error scanning for malicious symlinks: ${e.message}")
        }
        
        return maliciousLinks
    }
    
    private fun detectSymlinkLoops(): List<String> {
        val loops = mutableListOf<String>()
        val visited = mutableSetOf<String>()
        
        suspiciousSymlinks.forEach { symlinkPath ->
            try {
                val path = Paths.get(symlinkPath)
                if (Files.isSymbolicLink(path)) {
                    if (hasSymlinkLoop(path, visited)) {
                        loops.add(symlinkPath)
                    }
                }
            } catch (e: Exception) {
                // Skip problematic symlinks
            }
        }
        
        return loops
    }
    
    private fun findExcessivelyDeepSymlinks(): List<String> {
        val deepLinks = mutableListOf<String>()
        
        suspiciousSymlinks.forEach { symlinkPath ->
            try {
                val path = Paths.get(symlinkPath)
                val depth = calculateSymlinkDepth(path)
                if (depth > maxSymlinkDepth) {
                    deepLinks.add("$symlinkPath (depth: $depth)")
                }
            } catch (e: Exception) {
                // Skip problematic symlinks
            }
        }
        
        return deepLinks
    }
    
    private fun detectPoisonPillFiles(): List<String> {
        val poisonPills = mutableListOf<String>()
        
        // Look for files with suspicious names that might be poison pills
        val suspiciousPatterns = listOf(
            Regex(".*\\.\\.(\\\\|/).*"), // Directory traversal
            Regex(".*[<>:\"|?*].*"),     // Invalid filename characters
            Regex(".*\\x00.*"),          // Null byte injection
            Regex(".*(CON|PRN|AUX|NUL|COM[1-9]|LPT[1-9])(\\..*)?", RegexOption.IGNORE_CASE) // Windows reserved names
        )
        
        try {
            val searchDirs = listOf(
                System.getProperty("java.io.tmpdir"),
                System.getProperty("user.home"),
                "/tmp"
            )
            
            searchDirs.forEach { dirPath ->
                val dir = File(dirPath)
                if (dir.exists() && dir.isDirectory) {
                    dir.walk()
                        .take(500) // Limit for performance
                        .filter { it.isFile }
                        .forEach { file ->
                            val fileName = file.name
                            if (suspiciousPatterns.any { it.matches(fileName) }) {
                                poisonPills.add(file.absolutePath)
                            }
                        }
                }
            }
        } catch (e: Exception) {
            println("[SymlinkDirector] Error detecting poison pills: ${e.message}")
        }
        
        return poisonPills
    }
    
    private fun containsDirectoryTraversal(path: String): Boolean {
        return path.contains("../") || path.contains("..\\") || 
               path.contains("./") || path.contains(".\\")
    }
    
    private fun isTargetingProtectedPath(targetPath: String): Boolean {
        return protectedPaths.any { protectedPath ->
            targetPath.startsWith(protectedPath) || 
            targetPath.contains(protectedPath)
        }
    }
    
    private fun isTargetAllowed(targetPath: String): Boolean {
        if (allowedTargets.isEmpty()) return true
        
        return allowedTargets.any { pattern ->
            targetPath.matches(Regex(pattern)) || targetPath.startsWith(pattern)
        }
    }
    
    private fun calculateSymlinkDepth(path: Path): Int {
        var depth = 0
        var currentPath = path
        val visited = mutableSetOf<Path>()
        
        while (Files.isSymbolicLink(currentPath) && depth < 20) { // Max 20 to prevent infinite loops
            if (currentPath in visited) break // Loop detected
            visited.add(currentPath)
            
            try {
                val target = Files.readSymbolicLink(currentPath)
                currentPath = if (target.isAbsolute) {
                    target
                } else {
                    currentPath.resolveSibling(target).normalize()
                }
                depth++
            } catch (e: Exception) {
                break
            }
        }
        
        return depth
    }
    
    private fun hasSymlinkLoop(path: Path, globalVisited: MutableSet<String>): Boolean {
        val localVisited = mutableSetOf<Path>()
        var currentPath = path
        
        while (Files.isSymbolicLink(currentPath)) {
            if (currentPath in localVisited) {
                return true // Loop detected
            }
            localVisited.add(currentPath)
            
            try {
                val target = Files.readSymbolicLink(currentPath)
                currentPath = if (target.isAbsolute) {
                    target
                } else {
                    currentPath.resolveSibling(target).normalize()
                }
            } catch (e: Exception) {
                break
            }
        }
        
        return false
    }
    
    /**
     * Result of symlink validation
     */
    data class ValidationResult(
        val isValid: Boolean,
        val reason: String
    )
}