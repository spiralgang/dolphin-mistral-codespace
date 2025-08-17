package com.spiralgang.dolphin.envdirectors.directors

import com.spiralgang.dolphin.envdirectors.*
import java.io.File
import java.nio.file.*
import java.util.concurrent.ConcurrentHashMap

/**
 * Director responsible for symlink security checks and validation.
 * Prevents symlink attacks, validates symlink targets, and enforces path restrictions.
 */
class SymlinkDirector : Director {
    private var enabled = true
    private var maxDepth = 10
    private var allowedTargets = setOf("/tmp", "/var/tmp")
    private val symlinkCache = ConcurrentHashMap<String, CachedSymlinkInfo>()
    private var lastRun: Long? = null

    companion object {
        private const val CACHE_TTL_MS = 60000L // 1 minute cache
        private const val MAX_CACHE_SIZE = 1000
    }

    override fun getName(): String = "symlink"

    override fun initialize(config: Map<String, Any>): Boolean {
        return try {
            enabled = config["enabled"] as? Boolean ?: true
            maxDepth = (config["max_depth"] as? Number)?.toInt() ?: 10
            
            @Suppress("UNCHECKED_CAST")
            val targets = config["allowed_targets"] as? List<String>
            allowedTargets = targets?.toSet() ?: setOf("/tmp", "/var/tmp")
            
            println("SymlinkDirector initialized - Max depth: $maxDepth, Allowed targets: $allowedTargets")
            true
        } catch (e: Exception) {
            println("Failed to initialize SymlinkDirector: ${e.message}")
            false
        }
    }

    override fun isEnabled(): Boolean = enabled

    override fun isApplicable(context: SecurityContext): Boolean {
        return context.operation in listOf(
            "symlink_create", "symlink_follow", "file_access", 
            "directory_traverse", "path_resolve"
        )
    }

    override fun execute(context: SecurityContext): DirectorResult {
        lastRun = System.currentTimeMillis()
        
        return try {
            when (context.operation) {
                "symlink_create" -> validateSymlinkCreation(context.target, context.metadata)
                "symlink_follow" -> validateSymlinkFollow(context.target)
                "file_access", "directory_traverse", "path_resolve" -> validatePath(context.target)
                else -> DirectorResult(
                    success = true,
                    message = "Operation not applicable to symlink director",
                    level = SecurityLevel.INFO
                )
            }
        } catch (e: Exception) {
            DirectorResult(
                success = false,
                message = "Symlink validation failed: ${e.message}",
                level = SecurityLevel.ERROR
            )
        }
    }

    override fun healthCheck(): Boolean {
        return try {
            enabled && maxDepth > 0 && allowedTargets.isNotEmpty()
        } catch (e: Exception) {
            false
        }
    }

    override fun getLastRunTime(): Long? = lastRun

    /**
     * Validate symlink creation request
     */
    private fun validateSymlinkCreation(linkPath: String, metadata: Map<String, Any>): DirectorResult {
        val targetPath = metadata["target"] as? String
            ?: return DirectorResult(
                success = false,
                message = "No target path specified for symlink creation",
                level = SecurityLevel.ERROR
            )

        val linkFile = File(linkPath)
        val targetFile = File(targetPath)

        // Check if target exists
        if (!targetFile.exists()) {
            return DirectorResult(
                success = false,
                message = "Symlink target does not exist: $targetPath",
                level = SecurityLevel.WARNING,
                details = mapOf("target" to targetPath, "link" to linkPath)
            )
        }

        // Check if target is within allowed directories
        val targetCanonical = try {
            targetFile.canonicalPath
        } catch (e: Exception) {
            return DirectorResult(
                success = false,
                message = "Cannot resolve target canonical path: ${e.message}",
                level = SecurityLevel.ERROR
            )
        }

        val isAllowed = allowedTargets.any { allowed ->
            targetCanonical.startsWith(allowed)
        }

        if (!isAllowed) {
            return DirectorResult(
                success = false,
                message = "Symlink target not in allowed directories: $targetCanonical",
                level = SecurityLevel.CRITICAL,
                details = mapOf(
                    "target" to targetCanonical,
                    "allowed_targets" to allowedTargets
                )
            )
        }

        // Check for potential symlink loops
        val loopCheck = detectSymlinkLoop(linkPath, targetPath)
        if (loopCheck.hasLoop) {
            return DirectorResult(
                success = false,
                message = "Potential symlink loop detected",
                level = SecurityLevel.CRITICAL,
                details = mapOf(
                    "loop_path" to loopCheck.loopPath,
                    "depth" to loopCheck.depth
                )
            )
        }

        return DirectorResult(
            success = true,
            message = "Symlink creation validated successfully",
            level = SecurityLevel.INFO,
            details = mapOf(
                "link" to linkPath,
                "target" to targetCanonical,
                "checks_passed" to listOf("target_exists", "allowed_directory", "no_loops")
            )
        )
    }

    /**
     * Validate symlink following operation
     */
    private fun validateSymlinkFollow(symlinkPath: String): DirectorResult {
        val cacheKey = symlinkPath
        val cached = symlinkCache[cacheKey]
        
        // Return cached result if still valid
        if (cached != null && !cached.isExpired()) {
            return DirectorResult(
                success = cached.isValid,
                message = if (cached.isValid) "Symlink follow allowed (cached)" else "Symlink follow denied (cached)",
                level = if (cached.isValid) SecurityLevel.INFO else SecurityLevel.WARNING,
                details = mapOf("cached" to true, "resolved_path" to cached.resolvedPath)
            )
        }

        val symlinkFile = File(symlinkPath)
        
        if (!Files.isSymbolicLink(symlinkFile.toPath())) {
            return DirectorResult(
                success = true,
                message = "Path is not a symlink, allowing access",
                level = SecurityLevel.INFO
            )
        }

        val resolution = resolveSymlinkSafely(symlinkPath)
        
        // Cache the result
        symlinkCache[cacheKey] = CachedSymlinkInfo(
            resolvedPath = resolution.finalPath,
            isValid = resolution.isValid,
            timestamp = System.currentTimeMillis()
        )

        // Clean cache if too large
        if (symlinkCache.size > MAX_CACHE_SIZE) {
            cleanupExpiredCache()
        }

        return DirectorResult(
            success = resolution.isValid,
            message = resolution.message,
            level = if (resolution.isValid) SecurityLevel.INFO else SecurityLevel.WARNING,
            details = mapOf(
                "resolved_path" to resolution.finalPath,
                "resolution_depth" to resolution.depth,
                "cached" to false
            )
        )
    }

    /**
     * Validate general path access (checking for symlinks in path)
     */
    private fun validatePath(path: String): DirectorResult {
        val pathFile = File(path)
        val pathComponents = mutableListOf<String>()
        var currentPath = pathFile
        
        // Build path components from leaf to root
        while (currentPath.parent != null) {
            pathComponents.add(0, currentPath.name)
            currentPath = currentPath.parentFile
        }
        
        // Check each component for symlinks
        var buildPath = if (pathFile.isAbsolute) "/" else ""
        for (component in pathComponents) {
            buildPath = File(buildPath, component).path
            val componentFile = File(buildPath)
            
            if (Files.isSymbolicLink(componentFile.toPath())) {
                val validation = validateSymlinkFollow(buildPath)
                if (!validation.success) {
                    return DirectorResult(
                        success = false,
                        message = "Path contains unsafe symlink at: $buildPath",
                        level = SecurityLevel.WARNING,
                        details = mapOf(
                            "full_path" to path,
                            "symlink_at" to buildPath,
                            "validation_error" to validation.message
                        )
                    )
                }
            }
        }

        return DirectorResult(
            success = true,
            message = "Path validation successful",
            level = SecurityLevel.INFO,
            details = mapOf("validated_path" to path)
        )
    }

    /**
     * Safely resolve a symlink with depth and security checks
     */
    private fun resolveSymlinkSafely(symlinkPath: String): SymlinkResolution {
        var currentPath = symlinkPath
        val visitedPaths = mutableSetOf<String>()
        var depth = 0

        while (depth < maxDepth) {
            val currentFile = File(currentPath)
            
            // Check for loops
            if (visitedPaths.contains(currentPath)) {
                return SymlinkResolution(
                    finalPath = currentPath,
                    isValid = false,
                    message = "Symlink loop detected at depth $depth",
                    depth = depth
                )
            }
            
            visitedPaths.add(currentPath)
            
            if (!Files.isSymbolicLink(currentFile.toPath())) {
                // Check if final target is in allowed directories
                val canonicalPath = try {
                    currentFile.canonicalPath
                } catch (e: Exception) {
                    return SymlinkResolution(
                        finalPath = currentPath,
                        isValid = false,
                        message = "Cannot resolve canonical path: ${e.message}",
                        depth = depth
                    )
                }
                
                val isAllowed = allowedTargets.any { allowed ->
                    canonicalPath.startsWith(allowed)
                } || allowedTargets.contains("*") // Allow wildcard
                
                return SymlinkResolution(
                    finalPath = canonicalPath,
                    isValid = isAllowed,
                    message = if (isAllowed) "Symlink resolved successfully" 
                             else "Symlink target not in allowed directories",
                    depth = depth
                )
            }

            // Follow the symlink
            try {
                currentPath = Files.readSymbolicLink(currentFile.toPath()).toString()
                if (!File(currentPath).isAbsolute) {
                    // Handle relative symlinks
                    currentPath = File(currentFile.parentFile, currentPath).path
                }
            } catch (e: Exception) {
                return SymlinkResolution(
                    finalPath = currentPath,
                    isValid = false,
                    message = "Failed to read symlink: ${e.message}",
                    depth = depth
                )
            }
            
            depth++
        }

        return SymlinkResolution(
            finalPath = currentPath,
            isValid = false,
            message = "Maximum symlink resolution depth exceeded ($maxDepth)",
            depth = depth
        )
    }

    /**
     * Detect potential symlink loops before creation
     */
    private fun detectSymlinkLoop(linkPath: String, targetPath: String): LoopDetectionResult {
        val linkParent = File(linkPath).parentFile?.canonicalPath ?: return LoopDetectionResult(false, "", 0)
        val targetCanonical = try {
            File(targetPath).canonicalPath
        } catch (e: Exception) {
            return LoopDetectionResult(true, "Cannot resolve target path", 0)
        }

        // Simple check: if target is a parent of link location, could create loop
        if (linkParent.startsWith(targetCanonical)) {
            return LoopDetectionResult(
                true, 
                "$linkParent would create loop with $targetCanonical", 
                1
            )
        }

        return LoopDetectionResult(false, "", 0)
    }

    /**
     * Clean up expired cache entries
     */
    private fun cleanupExpiredCache() {
        val now = System.currentTimeMillis()
        val expired = symlinkCache.entries.filter { 
            it.value.timestamp + CACHE_TTL_MS < now
        }
        expired.forEach { symlinkCache.remove(it.key) }
        
        if (expired.isNotEmpty()) {
            println("Cleaned up ${expired.size} expired symlink cache entries")
        }
    }

    /**
     * Get current statistics
     */
    fun getStats(): Map<String, Any> {
        return mapOf(
            "cache_size" to symlinkCache.size,
            "max_depth" to maxDepth,
            "allowed_targets" to allowedTargets,
            "cache_ttl_ms" to CACHE_TTL_MS
        )
    }
}

/**
 * Result of symlink resolution
 */
data class SymlinkResolution(
    val finalPath: String,
    val isValid: Boolean,
    val message: String,
    val depth: Int
)

/**
 * Result of symlink loop detection
 */
data class LoopDetectionResult(
    val hasLoop: Boolean,
    val loopPath: String,
    val depth: Int
)

/**
 * Cached symlink information
 */
data class CachedSymlinkInfo(
    val resolvedPath: String,
    val isValid: Boolean,
    val timestamp: Long
) {
    fun isExpired(ttlMs: Long = SymlinkDirector.CACHE_TTL_MS): Boolean {
        return System.currentTimeMillis() - timestamp > ttlMs
    }
}