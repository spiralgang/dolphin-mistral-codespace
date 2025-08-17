package com.spiralgang.dolphin.envdirectors.directors

import com.spiralgang.dolphin.envdirectors.*
import java.security.Principal
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.TimeUnit

/**
 * Director responsible for role-based access control and permission management.
 * Handles user authentication, authorization, and permission caching.
 */
class PermissionsDirector : Director {
    private var enabled = true
    private var strictMode = false
    private var cacheTtl = 300L // 5 minutes default
    private val permissionCache = ConcurrentHashMap<String, CachedPermission>()
    private val roleDefinitions = ConcurrentHashMap<String, Role>()
    private var lastRun: Long? = null

    companion object {
        const val ADMIN_ROLE = "admin"
        const val USER_ROLE = "user"
        const val GUEST_ROLE = "guest"
        const val SYSTEM_ROLE = "system"
    }

    override fun getName(): String = "permissions"

    override fun initialize(config: Map<String, Any>): Boolean {
        return try {
            enabled = config["enabled"] as? Boolean ?: true
            strictMode = config["strict_mode"] as? Boolean ?: false
            cacheTtl = (config["cache_ttl"] as? Number)?.toLong() ?: 300L
            
            // Initialize default roles
            initializeDefaultRoles()
            
            println("PermissionsDirector initialized - Strict mode: $strictMode, Cache TTL: ${cacheTtl}s")
            true
        } catch (e: Exception) {
            println("Failed to initialize PermissionsDirector: ${e.message}")
            false
        }
    }

    override fun isEnabled(): Boolean = enabled

    override fun isApplicable(context: SecurityContext): Boolean {
        // Permissions apply to most operations, especially file access and system operations
        return context.operation in listOf(
            "file_access", "file_write", "file_delete", "system_command", 
            "network_access", "directory_create", "symlink_create"
        )
    }

    override fun execute(context: SecurityContext): DirectorResult {
        lastRun = System.currentTimeMillis()
        
        return try {
            val user = context.user ?: return DirectorResult(
                success = false,
                message = "No user specified in security context",
                level = SecurityLevel.ERROR
            )

            val permission = checkPermission(user, context.operation, context.target)
            
            when (permission.status) {
                PermissionStatus.GRANTED -> DirectorResult(
                    success = true,
                    message = "Permission granted for ${context.operation} on ${context.target}",
                    level = SecurityLevel.INFO,
                    details = mapOf(
                        "user" to user,
                        "role" to permission.role,
                        "cached" to permission.fromCache
                    )
                )
                PermissionStatus.DENIED -> DirectorResult(
                    success = false,
                    message = "Permission denied for ${context.operation} on ${context.target}",
                    level = if (strictMode) SecurityLevel.CRITICAL else SecurityLevel.WARNING,
                    details = mapOf(
                        "user" to user,
                        "reason" to permission.reason
                    )
                )
                PermissionStatus.UNKNOWN -> DirectorResult(
                    success = !strictMode,
                    message = "Permission status unknown - ${if (strictMode) "denied in strict mode" else "allowed with warning"}",
                    level = SecurityLevel.WARNING,
                    details = mapOf(
                        "user" to user,
                        "strict_mode" to strictMode
                    )
                )
            }
        } catch (e: Exception) {
            DirectorResult(
                success = false,
                message = "Permission check failed: ${e.message}",
                level = SecurityLevel.ERROR
            )
        }
    }

    override fun healthCheck(): Boolean {
        return try {
            // Verify core role definitions exist
            roleDefinitions.containsKey(ADMIN_ROLE) && 
            roleDefinitions.containsKey(USER_ROLE) &&
            permissionCache.size < 10000 // Prevent memory issues
        } catch (e: Exception) {
            false
        }
    }

    override fun getLastRunTime(): Long? = lastRun

    /**
     * Check if a user has permission for a specific operation on a target
     */
    fun checkPermission(user: String, operation: String, target: String): PermissionResult {
        val cacheKey = "$user:$operation:$target"
        
        // Check cache first
        val cached = permissionCache[cacheKey]
        if (cached != null && !cached.isExpired()) {
            return PermissionResult(
                status = cached.status,
                role = cached.role,
                reason = "Cached result",
                fromCache = true
            )
        }

        // Determine user role
        val userRole = getUserRole(user)
        val role = roleDefinitions[userRole]
            ?: return PermissionResult(
                status = PermissionStatus.UNKNOWN,
                role = userRole,
                reason = "Unknown role: $userRole"
            )

        // Check permission
        val status = when {
            role.hasPermission(operation, target) -> PermissionStatus.GRANTED
            role.isDenied(operation, target) -> PermissionStatus.DENIED
            else -> PermissionStatus.UNKNOWN
        }

        val result = PermissionResult(
            status = status,
            role = userRole,
            reason = "Role-based check",
            fromCache = false
        )

        // Cache result
        permissionCache[cacheKey] = CachedPermission(
            status = status,
            role = userRole,
            timestamp = System.currentTimeMillis()
        )

        // Cleanup old cache entries periodically
        if (permissionCache.size > 1000) {
            cleanupExpiredCache()
        }

        return result
    }

    /**
     * Get user role (simplified implementation - would integrate with actual auth system)
     */
    private fun getUserRole(user: String): String {
        return when {
            user == "root" || user == "admin" -> ADMIN_ROLE
            user == "system" -> SYSTEM_ROLE
            user == "guest" || user == "anonymous" -> GUEST_ROLE
            else -> USER_ROLE
        }
    }

    /**
     * Initialize default role definitions
     */
    private fun initializeDefaultRoles() {
        // Admin role - full access
        roleDefinitions[ADMIN_ROLE] = Role(
            name = ADMIN_ROLE,
            permissions = mutableSetOf("*"),
            denials = mutableSetOf()
        )

        // User role - limited access
        roleDefinitions[USER_ROLE] = Role(
            name = USER_ROLE,
            permissions = mutableSetOf(
                "file_access", "file_write", "directory_create", 
                "network_access"
            ),
            denials = mutableSetOf("system_command", "file_delete")
        )

        // Guest role - read-only access
        roleDefinitions[GUEST_ROLE] = Role(
            name = GUEST_ROLE,
            permissions = mutableSetOf("file_access"),
            denials = mutableSetOf(
                "file_write", "file_delete", "system_command", 
                "directory_create", "symlink_create"
            )
        )

        // System role - system operations only
        roleDefinitions[SYSTEM_ROLE] = Role(
            name = SYSTEM_ROLE,
            permissions = mutableSetOf(
                "system_command", "file_access", "file_write", 
                "directory_create"
            ),
            denials = mutableSetOf("network_access")
        )
    }

    /**
     * Clean up expired cache entries
     */
    private fun cleanupExpiredCache() {
        val now = System.currentTimeMillis()
        val expired = permissionCache.entries.filter { 
            it.value.timestamp + TimeUnit.SECONDS.toMillis(cacheTtl) < now
        }
        expired.forEach { permissionCache.remove(it.key) }
        
        if (expired.isNotEmpty()) {
            println("Cleaned up ${expired.size} expired permission cache entries")
        }
    }

    /**
     * Add or update a role definition
     */
    fun defineRole(role: Role) {
        roleDefinitions[role.name] = role
        // Invalidate related cache entries
        permissionCache.clear()
        println("Role definition updated: ${role.name}")
    }

    /**
     * Get current cache statistics
     */
    fun getCacheStats(): Map<String, Any> {
        return mapOf(
            "cache_size" to permissionCache.size,
            "cache_ttl" to cacheTtl,
            "roles_defined" to roleDefinitions.size
        )
    }
}

/**
 * Represents a user role with permissions and denials
 */
data class Role(
    val name: String,
    val permissions: MutableSet<String> = mutableSetOf(),
    val denials: MutableSet<String> = mutableSetOf()
) {
    fun hasPermission(operation: String, target: String): Boolean {
        // Check for explicit denials first
        if (isDenied(operation, target)) return false
        
        // Check for wildcard permission
        if (permissions.contains("*")) return true
        
        // Check for specific permission
        return permissions.contains(operation)
    }

    fun isDenied(operation: String, target: String): Boolean {
        return denials.contains(operation) || denials.contains("*")
    }

    fun addPermission(permission: String) {
        permissions.add(permission)
    }

    fun addDenial(denial: String) {
        denials.add(denial)
    }
}

/**
 * Result of a permission check
 */
data class PermissionResult(
    val status: PermissionStatus,
    val role: String,
    val reason: String,
    val fromCache: Boolean = false
)

/**
 * Permission status enumeration
 */
enum class PermissionStatus {
    GRANTED, DENIED, UNKNOWN
}

/**
 * Cached permission entry
 */
data class CachedPermission(
    val status: PermissionStatus,
    val role: String,
    val timestamp: Long
) {
    fun isExpired(ttlSeconds: Long = 300): Boolean {
        return System.currentTimeMillis() - timestamp > TimeUnit.SECONDS.toMillis(ttlSeconds)
    }
}