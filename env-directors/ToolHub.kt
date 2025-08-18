package dolphin.mistral.envdirectors

import kotlin.collections.mutableMapOf
import kotlin.collections.mutableListOf

/**
 * Central ToolHub/DirectorHub API for coordinating all environment directors.
 * 
 * This hub provides a unified interface for managing security, permissions,
 * symlink defense, memory management, and other environmental concerns
 * through pluggable director modules.
 */
class ToolHub {
    private val directors = mutableMapOf<String, Director>()
    private val hooks = mutableMapOf<String, MutableList<() -> Unit>>()
    private val config = mutableMapOf<String, Any>()
    
    companion object {
        private var instance: ToolHub? = null
        
        fun getInstance(): ToolHub {
            if (instance == null) {
                instance = ToolHub()
            }
            return instance!!
        }
    }
    
    /**
     * Register a director module with the hub
     */
    fun registerDirector(name: String, director: Director) {
        directors[name] = director
        director.initialize(this)
        println("[ToolHub] Registered director: $name")
    }
    
    /**
     * Unregister a director module
     */
    fun unregisterDirector(name: String) {
        directors[name]?.shutdown()
        directors.remove(name)
        println("[ToolHub] Unregistered director: $name")
    }
    
    /**
     * Get a specific director by name
     */
    fun getDirector(name: String): Director? {
        return directors[name]
    }
    
    /**
     * Get all registered directors
     */
    fun getAllDirectors(): Map<String, Director> {
        return directors.toMap()
    }
    
    /**
     * Execute a security check across all relevant directors
     */
    fun executeSecurityCheck(): SecurityReport {
        val report = SecurityReport()
        
        directors.values.forEach { director ->
            try {
                val result = director.performSecurityCheck()
                report.addDirectorResult(director.getName(), result)
            } catch (e: Exception) {
                report.addError(director.getName(), e.message ?: "Unknown error")
            }
        }
        
        return report
    }
    
    /**
     * Set configuration value
     */
    fun setConfig(key: String, value: Any) {
        config[key] = value
    }
    
    /**
     * Get configuration value
     */
    fun getConfig(key: String): Any? {
        return config[key]
    }
    
    /**
     * Register a lifecycle hook
     */
    fun registerHook(event: String, callback: () -> Unit) {
        if (!hooks.containsKey(event)) {
            hooks[event] = mutableListOf()
        }
        hooks[event]?.add(callback)
    }
    
    /**
     * Execute lifecycle hooks
     */
    fun executeHooks(event: String) {
        hooks[event]?.forEach { callback ->
            try {
                callback()
            } catch (e: Exception) {
                println("[ToolHub] Hook execution failed for $event: ${e.message}")
            }
        }
    }
    
    /**
     * Initialize all directors and execute startup hooks
     */
    fun startup() {
        executeHooks("startup")
        directors.values.forEach { director ->
            try {
                director.startup()
            } catch (e: Exception) {
                println("[ToolHub] Director ${director.getName()} startup failed: ${e.message}")
            }
        }
    }
    
    /**
     * Shutdown all directors and execute shutdown hooks
     */
    fun shutdown() {
        executeHooks("shutdown")
        directors.values.forEach { director ->
            try {
                director.shutdown()
            } catch (e: Exception) {
                println("[ToolHub] Director ${director.getName()} shutdown failed: ${e.message}")
            }
        }
    }
}

/**
 * Base interface for all director modules
 */
abstract class Director {
    abstract fun getName(): String
    abstract fun initialize(hub: ToolHub)
    abstract fun performSecurityCheck(): DirectorResult
    
    open fun startup() {
        // Default implementation - can be overridden
    }
    
    open fun shutdown() {
        // Default implementation - can be overridden  
    }
}

/**
 * Result from a director's security check
 */
data class DirectorResult(
    val status: Status,
    val message: String,
    val details: Map<String, Any> = emptyMap()
) {
    enum class Status {
        PASS, WARN, FAIL, ERROR
    }
}

/**
 * Overall security report from all directors
 */
class SecurityReport {
    private val results = mutableMapOf<String, DirectorResult>()
    private val errors = mutableMapOf<String, String>()
    
    fun addDirectorResult(directorName: String, result: DirectorResult) {
        results[directorName] = result
    }
    
    fun addError(directorName: String, error: String) {
        errors[directorName] = error
    }
    
    fun getResults(): Map<String, DirectorResult> = results.toMap()
    fun getErrors(): Map<String, String> = errors.toMap()
    
    fun hasFailures(): Boolean {
        return results.values.any { it.status == DirectorResult.Status.FAIL } || errors.isNotEmpty()
    }
    
    fun hasWarnings(): Boolean {
        return results.values.any { it.status == DirectorResult.Status.WARN }
    }
    
    override fun toString(): String {
        val sb = StringBuilder()
        sb.append("=== Security Report ===\n")
        
        results.forEach { (name, result) ->
            sb.append("[$name] ${result.status}: ${result.message}\n")
        }
        
        errors.forEach { (name, error) ->
            sb.append("[$name] ERROR: $error\n")
        }
        
        return sb.toString()
    }
}