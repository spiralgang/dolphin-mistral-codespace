package com.spiralgang.dolphin.envdirectors.integration

import com.spiralgang.dolphin.envdirectors.*
import kotlinx.coroutines.*
import java.net.HttpURLConnection
import java.net.URL
import java.util.concurrent.CompletableFuture
import com.google.gson.Gson
import com.google.gson.reflect.TypeToken

/**
 * Sample integration for Android agents with the environment director system.
 * Provides secure communication, authentication, and coordination with Android devices.
 */
class AndroidAgentIntegration {
    private var endpoint = "http://localhost:8080/api/security"
    private var authToken = ""
    private var timeoutMs = 5000L
    private var enabled = false
    private val gson = Gson()
    private val scope = CoroutineScope(Dispatchers.IO + SupervisorJob())

    companion object {
        private const val API_VERSION = "v1"
        private const val USER_AGENT = "EnvDirectors-AndroidIntegration/1.0"
    }

    /**
     * Initialize the Android agent integration
     */
    fun initialize(config: Map<String, Any>): Boolean {
        return try {
            enabled = config["enabled"] as? Boolean ?: false
            endpoint = config["endpoint"] as? String ?: endpoint
            authToken = config["auth_token"] as? String ?: ""
            timeoutMs = (config["timeout_ms"] as? Number)?.toLong() ?: timeoutMs

            if (enabled && authToken.isEmpty()) {
                println("WARNING: Android agent integration enabled but no auth token provided")
            }

            println("AndroidAgentIntegration initialized - Enabled: $enabled, Endpoint: $endpoint")
            true
        } catch (e: Exception) {
            println("Failed to initialize AndroidAgentIntegration: ${e.message}")
            false
        }
    }

    /**
     * Send security event to Android agent
     */
    fun sendSecurityEvent(event: SecurityEvent): CompletableFuture<Boolean> {
        if (!enabled) {
            return CompletableFuture.completedFuture(true)
        }

        return CompletableFuture.supplyAsync {
            try {
                val response = sendHttpRequest("POST", "/events", event)
                response.success
            } catch (e: Exception) {
                println("Failed to send security event to Android agent: ${e.message}")
                false
            }
        }
    }

    /**
     * Request security scan from Android agent
     */
    suspend fun requestSecurityScan(scanRequest: ScanRequest): ApiResponse {
        return withContext(Dispatchers.IO) {
            try {
                sendHttpRequest("POST", "/scan", scanRequest)
            } catch (e: Exception) {
                ApiResponse(
                    success = false,
                    message = "Scan request failed: ${e.message}",
                    data = emptyMap()
                )
            }
        }
    }

    /**
     * Get security status from Android agent
     */
    suspend fun getSecurityStatus(): SecurityStatus {
        return withContext(Dispatchers.IO) {
            try {
                val response = sendHttpRequest("GET", "/status", null)
                if (response.success) {
                    gson.fromJson(gson.toJson(response.data), SecurityStatus::class.java)
                } else {
                    SecurityStatus(
                        agentId = "unknown",
                        status = AgentStatus.ERROR,
                        lastUpdate = System.currentTimeMillis(),
                        message = response.message
                    )
                }
            } catch (e: Exception) {
                SecurityStatus(
                    agentId = "error",
                    status = AgentStatus.OFFLINE,
                    lastUpdate = System.currentTimeMillis(),
                    message = "Failed to get status: ${e.message}"
                )
            }
        }
    }

    /**
     * Register device with the director system
     */
    suspend fun registerDevice(deviceInfo: DeviceInfo): RegistrationResult {
        return withContext(Dispatchers.IO) {
            try {
                val response = sendHttpRequest("POST", "/register", deviceInfo)
                RegistrationResult(
                    success = response.success,
                    deviceId = response.data["deviceId"] as? String ?: "",
                    token = response.data["token"] as? String ?: "",
                    message = response.message
                )
            } catch (e: Exception) {
                RegistrationResult(
                    success = false,
                    deviceId = "",
                    token = "",
                    message = "Registration failed: ${e.message}"
                )
            }
        }
    }

    /**
     * Push director configuration to Android agent
     */
    suspend fun pushConfiguration(config: DirectorConfig): Boolean {
        return withContext(Dispatchers.IO) {
            try {
                val response = sendHttpRequest("PUT", "/config", config)
                if (response.success) {
                    println("Configuration pushed to Android agent successfully")
                    true
                } else {
                    println("Failed to push configuration: ${response.message}")
                    false
                }
            } catch (e: Exception) {
                println("Configuration push error: ${e.message}")
                false
            }
        }
    }

    /**
     * Execute remote security command on Android agent
     */
    suspend fun executeRemoteCommand(command: RemoteCommand): CommandResult {
        return withContext(Dispatchers.IO) {
            try {
                val response = sendHttpRequest("POST", "/command", command)
                CommandResult(
                    success = response.success,
                    output = response.data["output"] as? String ?: "",
                    exitCode = (response.data["exitCode"] as? Number)?.toInt() ?: -1,
                    message = response.message
                )
            } catch (e: Exception) {
                CommandResult(
                    success = false,
                    output = "",
                    exitCode = -1,
                    message = "Command execution failed: ${e.message}"
                )
            }
        }
    }

    /**
     * Send HTTP request to Android agent
     */
    private fun sendHttpRequest(method: String, path: String, body: Any?): ApiResponse {
        val url = URL("$endpoint$path")
        val connection = url.openConnection() as HttpURLConnection

        return try {
            // Configure connection
            connection.requestMethod = method
            connection.setRequestProperty("Content-Type", "application/json")
            connection.setRequestProperty("User-Agent", USER_AGENT)
            connection.setRequestProperty("X-API-Version", API_VERSION)
            
            if (authToken.isNotEmpty()) {
                connection.setRequestProperty("Authorization", "Bearer $authToken")
            }
            
            connection.connectTimeout = timeoutMs.toInt()
            connection.readTimeout = timeoutMs.toInt()

            // Send body if provided
            if (body != null && method != "GET") {
                connection.doOutput = true
                val jsonBody = gson.toJson(body)
                connection.outputStream.use { it.write(jsonBody.toByteArray()) }
            }

            // Read response
            val responseCode = connection.responseCode
            val responseBody = if (responseCode in 200..299) {
                connection.inputStream.bufferedReader().use { it.readText() }
            } else {
                connection.errorStream?.bufferedReader()?.use { it.readText() } ?: ""
            }

            // Parse response
            val success = responseCode in 200..299
            val responseMap = if (responseBody.isNotEmpty()) {
                try {
                    val type = object : TypeToken<Map<String, Any>>() {}.type
                    gson.fromJson<Map<String, Any>>(responseBody, type)
                } catch (e: Exception) {
                    mapOf("raw_response" to responseBody)
                }
            } else {
                emptyMap()
            }

            ApiResponse(
                success = success,
                message = responseMap["message"] as? String ?: "HTTP $responseCode",
                data = responseMap["data"] as? Map<String, Any> ?: responseMap
            )

        } finally {
            connection.disconnect()
        }
    }

    /**
     * Start periodic health check with Android agent
     */
    fun startHealthCheck(intervalMs: Long = 30000L) {
        if (!enabled) return

        scope.launch {
            while (isActive) {
                try {
                    val status = getSecurityStatus()
                    handleHealthCheckResult(status)
                    delay(intervalMs)
                } catch (e: Exception) {
                    println("Health check error: ${e.message}")
                    delay(intervalMs)
                }
            }
        }
    }

    /**
     * Handle health check results
     */
    private fun handleHealthCheckResult(status: SecurityStatus) {
        when (status.status) {
            AgentStatus.HEALTHY -> {
                // Agent is healthy, no action needed
            }
            AgentStatus.WARNING -> {
                println("WARNING: Android agent reports warning status: ${status.message}")
            }
            AgentStatus.ERROR -> {
                println("ERROR: Android agent reports error status: ${status.message}")
            }
            AgentStatus.OFFLINE -> {
                println("CRITICAL: Android agent is offline: ${status.message}")
            }
        }
    }

    /**
     * Shutdown the integration
     */
    fun shutdown() {
        scope.cancel()
        println("AndroidAgentIntegration shutdown")
    }
}

// Data classes for Android agent communication

data class SecurityEvent(
    val eventType: String,
    val severity: SecurityLevel,
    val source: String,
    val target: String,
    val details: Map<String, Any> = emptyMap(),
    val timestamp: Long = System.currentTimeMillis()
)

data class ScanRequest(
    val scanType: String, // "file", "process", "network", "full"
    val target: String,
    val options: Map<String, Any> = emptyMap()
)

data class ApiResponse(
    val success: Boolean,
    val message: String,
    val data: Map<String, Any> = emptyMap()
)

data class SecurityStatus(
    val agentId: String,
    val status: AgentStatus,
    val lastUpdate: Long,
    val message: String = "",
    val metrics: Map<String, Any> = emptyMap()
)

data class DeviceInfo(
    val deviceId: String,
    val deviceType: String,
    val osVersion: String,
    val appVersion: String,
    val capabilities: List<String> = emptyList()
)

data class RegistrationResult(
    val success: Boolean,
    val deviceId: String,
    val token: String,
    val message: String
)

data class DirectorConfig(
    val directors: Map<String, Map<String, Any>>,
    val global: Map<String, Any>
)

data class RemoteCommand(
    val command: String,
    val args: List<String> = emptyList(),
    val timeout: Long = 30000L,
    val workingDir: String? = null
)

data class CommandResult(
    val success: Boolean,
    val output: String,
    val exitCode: Int,
    val message: String
)

enum class AgentStatus {
    HEALTHY, WARNING, ERROR, OFFLINE
}

// Example usage
fun main() {
    val integration = AndroidAgentIntegration()
    
    val config = mapOf(
        "enabled" to true,
        "endpoint" to "http://192.168.1.100:8080/api/security",
        "auth_token" to "your-secure-token",
        "timeout_ms" to 10000
    )
    
    if (integration.initialize(config)) {
        println("Android integration initialized successfully")
        
        // Start health monitoring
        integration.startHealthCheck(30000L)
        
        // Example: Send security event
        val event = SecurityEvent(
            eventType = "file_scan_completed",
            severity = SecurityLevel.INFO,
            source = "file_security_director",
            target = "/tmp/suspicious_file.txt",
            details = mapOf(
                "risk_score" to 25,
                "threats_found" to 0
            )
        )
        
        integration.sendSecurityEvent(event).thenAccept { success ->
            println("Security event sent: $success")
        }
        
        // Keep alive for demonstration
        Thread.sleep(60000)
        integration.shutdown()
    }
}