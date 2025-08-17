package com.spiralgang.dolphin.envdirectors.directors

import com.spiralgang.dolphin.envdirectors.*
import java.lang.management.ManagementFactory
import java.lang.management.MemoryMXBean
import java.lang.management.MemoryUsage
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.Executors
import java.util.concurrent.ScheduledExecutorService
import java.util.concurrent.ScheduledFuture
import java.util.concurrent.TimeUnit

/**
 * Director responsible for memory monitoring, leak detection, and usage enforcement.
 * Provides real-time memory analysis and automatic cleanup mechanisms.
 */
class MemoryDirector : Director {
    private var enabled = true
    private var thresholdMb = 1024L
    private var checkIntervalSeconds = 60L
    private var lastRun: Long? = null
    private var criticalThreshold = 0.9 // 90% of max memory
    private var warningThreshold = 0.75 // 75% of max memory
    
    private val memoryBean: MemoryMXBean = ManagementFactory.getMemoryMXBean()
    private val memoryHistory = mutableListOf<MemorySnapshot>()
    private val processMemoryMap = ConcurrentHashMap<String, ProcessMemoryInfo>()
    private val scheduler: ScheduledExecutorService = Executors.newScheduledThreadPool(1)
    private var monitoringTask: ScheduledFuture<*>? = null

    companion object {
        private const val MAX_HISTORY_SIZE = 1000
        private const val BYTES_TO_MB = 1024 * 1024
        private const val GC_THRESHOLD_DIFFERENCE = 0.1 // Trigger GC if memory usage increases by 10%
    }

    override fun getName(): String = "memory"

    override fun initialize(config: Map<String, Any>): Boolean {
        return try {
            enabled = config["enabled"] as? Boolean ?: true
            thresholdMb = (config["threshold_mb"] as? Number)?.toLong() ?: 1024L
            checkIntervalSeconds = (config["check_interval"] as? Number)?.toLong() ?: 60L
            criticalThreshold = (config["critical_threshold"] as? Double) ?: 0.9
            warningThreshold = (config["warning_threshold"] as? Double) ?: 0.75

            if (enabled) {
                startMemoryMonitoring()
            }

            println("MemoryDirector initialized - Threshold: ${thresholdMb}MB, Check interval: ${checkIntervalSeconds}s")
            true
        } catch (e: Exception) {
            println("Failed to initialize MemoryDirector: ${e.message}")
            false
        }
    }

    override fun isEnabled(): Boolean = enabled

    override fun isApplicable(context: SecurityContext): Boolean {
        return context.operation in listOf(
            "memory_check", "process_start", "memory_cleanup", 
            "allocation_request", "gc_trigger", "memory_limit"
        )
    }

    override fun execute(context: SecurityContext): DirectorResult {
        lastRun = System.currentTimeMillis()
        
        return try {
            when (context.operation) {
                "memory_check" -> performMemoryCheck()
                "process_start" -> validateProcessStart(context)
                "memory_cleanup" -> performMemoryCleanup()
                "allocation_request" -> validateAllocation(context)
                "gc_trigger" -> triggerGarbageCollection()
                "memory_limit" -> enforceMemoryLimit(context)
                else -> DirectorResult(
                    success = true,
                    message = "Operation not applicable to memory director",
                    level = SecurityLevel.INFO
                )
            }
        } catch (e: Exception) {
            DirectorResult(
                success = false,
                message = "Memory check failed: ${e.message}",
                level = SecurityLevel.ERROR
            )
        }
    }

    override fun healthCheck(): Boolean {
        return try {
            val currentMemory = getCurrentMemoryUsage()
            enabled && 
            currentMemory.heapUsed > 0 &&
            currentMemory.heapMax > 0 &&
            memoryHistory.size < MAX_HISTORY_SIZE * 2 // Prevent unbounded growth
        } catch (e: Exception) {
            false
        }
    }

    override fun getLastRunTime(): Long? = lastRun

    /**
     * Perform comprehensive memory check
     */
    private fun performMemoryCheck(): DirectorResult {
        val memoryUsage = getCurrentMemoryUsage()
        val analysis = analyzeMemoryUsage(memoryUsage)
        
        // Store snapshot
        addMemorySnapshot(memoryUsage)
        
        val level = when {
            analysis.usageRatio >= criticalThreshold -> SecurityLevel.CRITICAL
            analysis.usageRatio >= warningThreshold -> SecurityLevel.WARNING
            else -> SecurityLevel.INFO
        }

        val message = buildString {
            append("Memory check: ${String.format("%.1f", analysis.usageRatio * 100)}% used")
            append(" (${memoryUsage.heapUsed}MB/${memoryUsage.heapMax}MB)")
            
            if (analysis.isLowMemory) {
                append(" - LOW MEMORY WARNING")
            }
            if (analysis.possibleLeak) {
                append(" - POSSIBLE MEMORY LEAK")
            }
        }

        return DirectorResult(
            success = level != SecurityLevel.CRITICAL,
            message = message,
            level = level,
            details = mapOf(
                "heap_used_mb" to memoryUsage.heapUsed,
                "heap_max_mb" to memoryUsage.heapMax,
                "non_heap_used_mb" to memoryUsage.nonHeapUsed,
                "usage_ratio" to analysis.usageRatio,
                "is_low_memory" to analysis.isLowMemory,
                "possible_leak" to analysis.possibleLeak,
                "gc_count" to memoryUsage.gcCount,
                "gc_time" to memoryUsage.gcTime
            )
        )
    }

    /**
     * Validate process start against memory constraints
     */
    private fun validateProcessStart(context: SecurityContext): DirectorResult {
        val currentUsage = getCurrentMemoryUsage()
        val requestedMemory = (context.metadata["requested_memory_mb"] as? Number)?.toLong() ?: 0L
        
        if (currentUsage.heapUsed + requestedMemory > currentUsage.heapMax * warningThreshold) {
            return DirectorResult(
                success = false,
                message = "Process start denied - insufficient memory (${currentUsage.heapUsed + requestedMemory}MB required, ${currentUsage.heapMax}MB max)",
                level = SecurityLevel.WARNING,
                details = mapOf(
                    "current_usage_mb" to currentUsage.heapUsed,
                    "requested_mb" to requestedMemory,
                    "max_available_mb" to currentUsage.heapMax,
                    "projected_usage" to currentUsage.heapUsed + requestedMemory
                )
            )
        }

        // Track process memory allocation
        val processId = context.target
        processMemoryMap[processId] = ProcessMemoryInfo(
            processId = processId,
            allocatedMemoryMb = requestedMemory,
            startTime = System.currentTimeMillis()
        )

        return DirectorResult(
            success = true,
            message = "Process start approved - memory allocation: ${requestedMemory}MB",
            level = SecurityLevel.INFO,
            details = mapOf(
                "allocated_mb" to requestedMemory,
                "remaining_mb" to (currentUsage.heapMax - currentUsage.heapUsed - requestedMemory)
            )
        )
    }

    /**
     * Perform memory cleanup operations
     */
    private fun performMemoryCleanup(): DirectorResult {
        val beforeCleanup = getCurrentMemoryUsage()
        
        // Force garbage collection
        System.gc()
        Thread.sleep(100) // Give GC time to complete
        System.runFinalization()
        
        val afterCleanup = getCurrentMemoryUsage()
        val freedMemory = beforeCleanup.heapUsed - afterCleanup.heapUsed
        
        // Clean up expired process entries
        val currentTime = System.currentTimeMillis()
        val expiredProcesses = processMemoryMap.entries.filter { (_, info) ->
            currentTime - info.startTime > TimeUnit.HOURS.toMillis(1)
        }
        expiredProcesses.forEach { processMemoryMap.remove(it.key) }
        
        // Trim memory history if too large
        if (memoryHistory.size > MAX_HISTORY_SIZE) {
            val toRemove = memoryHistory.size - MAX_HISTORY_SIZE
            repeat(toRemove) {
                memoryHistory.removeFirstOrNull()
            }
        }

        return DirectorResult(
            success = true,
            message = "Memory cleanup completed - freed ${freedMemory}MB",
            level = SecurityLevel.INFO,
            details = mapOf(
                "freed_memory_mb" to freedMemory,
                "before_cleanup_mb" to beforeCleanup.heapUsed,
                "after_cleanup_mb" to afterCleanup.heapUsed,
                "expired_processes_cleaned" to expiredProcesses.size,
                "history_entries_trimmed" to maxOf(0, memoryHistory.size - MAX_HISTORY_SIZE)
            )
        )
    }

    /**
     * Validate memory allocation request
     */
    private fun validateAllocation(context: SecurityContext): DirectorResult {
        val requestedMb = (context.metadata["size_mb"] as? Number)?.toLong() ?: 0L
        val currentUsage = getCurrentMemoryUsage()
        
        if (requestedMb > thresholdMb) {
            return DirectorResult(
                success = false,
                message = "Allocation denied - exceeds size threshold (${requestedMb}MB > ${thresholdMb}MB)",
                level = SecurityLevel.WARNING,
                details = mapOf(
                    "requested_mb" to requestedMb,
                    "threshold_mb" to thresholdMb
                )
            )
        }

        val projectedUsage = currentUsage.heapUsed + requestedMb
        val maxMemory = currentUsage.heapMax
        
        if (projectedUsage > maxMemory * criticalThreshold) {
            return DirectorResult(
                success = false,
                message = "Allocation denied - would exceed critical memory threshold",
                level = SecurityLevel.CRITICAL,
                details = mapOf(
                    "projected_usage_mb" to projectedUsage,
                    "max_memory_mb" to maxMemory,
                    "critical_threshold" to criticalThreshold
                )
            )
        }

        return DirectorResult(
            success = true,
            message = "Memory allocation approved",
            level = SecurityLevel.INFO,
            details = mapOf(
                "requested_mb" to requestedMb,
                "current_usage_mb" to currentUsage.heapUsed,
                "projected_usage_mb" to projectedUsage
            )
        )
    }

    /**
     * Trigger garbage collection
     */
    private fun triggerGarbageCollection(): DirectorResult {
        val beforeGc = getCurrentMemoryUsage()
        
        System.gc()
        Thread.sleep(200)
        
        val afterGc = getCurrentMemoryUsage()
        val freedMemory = beforeGc.heapUsed - afterGc.heapUsed
        
        return DirectorResult(
            success = true,
            message = "Garbage collection completed - freed ${freedMemory}MB",
            level = SecurityLevel.INFO,
            details = mapOf(
                "before_gc_mb" to beforeGc.heapUsed,
                "after_gc_mb" to afterGc.heapUsed,
                "freed_memory_mb" to freedMemory,
                "gc_count_increase" to (afterGc.gcCount - beforeGc.gcCount)
            )
        )
    }

    /**
     * Enforce memory limits
     */
    private fun enforceMemoryLimit(context: SecurityContext): DirectorResult {
        val limitMb = (context.metadata["limit_mb"] as? Number)?.toLong() ?: thresholdMb
        val currentUsage = getCurrentMemoryUsage()
        
        if (currentUsage.heapUsed > limitMb) {
            // Try cleanup first
            val cleanupResult = performMemoryCleanup()
            val afterCleanup = getCurrentMemoryUsage()
            
            if (afterCleanup.heapUsed > limitMb) {
                return DirectorResult(
                    success = false,
                    message = "Memory limit exceeded even after cleanup (${afterCleanup.heapUsed}MB > ${limitMb}MB)",
                    level = SecurityLevel.CRITICAL,
                    details = mapOf(
                        "current_usage_mb" to afterCleanup.heapUsed,
                        "limit_mb" to limitMb,
                        "cleanup_freed_mb" to (currentUsage.heapUsed - afterCleanup.heapUsed)
                    )
                )
            }
        }

        return DirectorResult(
            success = true,
            message = "Memory usage within limits",
            level = SecurityLevel.INFO,
            details = mapOf(
                "current_usage_mb" to currentUsage.heapUsed,
                "limit_mb" to limitMb
            )
        )
    }

    /**
     * Get current memory usage information
     */
    private fun getCurrentMemoryUsage(): MemorySnapshot {
        val heapMemory = memoryBean.heapMemoryUsage
        val nonHeapMemory = memoryBean.nonHeapMemoryUsage
        val gcMxBeans = ManagementFactory.getGarbageCollectorMXBeans()
        
        val gcCount = gcMxBeans.sumOf { it.collectionCount }
        val gcTime = gcMxBeans.sumOf { it.collectionTime }
        
        return MemorySnapshot(
            timestamp = System.currentTimeMillis(),
            heapUsed = heapMemory.used / BYTES_TO_MB,
            heapMax = heapMemory.max / BYTES_TO_MB,
            nonHeapUsed = nonHeapMemory.used / BYTES_TO_MB,
            gcCount = gcCount,
            gcTime = gcTime
        )
    }

    /**
     * Analyze memory usage patterns
     */
    private fun analyzeMemoryUsage(current: MemorySnapshot): MemoryAnalysis {
        val usageRatio = current.heapUsed.toDouble() / current.heapMax.toDouble()
        val isLowMemory = usageRatio >= warningThreshold
        
        // Check for memory leak patterns
        var possibleLeak = false
        if (memoryHistory.size >= 10) {
            val recentHistory = memoryHistory.takeLast(10)
            val avgUsage = recentHistory.map { it.heapUsed }.average()
            val trend = (current.heapUsed - avgUsage) / avgUsage
            
            // If memory usage is consistently increasing by more than 5% over recent history
            possibleLeak = trend > 0.05 && recentHistory.all { it.heapUsed < current.heapUsed }
        }

        return MemoryAnalysis(
            usageRatio = usageRatio,
            isLowMemory = isLowMemory,
            possibleLeak = possibleLeak
        )
    }

    /**
     * Add memory snapshot to history
     */
    private fun addMemorySnapshot(snapshot: MemorySnapshot) {
        synchronized(memoryHistory) {
            memoryHistory.add(snapshot)
            if (memoryHistory.size > MAX_HISTORY_SIZE) {
                memoryHistory.removeFirst()
            }
        }
    }

    /**
     * Start continuous memory monitoring
     */
    private fun startMemoryMonitoring() {
        monitoringTask = scheduler.scheduleAtFixedRate({
            try {
                val snapshot = getCurrentMemoryUsage()
                addMemorySnapshot(snapshot)
                
                // Auto-trigger GC if memory usage is high
                val analysis = analyzeMemoryUsage(snapshot)
                if (analysis.usageRatio >= criticalThreshold) {
                    println("Auto-triggering GC due to high memory usage: ${String.format("%.1f", analysis.usageRatio * 100)}%")
                    System.gc()
                }
                
                // Log warnings for memory issues
                if (analysis.possibleLeak) {
                    println("WARNING: Possible memory leak detected")
                }
                
            } catch (e: Exception) {
                println("Memory monitoring error: ${e.message}")
            }
        }, checkIntervalSeconds, checkIntervalSeconds, TimeUnit.SECONDS)
        
        println("Memory monitoring started with ${checkIntervalSeconds}s interval")
    }

    /**
     * Stop memory monitoring
     */
    fun stopMemoryMonitoring() {
        monitoringTask?.cancel(true)
        println("Memory monitoring stopped")
    }

    /**
     * Get memory statistics
     */
    fun getMemoryStats(): Map<String, Any> {
        val current = getCurrentMemoryUsage()
        val analysis = analyzeMemoryUsage(current)
        
        return mapOf(
            "current_heap_used_mb" to current.heapUsed,
            "current_heap_max_mb" to current.heapMax,
            "current_non_heap_used_mb" to current.nonHeapUsed,
            "usage_ratio" to analysis.usageRatio,
            "is_low_memory" to analysis.isLowMemory,
            "possible_leak" to analysis.possibleLeak,
            "gc_count" to current.gcCount,
            "gc_time_ms" to current.gcTime,
            "history_size" to memoryHistory.size,
            "tracked_processes" to processMemoryMap.size,
            "monitoring_active" to (monitoringTask?.isDone == false)
        )
    }

    /**
     * Get memory history for analysis
     */
    fun getMemoryHistory(limit: Int = 100): List<MemorySnapshot> {
        return synchronized(memoryHistory) {
            memoryHistory.takeLast(limit).toList()
        }
    }

    /**
     * Clean up resources when director is destroyed
     */
    fun cleanup() {
        stopMemoryMonitoring()
        scheduler.shutdown()
        try {
            if (!scheduler.awaitTermination(5, TimeUnit.SECONDS)) {
                scheduler.shutdownNow()
            }
        } catch (e: InterruptedException) {
            scheduler.shutdownNow()
        }
    }
}

/**
 * Memory snapshot data class
 */
data class MemorySnapshot(
    val timestamp: Long,
    val heapUsed: Long,
    val heapMax: Long,
    val nonHeapUsed: Long,
    val gcCount: Long,
    val gcTime: Long
)

/**
 * Memory analysis result
 */
data class MemoryAnalysis(
    val usageRatio: Double,
    val isLowMemory: Boolean,
    val possibleLeak: Boolean
)

/**
 * Process memory tracking information
 */
data class ProcessMemoryInfo(
    val processId: String,
    val allocatedMemoryMb: Long,
    val startTime: Long
)