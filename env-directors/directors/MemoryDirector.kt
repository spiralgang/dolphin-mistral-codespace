package dolphin.mistral.envdirectors.directors

import dolphin.mistral.envdirectors.Director
import dolphin.mistral.envdirectors.DirectorResult
import dolphin.mistral.envdirectors.ToolHub
import java.lang.management.ManagementFactory
import java.lang.management.MemoryMXBean
import java.lang.management.MemoryPoolMXBean
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.Executors
import java.util.concurrent.ScheduledExecutorService
import java.util.concurrent.TimeUnit

/**
 * MemoryDirector manages memory usage, cleanup, and prevents memory-based attacks
 * 
 * This director monitors JVM memory usage, performs garbage collection optimization,
 * detects memory leaks, and provides protection against memory exhaustion attacks.
 * It also manages temporary data cleanup and memory pressure monitoring.
 */
class MemoryDirector : Director() {
    
    private lateinit var hub: ToolHub
    private val memoryBean: MemoryMXBean = ManagementFactory.getMemoryMXBean()
    private val memoryPools: List<MemoryPoolMXBean> = ManagementFactory.getMemoryPoolMXBeans()
    
    private val memoryHistory = mutableListOf<MemorySnapshot>()
    private val allocatedObjects = ConcurrentHashMap<String, Long>()
    private var monitoringEnabled = false
    private var scheduler: ScheduledExecutorService? = null
    
    // Configuration
    private var maxHeapUsagePercent = 85
    private var maxNonHeapUsagePercent = 90
    private var memoryLeakThreshold = 0.95
    private var cleanupIntervalMinutes = 5
    private var historyRetentionHours = 24
    
    override fun getName(): String = "MemoryDirector"
    
    override fun initialize(hub: ToolHub) {
        this.hub = hub
        
        // Load configuration
        val maxHeapConfig = hub.getConfig("memory.maxHeapUsagePercent") as? Int
        if (maxHeapConfig != null) {
            maxHeapUsagePercent = maxHeapConfig
        }
        
        val maxNonHeapConfig = hub.getConfig("memory.maxNonHeapUsagePercent") as? Int
        if (maxNonHeapConfig != null) {
            maxNonHeapUsagePercent = maxNonHeapConfig
        }
        
        val cleanupConfig = hub.getConfig("memory.cleanupIntervalMinutes") as? Int
        if (cleanupConfig != null) {
            cleanupIntervalMinutes = cleanupConfig
        }
        
        println("[MemoryDirector] Initialized with heap threshold: $maxHeapUsagePercent%")
    }
    
    override fun performSecurityCheck(): DirectorResult {
        val issues = mutableListOf<String>()
        val details = mutableMapOf<String, Any>()
        
        try {
            val currentSnapshot = takeMemorySnapshot()
            memoryHistory.add(currentSnapshot)
            
            // Clean old history
            cleanOldHistory()
            
            // Check heap memory usage
            val heapUsage = currentSnapshot.heapUsagePercent
            if (heapUsage > maxHeapUsagePercent) {
                issues.add("Heap memory usage critical: ${heapUsage.toInt()}%")
            } else if (heapUsage > maxHeapUsagePercent * 0.8) {
                issues.add("Heap memory usage high: ${heapUsage.toInt()}%")
            }
            
            // Check non-heap memory usage
            val nonHeapUsage = currentSnapshot.nonHeapUsagePercent
            if (nonHeapUsage > maxNonHeapUsagePercent) {
                issues.add("Non-heap memory usage critical: ${nonHeapUsage.toInt()}%")
            }
            
            // Detect potential memory leaks
            val leakDetection = detectMemoryLeaks()
            if (leakDetection.isNotEmpty()) {
                issues.addAll(leakDetection)
            }
            
            // Check memory pools
            val poolIssues = checkMemoryPools()
            if (poolIssues.isNotEmpty()) {
                issues.addAll(poolIssues)
            }
            
            // Check for memory pressure trends
            val pressureTrends = analyzePressureTrends()
            if (pressureTrends.isNotEmpty()) {
                issues.addAll(pressureTrends)
            }
            
            // Populate details
            details["heapUsagePercent"] = heapUsage
            details["nonHeapUsagePercent"] = nonHeapUsage
            details["heapUsedMB"] = currentSnapshot.heapUsed / (1024 * 1024)
            details["heapMaxMB"] = currentSnapshot.heapMax / (1024 * 1024)
            details["nonHeapUsedMB"] = currentSnapshot.nonHeapUsed / (1024 * 1024)
            details["gcCount"] = currentSnapshot.gcCount
            details["memoryHistorySize"] = memoryHistory.size
            
            return when {
                issues.any { it.contains("critical") } -> DirectorResult(
                    DirectorResult.Status.FAIL,
                    "Critical memory issues detected: ${issues.joinToString("; ")}",
                    details
                )
                issues.isNotEmpty() -> DirectorResult(
                    DirectorResult.Status.WARN,
                    "Memory issues found: ${issues.joinToString("; ")}",
                    details
                )
                else -> DirectorResult(
                    DirectorResult.Status.PASS,
                    "All memory checks passed",
                    details
                )
            }
            
        } catch (e: Exception) {
            return DirectorResult(
                DirectorResult.Status.ERROR,
                "Memory security check failed: ${e.message}",
                mapOf("exception" to e.javaClass.simpleName)
            )
        }
    }
    
    override fun startup() {
        monitoringEnabled = true
        scheduler = Executors.newScheduledThreadPool(1)
        
        // Schedule periodic memory monitoring
        scheduler?.scheduleAtFixedRate({
            try {
                performMemoryMaintenance()
            } catch (e: Exception) {
                println("[MemoryDirector] Error during maintenance: ${e.message}")
            }
        }, cleanupIntervalMinutes.toLong(), cleanupIntervalMinutes.toLong(), TimeUnit.MINUTES)
        
        println("[MemoryDirector] Started memory monitoring")
    }
    
    override fun shutdown() {
        monitoringEnabled = false
        scheduler?.shutdown()
        
        try {
            scheduler?.awaitTermination(30, TimeUnit.SECONDS)
        } catch (e: InterruptedException) {
            println("[MemoryDirector] Shutdown interrupted")
        }
        
        // Clear monitoring data
        memoryHistory.clear()
        allocatedObjects.clear()
        
        println("[MemoryDirector] Shutdown complete")
    }
    
    /**
     * Force garbage collection and memory cleanup
     */
    fun forceCleanup(): CleanupResult {
        val beforeSnapshot = takeMemorySnapshot()
        
        // Suggest GC
        System.gc()
        System.runFinalization()
        
        // Wait a bit for GC to complete
        Thread.sleep(100)
        
        val afterSnapshot = takeMemorySnapshot()
        
        val heapFreed = beforeSnapshot.heapUsed - afterSnapshot.heapUsed
        val nonHeapFreed = beforeSnapshot.nonHeapUsed - afterSnapshot.nonHeapUsed
        
        return CleanupResult(
            heapFreedMB = heapFreed / (1024 * 1024),
            nonHeapFreedMB = nonHeapFreed / (1024 * 1024),
            beforeUsagePercent = beforeSnapshot.heapUsagePercent,
            afterUsagePercent = afterSnapshot.heapUsagePercent
        )
    }
    
    /**
     * Get current memory status
     */
    fun getMemoryStatus(): MemoryStatus {
        val snapshot = takeMemorySnapshot()
        val memoryPressure = calculateMemoryPressure()
        
        return MemoryStatus(
            heapUsedMB = snapshot.heapUsed / (1024 * 1024),
            heapMaxMB = snapshot.heapMax / (1024 * 1024),
            heapUsagePercent = snapshot.heapUsagePercent,
            nonHeapUsedMB = snapshot.nonHeapUsed / (1024 * 1024),
            memoryPressure = memoryPressure,
            isUnderPressure = memoryPressure > 0.8,
            gcCount = snapshot.gcCount
        )
    }
    
    /**
     * Track object allocation for leak detection
     */
    fun trackAllocation(objectType: String, size: Long) {
        if (monitoringEnabled) {
            allocatedObjects[objectType] = allocatedObjects.getOrDefault(objectType, 0) + size
        }
    }
    
    /**
     * Track object deallocation
     */
    fun trackDeallocation(objectType: String, size: Long) {
        if (monitoringEnabled) {
            val current = allocatedObjects.getOrDefault(objectType, 0)
            allocatedObjects[objectType] = maxOf(0, current - size)
        }
    }
    
    private fun takeMemorySnapshot(): MemorySnapshot {
        val heapMemory = memoryBean.heapMemoryUsage
        val nonHeapMemory = memoryBean.nonHeapMemoryUsage
        val gcBeans = ManagementFactory.getGarbageCollectorMXBeans()
        val totalGcCount = gcBeans.sumOf { it.collectionCount }
        
        return MemorySnapshot(
            timestamp = System.currentTimeMillis(),
            heapUsed = heapMemory.used,
            heapMax = heapMemory.max,
            heapUsagePercent = if (heapMemory.max > 0) {
                (heapMemory.used.toDouble() / heapMemory.max.toDouble()) * 100.0
            } else 0.0,
            nonHeapUsed = nonHeapMemory.used,
            nonHeapUsagePercent = if (nonHeapMemory.max > 0) {
                (nonHeapMemory.used.toDouble() / nonHeapMemory.max.toDouble()) * 100.0
            } else 0.0,
            gcCount = totalGcCount
        )
    }
    
    private fun detectMemoryLeaks(): List<String> {
        val issues = mutableListOf<String>()
        
        if (memoryHistory.size < 5) {
            return issues // Need more history
        }
        
        val recent = memoryHistory.takeLast(5)
        val usageIncrease = recent.last().heapUsagePercent - recent.first().heapUsagePercent
        
        // Check for consistent memory growth without GC
        if (usageIncrease > 20 && !hasSignificantGC(recent)) {
            issues.add("Potential memory leak detected: consistent growth without GC")
        }
        
        // Check object allocation tracking
        allocatedObjects.forEach { (objectType, size) ->
            if (size > 100 * 1024 * 1024) { // > 100MB
                issues.add("Large object allocation detected: $objectType (${size / (1024 * 1024)}MB)")
            }
        }
        
        return issues
    }
    
    private fun checkMemoryPools(): List<String> {
        val issues = mutableListOf<String>()
        
        memoryPools.forEach { pool ->
            val usage = pool.usage
            if (usage != null && usage.max > 0) {
                val usagePercent = (usage.used.toDouble() / usage.max.toDouble()) * 100.0
                
                when {
                    usagePercent > 95 -> {
                        issues.add("Memory pool '${pool.name}' critically full: ${usagePercent.toInt()}%")
                    }
                    usagePercent > 85 -> {
                        issues.add("Memory pool '${pool.name}' high usage: ${usagePercent.toInt()}%")
                    }
                }
            }
        }
        
        return issues
    }
    
    private fun analyzePressureTrends(): List<String> {
        val issues = mutableListOf<String>()
        
        if (memoryHistory.size < 10) {
            return issues
        }
        
        val recent = memoryHistory.takeLast(10)
        val trend = calculateTrend(recent.map { it.heapUsagePercent })
        
        if (trend > 2.0) { // Increasing by more than 2% per measurement
            issues.add("Memory usage trending upward rapidly")
        }
        
        return issues
    }
    
    private fun calculateMemoryPressure(): Double {
        val snapshot = takeMemorySnapshot()
        
        val heapPressure = snapshot.heapUsagePercent / 100.0
        val nonHeapPressure = snapshot.nonHeapUsagePercent / 100.0
        
        // Weight heap pressure more heavily
        return (heapPressure * 0.7) + (nonHeapPressure * 0.3)
    }
    
    private fun hasSignificantGC(snapshots: List<MemorySnapshot>): Boolean {
        if (snapshots.size < 2) return false
        
        val gcIncrease = snapshots.last().gcCount - snapshots.first().gcCount
        return gcIncrease > 5 // Significant GC activity
    }
    
    private fun calculateTrend(values: List<Double>): Double {
        if (values.size < 2) return 0.0
        
        // Simple linear trend calculation
        val n = values.size
        val sumX = (0 until n).sum()
        val sumY = values.sum()
        val sumXY = values.withIndex().sumOf { (index, value) -> index * value }
        val sumX2 = (0 until n).sumOf { it * it }
        
        return (n * sumXY - sumX * sumY) / (n * sumX2 - sumX * sumX)
    }
    
    private fun cleanOldHistory() {
        val cutoffTime = System.currentTimeMillis() - (historyRetentionHours * 60 * 60 * 1000)
        memoryHistory.removeAll { it.timestamp < cutoffTime }
    }
    
    private fun performMemoryMaintenance() {
        // Take memory snapshot
        val snapshot = takeMemorySnapshot()
        memoryHistory.add(snapshot)
        
        // Clean old history
        cleanOldHistory()
        
        // Auto-cleanup if memory pressure is high
        val pressure = calculateMemoryPressure()
        if (pressure > memoryLeakThreshold) {
            println("[MemoryDirector] High memory pressure detected (${(pressure * 100).toInt()}%), performing cleanup")
            val result = forceCleanup()
            println("[MemoryDirector] Cleanup freed ${result.heapFreedMB}MB heap, ${result.nonHeapFreedMB}MB non-heap")
        }
        
        // Clean up tracking data
        allocatedObjects.entries.removeAll { it.value <= 0 }
    }
    
    /**
     * Memory snapshot data class
     */
    data class MemorySnapshot(
        val timestamp: Long,
        val heapUsed: Long,
        val heapMax: Long,
        val heapUsagePercent: Double,
        val nonHeapUsed: Long,
        val nonHeapUsagePercent: Double,
        val gcCount: Long
    )
    
    /**
     * Memory cleanup result
     */
    data class CleanupResult(
        val heapFreedMB: Long,
        val nonHeapFreedMB: Long,
        val beforeUsagePercent: Double,
        val afterUsagePercent: Double
    )
    
    /**
     * Current memory status
     */
    data class MemoryStatus(
        val heapUsedMB: Long,
        val heapMaxMB: Long,
        val heapUsagePercent: Double,
        val nonHeapUsedMB: Long,
        val memoryPressure: Double,
        val isUnderPressure: Boolean,
        val gcCount: Long
    )
}