/**
 * LicenseCM Kotlin SDK with Enhanced Security Features
 *
 * Dependencies:
 * - kotlinx-serialization-json
 * - ktor-client (HTTP)
 * - kotlinx-coroutines
 */

package com.licensecm

import kotlinx.coroutines.*
import kotlinx.serialization.*
import kotlinx.serialization.json.*
import java.io.*
import java.net.*
import java.security.*
import java.time.*
import java.util.*
import javax.crypto.*
import javax.crypto.spec.*
import kotlin.concurrent.timer

@Serializable
data class ClientData(
    val hwid: String,
    val timestamp: Long,
    val platform: String,
    val osVersion: String,
    val architecture: String,
    val hostname: String,
    val kotlinVersion: String,
    val envIndicators: Map<String, Boolean>,
    val vmIndicators: List<String>,
    val debugIndicators: List<String>
)

@Serializable
data class SessionInfo(
    val token: String?,
    val expires: String?,
    val isValid: Boolean
)

class LicenseCMClient(
    private val baseUrl: String,
    private val productId: String,
    private val secretKey: String = ""
) {
    var useEncryption: Boolean = false
    var autoHeartbeat: Boolean = true
    var heartbeatIntervalMs: Long = 300_000 // 5 minutes

    // Session state
    private var sessionToken: String? = null
    private var sessionExpires: Instant? = null
    private var heartbeatTimer: Timer? = null
    private var licenseKey: String? = null
    private var hwid: String? = null
    private var publicKey: String? = null

    // Callbacks
    var onSessionExpired: () -> Unit = {}
    var onSecurityViolation: (Map<String, Any?>) -> Unit = {}
    var onHeartbeatFailed: (Exception) -> Unit = {}

    private val json = Json {
        ignoreUnknownKeys = true
        encodeDefaults = true
    }

    companion object {
        /**
         * Generate Hardware ID from system information
         */
        fun generateHwid(): String {
            val components = mutableListOf<String>()

            // OS info
            components.add(System.getProperty("os.name") ?: "unknown")
            components.add(System.getProperty("os.arch") ?: "unknown")

            // Hostname
            try {
                components.add(InetAddress.getLocalHost().hostName)
            } catch (e: Exception) {
                components.add("unknown")
            }

            // MAC address
            try {
                val interfaces = NetworkInterface.getNetworkInterfaces()
                for (ni in interfaces) {
                    if (!ni.isLoopback && ni.hardwareAddress != null) {
                        val mac = ni.hardwareAddress.joinToString(":") { "%02x".format(it) }
                        components.add(mac)
                        break
                    }
                }
            } catch (e: Exception) {}

            // CPU cores
            components.add(Runtime.getRuntime().availableProcessors().toString())

            val data = components.joinToString("|")
            return sha256(data)
        }

        private fun sha256(data: String): String {
            val digest = MessageDigest.getInstance("SHA-256")
            val hash = digest.digest(data.toByteArray(Charsets.UTF_8))
            return hash.joinToString("") { "%02x".format(it) }
        }

        private fun hmacSha256(key: String, data: String): String {
            val mac = Mac.getInstance("HmacSHA256")
            val secretKey = SecretKeySpec(key.toByteArray(Charsets.UTF_8), "HmacSHA256")
            mac.init(secretKey)
            val hash = mac.doFinal(data.toByteArray(Charsets.UTF_8))
            return hash.joinToString("") { "%02x".format(it) }
        }
    }

    private fun collectClientData(): ClientData {
        val hostname = try {
            InetAddress.getLocalHost().hostName
        } catch (e: Exception) {
            "unknown"
        }

        return ClientData(
            hwid = this.hwid ?: generateHwid(),
            timestamp = System.currentTimeMillis(),
            platform = System.getProperty("os.name") ?: "unknown",
            osVersion = System.getProperty("os.version") ?: "unknown",
            architecture = System.getProperty("os.arch") ?: "unknown",
            hostname = hostname,
            kotlinVersion = KotlinVersion.CURRENT.toString(),
            envIndicators = mapOf(
                "debug_mode" to (System.getenv("DEBUG") != null)
            ),
            vmIndicators = detectVMIndicators(),
            debugIndicators = detectDebugIndicators()
        )
    }

    private fun detectVMIndicators(): List<String> {
        val indicators = mutableListOf<String>()

        // Check hostname
        try {
            val hostname = InetAddress.getLocalHost().hostName.lowercase()
            val vmHostnames = listOf("vmware", "virtualbox", "sandbox", "virtual", "qemu")
            if (vmHostnames.any { hostname.contains(it) }) {
                indicators.add("suspicious_hostname")
            }
        } catch (e: Exception) {}

        // Check MAC prefixes
        val vmMacPrefixes = listOf(
            "00:0c:29", "00:50:56", "00:05:69", // VMware
            "08:00:27", "0a:00:27",             // VirtualBox
            "00:15:5d",                         // Hyper-V
            "00:16:3e",                         // Xen
            "52:54:00"                          // QEMU
        )

        try {
            val interfaces = NetworkInterface.getNetworkInterfaces()
            for (ni in interfaces) {
                if (ni.hardwareAddress != null) {
                    val mac = ni.hardwareAddress.joinToString(":") { "%02x".format(it) }
                    if (vmMacPrefixes.any { mac.lowercase().startsWith(it) }) {
                        indicators.add("vm_mac_address")
                        break
                    }
                }
            }
        } catch (e: Exception) {}

        // Check CPU count
        if (Runtime.getRuntime().availableProcessors() < 2) {
            indicators.add("single_cpu")
        }

        return indicators
    }

    private fun detectDebugIndicators(): List<String> {
        val indicators = mutableListOf<String>()

        // Check environment variables
        if (System.getenv("DEBUG") != null) {
            indicators.add("env_debug")
        }

        // Timing analysis
        val start = System.nanoTime()
        repeat(1000) { Math.random() }
        val duration = (System.nanoTime() - start) / 1_000_000

        if (duration > 100) {
            indicators.add("timing_anomaly")
        }

        return indicators
    }

    private fun encrypt(data: String): Map<String, String> {
        val key = secretKey.padEnd(32, '\u0000').take(32).toByteArray()
        val iv = ByteArray(16).also { SecureRandom().nextBytes(it) }

        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        val keySpec = SecretKeySpec(key, "AES")
        val gcmSpec = GCMParameterSpec(128, iv)
        cipher.init(Cipher.ENCRYPT_MODE, keySpec, gcmSpec)

        val ciphertext = cipher.doFinal(data.toByteArray(Charsets.UTF_8))

        // Split ciphertext and tag
        val encryptedData = ciphertext.take(ciphertext.size - 16).toByteArray()
        val tag = ciphertext.takeLast(16).toByteArray()

        return mapOf(
            "iv" to iv.joinToString("") { "%02x".format(it) },
            "data" to encryptedData.joinToString("") { "%02x".format(it) },
            "tag" to tag.joinToString("") { "%02x".format(it) }
        )
    }

    private fun sign(data: String): String {
        return hmacSha256(secretKey, data)
    }

    /**
     * Fetch public key from server
     */
    fun fetchPublicKey(): String? {
        val url = URL("$baseUrl/api/client/public-key")
        val conn = url.openConnection() as HttpURLConnection
        conn.requestMethod = "GET"
        conn.connectTimeout = 30000
        conn.readTimeout = 30000

        return try {
            val response = conn.inputStream.bufferedReader().readText()
            val result = json.parseToJsonElement(response).jsonObject

            if (result["success"]?.jsonPrimitive?.boolean == true) {
                publicKey = result["data"]?.jsonObject?.get("public_key")?.jsonPrimitive?.content
                publicKey
            } else null
        } catch (e: Exception) {
            null
        } finally {
            conn.disconnect()
        }
    }

    /**
     * Initialize the client
     */
    fun initialize(): Boolean {
        return try {
            fetchPublicKey()
            true
        } catch (e: Exception) {
            false
        }
    }

    private fun request(endpoint: String, data: Map<String, Any?>): JsonObject {
        val clientData = collectClientData()

        val body = data.toMutableMap()
        body["product_id"] = productId
        body["client_data"] = json.encodeToJsonElement(clientData)

        sessionToken?.let { body["session_token"] = it }

        val requestBody: String
        if (useEncryption && secretKey.isNotEmpty()) {
            val timestamp = System.currentTimeMillis()
            val encrypted = encrypt(json.encodeToString(body))
            val signaturePayload = "${encrypted["iv"]}:${encrypted["data"]}:${encrypted["tag"]}:$timestamp"
            val signature = sign(signaturePayload)

            requestBody = json.encodeToString(mapOf(
                "encrypted" to true,
                "iv" to encrypted["iv"],
                "data" to encrypted["data"],
                "tag" to encrypted["tag"],
                "signature" to signature,
                "product_id" to productId,
                "timestamp" to timestamp
            ))
        } else {
            requestBody = json.encodeToString(body)
        }

        val url = URL("$baseUrl/api/client$endpoint")
        val conn = url.openConnection() as HttpURLConnection
        conn.requestMethod = "POST"
        conn.setRequestProperty("Content-Type", "application/json")
        conn.doOutput = true
        conn.connectTimeout = 30000
        conn.readTimeout = 30000

        conn.outputStream.use { it.write(requestBody.toByteArray(Charsets.UTF_8)) }

        val responseText = try {
            conn.inputStream.bufferedReader().readText()
        } catch (e: IOException) {
            conn.errorStream?.bufferedReader()?.readText() ?: throw e
        }

        val response = json.parseToJsonElement(responseText).jsonObject

        return if (response["success"]?.jsonPrimitive?.boolean == true) {
            val result = response["data"]?.jsonObject ?: JsonObject(emptyMap())

            // Handle session token rotation
            result["new_token"]?.jsonPrimitive?.contentOrNull?.let {
                sessionToken = it
            }

            // Handle session info
            result["session"]?.jsonObject?.let { session ->
                sessionToken = session["token"]?.jsonPrimitive?.contentOrNull
                session["expires_at"]?.jsonPrimitive?.contentOrNull?.let {
                    sessionExpires = Instant.parse(it)
                }
            }

            result
        } else {
            // Handle security violations
            if (response["security_blocked"]?.jsonPrimitive?.boolean == true) {
                onSecurityViolation(mapOf(
                    "type" to "blocked",
                    "reason" to (response["message"]?.jsonPrimitive?.contentOrNull)
                ))
            }

            throw Exception(response["message"]?.jsonPrimitive?.contentOrNull ?: "Unknown error")
        }.also {
            conn.disconnect()
        }
    }

    /**
     * Validate a license
     */
    fun validate(licenseKey: String, hwid: String? = null): JsonObject {
        this.licenseKey = licenseKey
        this.hwid = hwid ?: generateHwid()

        return request("/validate", mapOf(
            "license_key" to licenseKey,
            "hwid" to this.hwid
        ))
    }

    /**
     * Activate a license
     */
    fun activate(licenseKey: String, hwid: String? = null): JsonObject {
        this.licenseKey = licenseKey
        this.hwid = hwid ?: generateHwid()

        val result = request("/activate", mapOf(
            "license_key" to licenseKey,
            "hwid" to this.hwid
        ))

        // Start heartbeat if enabled
        if (autoHeartbeat && result.containsKey("session")) {
            startHeartbeat()
        }

        return result
    }

    /**
     * Deactivate a license
     */
    fun deactivate(licenseKey: String? = null, hwid: String? = null): JsonObject {
        stopHeartbeat()

        val lk = licenseKey ?: this.licenseKey ?: ""
        val hw = hwid ?: this.hwid ?: generateHwid()

        val result = request("/deactivate", mapOf(
            "license_key" to lk,
            "hwid" to hw
        ))

        sessionToken = null
        sessionExpires = null

        return result
    }

    /**
     * Send heartbeat
     */
    fun heartbeat(licenseKey: String? = null, hwid: String? = null): JsonObject {
        val lk = licenseKey ?: this.licenseKey ?: ""
        val hw = hwid ?: this.hwid ?: generateHwid()

        return request("/heartbeat", mapOf(
            "license_key" to lk,
            "hwid" to hw
        ))
    }

    /**
     * Start automatic heartbeat
     */
    fun startHeartbeat() {
        stopHeartbeat()

        heartbeatTimer = timer(period = heartbeatIntervalMs) {
            try {
                heartbeat()
            } catch (e: Exception) {
                onHeartbeatFailed(e)

                val msg = e.message?.lowercase() ?: ""
                if (msg.contains("expired") || msg.contains("invalid")) {
                    stopHeartbeat()
                    onSessionExpired()
                }
            }
        }
    }

    /**
     * Stop automatic heartbeat
     */
    fun stopHeartbeat() {
        heartbeatTimer?.cancel()
        heartbeatTimer = null
    }

    /**
     * Check if session is valid
     */
    fun isSessionValid(): Boolean {
        return sessionToken != null && sessionExpires != null &&
                Instant.now().isBefore(sessionExpires)
    }

    /**
     * Get session info
     */
    fun getSessionInfo(): SessionInfo {
        return SessionInfo(
            token = sessionToken,
            expires = sessionExpires?.toString(),
            isValid = isSessionValid()
        )
    }

    /**
     * Cleanup
     */
    fun destroy() {
        stopHeartbeat()
        sessionToken = null
        sessionExpires = null
        licenseKey = null
        hwid = null
    }
}

// Example usage
fun main() {
    val client = LicenseCMClient(
        baseUrl = "http://localhost:3000",
        productId = "your-product-id",
        secretKey = "your-secret-key"
    ).apply {
        useEncryption = true
        autoHeartbeat = true
        onSessionExpired = {
            println("Session expired! Please re-activate.")
            System.exit(1)
        }
        onSecurityViolation = { details ->
            println("Security violation: $details")
            System.exit(1)
        }
        onHeartbeatFailed = { error ->
            println("Heartbeat failed: ${error.message}")
        }
    }

    val licenseKey = "XXXX-XXXX-XXXX-XXXX"

    try {
        // Initialize
        client.initialize()

        // Activate
        val result = client.activate(licenseKey)
        println("License activated: $result")

        // Session info
        println("Session: ${client.getSessionInfo()}")

        // Keep running
        println("Press Enter to exit...")
        readLine()

        // Deactivate
        client.deactivate()

    } catch (e: Exception) {
        println("Error: ${e.message}")
    } finally {
        client.destroy()
    }
}
