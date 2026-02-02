package com.licensecm;

import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.net.*;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.time.*;
import java.time.format.DateTimeFormatter;
import java.util.*;
import java.util.concurrent.*;
import java.util.function.Consumer;

import org.json.JSONObject;
import org.json.JSONArray;

/**
 * LicenseCM Java SDK with Enhanced Security Features
 */
public class LicenseCM implements AutoCloseable {
    private final String baseUrl;
    private final String productId;
    private final String secretKey;
    private boolean useEncryption;
    private boolean autoHeartbeat;
    private long heartbeatIntervalMs;

    // Session state
    private String sessionToken;
    private Instant sessionExpires;
    private ScheduledExecutorService heartbeatExecutor;
    private String licenseKey;
    private String hwid;
    private String publicKey;

    // Callbacks
    private Runnable onSessionExpired;
    private Consumer<Map<String, Object>> onSecurityViolation;
    private Consumer<Exception> onHeartbeatFailed;

    public LicenseCM(String baseUrl, String productId, String secretKey) {
        this.baseUrl = baseUrl.replaceAll("/+$", "");
        this.productId = productId;
        this.secretKey = secretKey;
        this.useEncryption = false;
        this.autoHeartbeat = true;
        this.heartbeatIntervalMs = 5 * 60 * 1000; // 5 minutes
        this.onSessionExpired = () -> {};
        this.onSecurityViolation = (details) -> {};
        this.onHeartbeatFailed = (e) -> {};
    }

    // Builder pattern for configuration
    public LicenseCM setUseEncryption(boolean useEncryption) {
        this.useEncryption = useEncryption;
        return this;
    }

    public LicenseCM setAutoHeartbeat(boolean autoHeartbeat) {
        this.autoHeartbeat = autoHeartbeat;
        return this;
    }

    public LicenseCM setHeartbeatInterval(long intervalMs) {
        this.heartbeatIntervalMs = intervalMs;
        return this;
    }

    public LicenseCM setOnSessionExpired(Runnable callback) {
        this.onSessionExpired = callback;
        return this;
    }

    public LicenseCM setOnSecurityViolation(Consumer<Map<String, Object>> callback) {
        this.onSecurityViolation = callback;
        return this;
    }

    public LicenseCM setOnHeartbeatFailed(Consumer<Exception> callback) {
        this.onHeartbeatFailed = callback;
        return this;
    }

    /**
     * Generate Hardware ID from system information
     */
    public static String generateHwid() {
        StringBuilder components = new StringBuilder();

        // OS info
        components.append(System.getProperty("os.name")).append("|");
        components.append(System.getProperty("os.arch")).append("|");

        // Hostname
        try {
            components.append(InetAddress.getLocalHost().getHostName()).append("|");
        } catch (Exception e) {
            components.append("unknown|");
        }

        // MAC address
        try {
            Enumeration<NetworkInterface> interfaces = NetworkInterface.getNetworkInterfaces();
            while (interfaces.hasMoreElements()) {
                NetworkInterface ni = interfaces.nextElement();
                if (!ni.isLoopback() && ni.getHardwareAddress() != null) {
                    byte[] mac = ni.getHardwareAddress();
                    StringBuilder macStr = new StringBuilder();
                    for (byte b : mac) {
                        macStr.append(String.format("%02x:", b));
                    }
                    components.append(macStr.toString()).append("|");
                    break;
                }
            }
        } catch (Exception e) {
            // Ignore
        }

        // CPU cores
        components.append(Runtime.getRuntime().availableProcessors()).append("|");

        // Disk serial (Windows)
        if (System.getProperty("os.name").toLowerCase().contains("windows")) {
            try {
                Process process = Runtime.getRuntime().exec("wmic diskdrive get serialnumber");
                BufferedReader reader = new BufferedReader(new InputStreamReader(process.getInputStream()));
                reader.readLine(); // Skip header
                String serial = reader.readLine();
                if (serial != null && !serial.trim().isEmpty()) {
                    components.append(serial.trim());
                }
                reader.close();
            } catch (Exception e) {
                // Ignore
            }
        }

        // Generate SHA-256 hash
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hash = digest.digest(components.toString().getBytes(StandardCharsets.UTF_8));
            StringBuilder hexString = new StringBuilder();
            for (byte b : hash) {
                hexString.append(String.format("%02x", b));
            }
            return hexString.toString();
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
    }

    /**
     * Collect client data for security analysis
     */
    private Map<String, Object> collectClientData() {
        Map<String, Object> data = new HashMap<>();

        data.put("hwid", hwid != null ? hwid : generateHwid());
        data.put("timestamp", System.currentTimeMillis());
        data.put("platform", System.getProperty("os.name"));
        data.put("os_version", System.getProperty("os.version"));
        data.put("architecture", System.getProperty("os.arch"));

        try {
            data.put("hostname", InetAddress.getLocalHost().getHostName());
        } catch (Exception e) {
            data.put("hostname", "unknown");
        }

        data.put("java_version", System.getProperty("java.version"));
        data.put("cpu_count", Runtime.getRuntime().availableProcessors());

        // Environment indicators
        Map<String, Object> envIndicators = new HashMap<>();
        envIndicators.put("debug_mode", System.getenv("DEBUG") != null);
        envIndicators.put("java_debug", System.getProperty("java.debug") != null);
        data.put("env_indicators", envIndicators);

        // VM indicators
        data.put("vm_indicators", detectVMIndicators());

        // Debug indicators
        data.put("debug_indicators", detectDebugIndicators());

        return data;
    }

    private List<String> detectVMIndicators() {
        List<String> indicators = new ArrayList<>();

        try {
            String hostname = InetAddress.getLocalHost().getHostName().toLowerCase();
            String[] vmHostnames = {"vmware", "virtualbox", "sandbox", "virtual", "qemu"};
            for (String vm : vmHostnames) {
                if (hostname.contains(vm)) {
                    indicators.add("suspicious_hostname");
                    break;
                }
            }
        } catch (Exception e) {
            // Ignore
        }

        // Check MAC address prefixes
        String[] vmMacPrefixes = {
            "00:0c:29", "00:50:56", "00:05:69", // VMware
            "08:00:27", "0a:00:27",             // VirtualBox
            "00:15:5d",                         // Hyper-V
            "00:16:3e",                         // Xen
            "52:54:00"                          // QEMU
        };

        try {
            Enumeration<NetworkInterface> interfaces = NetworkInterface.getNetworkInterfaces();
            outer:
            while (interfaces.hasMoreElements()) {
                NetworkInterface ni = interfaces.nextElement();
                if (ni.getHardwareAddress() != null) {
                    byte[] mac = ni.getHardwareAddress();
                    String macStr = String.format("%02x:%02x:%02x",
                        mac[0], mac[1], mac[2]).toLowerCase();
                    for (String prefix : vmMacPrefixes) {
                        if (macStr.equals(prefix)) {
                            indicators.add("vm_mac_address");
                            break outer;
                        }
                    }
                }
            }
        } catch (Exception e) {
            // Ignore
        }

        // Check CPU count
        if (Runtime.getRuntime().availableProcessors() < 2) {
            indicators.add("single_cpu");
        }

        return indicators;
    }

    private List<String> detectDebugIndicators() {
        List<String> indicators = new ArrayList<>();

        // Check for debug environment variables
        if (System.getenv("DEBUG") != null) {
            indicators.add("env_debug");
        }

        // Timing analysis
        long start = System.nanoTime();
        for (int i = 0; i < 1000; i++) {
            Math.random();
        }
        long duration = (System.nanoTime() - start) / 1_000_000;

        if (duration > 100) {
            indicators.add("timing_anomaly");
        }

        return indicators;
    }

    /**
     * Encrypt data using AES-256-GCM
     */
    private Map<String, String> encrypt(String plaintext) throws Exception {
        byte[] key = Arrays.copyOf(secretKey.getBytes(StandardCharsets.UTF_8), 32);
        byte[] iv = new byte[16];
        SecureRandom.getInstanceStrong().nextBytes(iv);

        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        SecretKeySpec keySpec = new SecretKeySpec(key, "AES");
        GCMParameterSpec gcmSpec = new GCMParameterSpec(128, iv);
        cipher.init(Cipher.ENCRYPT_MODE, keySpec, gcmSpec);

        byte[] ciphertext = cipher.doFinal(plaintext.getBytes(StandardCharsets.UTF_8));

        // Last 16 bytes are the auth tag
        byte[] encryptedData = Arrays.copyOfRange(ciphertext, 0, ciphertext.length - 16);
        byte[] tag = Arrays.copyOfRange(ciphertext, ciphertext.length - 16, ciphertext.length);

        Map<String, String> result = new HashMap<>();
        result.put("iv", bytesToHex(iv));
        result.put("data", bytesToHex(encryptedData));
        result.put("tag", bytesToHex(tag));
        return result;
    }

    /**
     * Decrypt data using AES-256-GCM
     */
    private String decrypt(String ivHex, String dataHex, String tagHex) throws Exception {
        byte[] key = Arrays.copyOf(secretKey.getBytes(StandardCharsets.UTF_8), 32);
        byte[] iv = hexToBytes(ivHex);
        byte[] ciphertext = hexToBytes(dataHex);
        byte[] tag = hexToBytes(tagHex);

        // Combine ciphertext and tag
        byte[] combined = new byte[ciphertext.length + tag.length];
        System.arraycopy(ciphertext, 0, combined, 0, ciphertext.length);
        System.arraycopy(tag, 0, combined, ciphertext.length, tag.length);

        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        SecretKeySpec keySpec = new SecretKeySpec(key, "AES");
        GCMParameterSpec gcmSpec = new GCMParameterSpec(128, iv);
        cipher.init(Cipher.DECRYPT_MODE, keySpec, gcmSpec);

        byte[] plaintext = cipher.doFinal(combined);
        return new String(plaintext, StandardCharsets.UTF_8);
    }

    /**
     * Generate HMAC-SHA256 signature
     */
    private String sign(String data) throws Exception {
        Mac hmac = Mac.getInstance("HmacSHA256");
        SecretKeySpec keySpec = new SecretKeySpec(
            secretKey.getBytes(StandardCharsets.UTF_8), "HmacSHA256");
        hmac.init(keySpec);
        byte[] hash = hmac.doFinal(data.getBytes(StandardCharsets.UTF_8));
        return bytesToHex(hash);
    }

    private String bytesToHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) {
            sb.append(String.format("%02x", b));
        }
        return sb.toString();
    }

    private byte[] hexToBytes(String hex) {
        int len = hex.length();
        byte[] data = new byte[len / 2];
        for (int i = 0; i < len; i += 2) {
            data[i / 2] = (byte) ((Character.digit(hex.charAt(i), 16) << 4)
                + Character.digit(hex.charAt(i + 1), 16));
        }
        return data;
    }

    /**
     * Fetch public key from server
     */
    public void fetchPublicKey() throws Exception {
        URL url = new URL(baseUrl + "/api/client/public-key");
        HttpURLConnection conn = (HttpURLConnection) url.openConnection();
        conn.setRequestMethod("GET");

        BufferedReader reader = new BufferedReader(
            new InputStreamReader(conn.getInputStream(), StandardCharsets.UTF_8));
        StringBuilder response = new StringBuilder();
        String line;
        while ((line = reader.readLine()) != null) {
            response.append(line);
        }
        reader.close();

        JSONObject json = new JSONObject(response.toString());
        if (json.getBoolean("success")) {
            publicKey = json.getJSONObject("data").getString("public_key");
        }
    }

    /**
     * Initialize the client
     */
    public void initialize() throws Exception {
        fetchPublicKey();
    }

    /**
     * Make API request
     */
    private JSONObject request(String endpoint, Map<String, Object> data) throws Exception {
        Map<String, Object> clientData = collectClientData();

        Map<String, Object> body = new HashMap<>(data);
        body.put("product_id", productId);
        body.put("client_data", clientData);

        if (sessionToken != null) {
            body.put("session_token", sessionToken);
        }

        String jsonBody;

        if (useEncryption && secretKey != null && !secretKey.isEmpty()) {
            long timestamp = System.currentTimeMillis();
            JSONObject bodyJson = new JSONObject(body);
            Map<String, String> encrypted = encrypt(bodyJson.toString());

            String signaturePayload = String.format("%s:%s:%s:%d",
                encrypted.get("iv"), encrypted.get("data"), encrypted.get("tag"), timestamp);
            String signature = sign(signaturePayload);

            Map<String, Object> encryptedBody = new HashMap<>();
            encryptedBody.put("encrypted", true);
            encryptedBody.put("iv", encrypted.get("iv"));
            encryptedBody.put("data", encrypted.get("data"));
            encryptedBody.put("tag", encrypted.get("tag"));
            encryptedBody.put("signature", signature);
            encryptedBody.put("product_id", productId);
            encryptedBody.put("timestamp", timestamp);

            jsonBody = new JSONObject(encryptedBody).toString();
        } else {
            jsonBody = new JSONObject(body).toString();
        }

        URL url = new URL(baseUrl + "/api/client" + endpoint);
        HttpURLConnection conn = (HttpURLConnection) url.openConnection();
        conn.setRequestMethod("POST");
        conn.setRequestProperty("Content-Type", "application/json");
        conn.setDoOutput(true);

        try (OutputStream os = conn.getOutputStream()) {
            os.write(jsonBody.getBytes(StandardCharsets.UTF_8));
        }

        int responseCode = conn.getResponseCode();
        InputStream inputStream = responseCode >= 400 ?
            conn.getErrorStream() : conn.getInputStream();

        BufferedReader reader = new BufferedReader(
            new InputStreamReader(inputStream, StandardCharsets.UTF_8));
        StringBuilder response = new StringBuilder();
        String line;
        while ((line = reader.readLine()) != null) {
            response.append(line);
        }
        reader.close();

        JSONObject responseJson = new JSONObject(response.toString());

        // Decrypt if encrypted
        if (useEncryption && responseJson.optBoolean("encrypted", false)) {
            String decrypted = decrypt(
                responseJson.getString("iv"),
                responseJson.getString("data"),
                responseJson.getString("tag")
            );
            responseJson = new JSONObject(decrypted);
        }

        if (responseJson.getBoolean("success")) {
            JSONObject result = responseJson.getJSONObject("data");

            // Handle session token rotation
            if (result.has("new_token")) {
                sessionToken = result.getString("new_token");
            }

            // Handle session info
            if (result.has("session")) {
                JSONObject session = result.getJSONObject("session");
                sessionToken = session.getString("token");
                if (session.has("expires_at")) {
                    sessionExpires = Instant.parse(session.getString("expires_at"));
                }
            }

            return result;
        } else {
            // Handle security violations
            if (responseJson.optBoolean("security_blocked", false)) {
                Map<String, Object> details = new HashMap<>();
                details.put("type", "blocked");
                details.put("reason", responseJson.getString("message"));
                onSecurityViolation.accept(details);
            }

            throw new Exception(responseJson.getString("message"));
        }
    }

    /**
     * Validate a license
     */
    public JSONObject validate(String licenseKey, String hwid) throws Exception {
        this.licenseKey = licenseKey;
        this.hwid = hwid != null ? hwid : generateHwid();

        Map<String, Object> data = new HashMap<>();
        data.put("license_key", licenseKey);
        data.put("hwid", this.hwid);

        return request("/validate", data);
    }

    /**
     * Activate a license
     */
    public JSONObject activate(String licenseKey, String hwid) throws Exception {
        this.licenseKey = licenseKey;
        this.hwid = hwid != null ? hwid : generateHwid();

        Map<String, Object> data = new HashMap<>();
        data.put("license_key", licenseKey);
        data.put("hwid", this.hwid);

        JSONObject result = request("/activate", data);

        // Start heartbeat if enabled
        if (autoHeartbeat && result.has("session")) {
            startHeartbeat();
        }

        return result;
    }

    /**
     * Deactivate a license
     */
    public JSONObject deactivate(String licenseKey, String hwid) throws Exception {
        stopHeartbeat();

        if (licenseKey == null) licenseKey = this.licenseKey;
        if (hwid == null) hwid = this.hwid != null ? this.hwid : generateHwid();

        Map<String, Object> data = new HashMap<>();
        data.put("license_key", licenseKey);
        data.put("hwid", hwid);

        JSONObject result = request("/deactivate", data);

        sessionToken = null;
        sessionExpires = null;

        return result;
    }

    /**
     * Send heartbeat
     */
    public JSONObject heartbeat(String licenseKey, String hwid) throws Exception {
        if (licenseKey == null) licenseKey = this.licenseKey;
        if (hwid == null) hwid = this.hwid != null ? this.hwid : generateHwid();

        Map<String, Object> data = new HashMap<>();
        data.put("license_key", licenseKey);
        data.put("hwid", hwid);

        return request("/heartbeat", data);
    }

    /**
     * Start automatic heartbeat
     */
    public void startHeartbeat() {
        stopHeartbeat();

        heartbeatExecutor = Executors.newSingleThreadScheduledExecutor();
        heartbeatExecutor.scheduleAtFixedRate(() -> {
            try {
                heartbeat(null, null);
            } catch (Exception e) {
                onHeartbeatFailed.accept(e);

                String msg = e.getMessage().toLowerCase();
                if (msg.contains("expired") || msg.contains("invalid")) {
                    stopHeartbeat();
                    onSessionExpired.run();
                }
            }
        }, heartbeatIntervalMs, heartbeatIntervalMs, TimeUnit.MILLISECONDS);
    }

    /**
     * Stop automatic heartbeat
     */
    public void stopHeartbeat() {
        if (heartbeatExecutor != null) {
            heartbeatExecutor.shutdown();
            heartbeatExecutor = null;
        }
    }

    /**
     * Check if session is valid
     */
    public boolean isSessionValid() {
        return sessionToken != null && sessionExpires != null &&
            Instant.now().isBefore(sessionExpires);
    }

    /**
     * Get session info
     */
    public Map<String, Object> getSessionInfo() {
        Map<String, Object> info = new HashMap<>();
        info.put("token", sessionToken);
        info.put("expires", sessionExpires != null ? sessionExpires.toString() : null);
        info.put("is_valid", isSessionValid());
        return info;
    }

    @Override
    public void close() {
        stopHeartbeat();
        sessionToken = null;
        sessionExpires = null;
        licenseKey = null;
        hwid = null;
    }

    // Example usage
    public static void main(String[] args) {
        try (LicenseCM client = new LicenseCM(
            "http://localhost:3000",
            "your-product-id",
            "your-secret-key"
        )) {
            client.setUseEncryption(true)
                  .setAutoHeartbeat(true)
                  .setOnSessionExpired(() -> {
                      System.out.println("Session expired! Please re-activate.");
                      System.exit(1);
                  })
                  .setOnSecurityViolation(details -> {
                      System.out.println("Security violation: " + details);
                      System.exit(1);
                  })
                  .setOnHeartbeatFailed(e -> {
                      System.out.println("Heartbeat failed: " + e.getMessage());
                  });

            String licenseKey = "XXXX-XXXX-XXXX-XXXX";

            // Initialize
            client.initialize();

            // Activate
            JSONObject result = client.activate(licenseKey, null);
            System.out.println("License activated: " + result.toString());

            // Keep running
            System.out.println("Press Enter to exit...");
            System.in.read();

            // Deactivate
            client.deactivate(null, null);

        } catch (Exception e) {
            System.out.println("Error: " + e.getMessage());
        }
    }
}
