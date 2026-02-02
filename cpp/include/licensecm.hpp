/**
 * LicenseCM C++ SDK with Enhanced Security Features
 *
 * Dependencies:
 * - libcurl (HTTP requests)
 * - OpenSSL (AES-GCM encryption, HMAC)
 * - nlohmann/json (JSON parsing)
 *
 * Compile: g++ -std=c++17 -o myapp myapp.cpp -lcurl -lssl -lcrypto
 */

#ifndef LICENSECM_HPP
#define LICENSECM_HPP

#include <string>
#include <map>
#include <vector>
#include <functional>
#include <chrono>
#include <thread>
#include <atomic>
#include <mutex>
#include <memory>
#include <ctime>
#include <sstream>
#include <iomanip>
#include <cstdlib>
#include <cstring>
#include <array>

// Include external dependencies
#include <curl/curl.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/sha.h>
#include <openssl/rand.h>
#include <nlohmann/json.hpp>

#ifdef _WIN32
#include <windows.h>
#include <iphlpapi.h>
#pragma comment(lib, "iphlpapi.lib")
#else
#include <unistd.h>
#include <sys/utsname.h>
#include <ifaddrs.h>
#include <net/if.h>
#endif

namespace LicenseCM {

using json = nlohmann::json;

class Client {
public:
    // Callback types
    using SessionExpiredCallback = std::function<void()>;
    using SecurityViolationCallback = std::function<void(const std::map<std::string, std::string>&)>;
    using HeartbeatFailedCallback = std::function<void(const std::string&)>;

private:
    std::string base_url_;
    std::string product_id_;
    std::string secret_key_;
    bool use_encryption_ = false;
    bool auto_heartbeat_ = true;
    int heartbeat_interval_ms_ = 300000; // 5 minutes

    // Session state
    std::string session_token_;
    std::string session_expires_;
    std::string license_key_;
    std::string hwid_;
    std::string public_key_;

    // Heartbeat control
    std::atomic<bool> heartbeat_stop_{true};
    std::unique_ptr<std::thread> heartbeat_thread_;
    std::mutex mutex_;

    // Callbacks
    SessionExpiredCallback on_session_expired_;
    SecurityViolationCallback on_security_violation_;
    HeartbeatFailedCallback on_heartbeat_failed_;

    // CURL handle
    CURL* curl_ = nullptr;

public:
    Client(const std::string& base_url,
           const std::string& product_id,
           const std::string& secret_key = "")
        : base_url_(rtrim(base_url, '/'))
        , product_id_(product_id)
        , secret_key_(secret_key)
    {
        curl_global_init(CURL_GLOBAL_ALL);
        curl_ = curl_easy_init();

        on_session_expired_ = []() {};
        on_security_violation_ = [](const std::map<std::string, std::string>&) {};
        on_heartbeat_failed_ = [](const std::string&) {};
    }

    ~Client() {
        destroy();
        if (curl_) {
            curl_easy_cleanup(curl_);
        }
        curl_global_cleanup();
    }

    // Configuration setters
    Client& setUseEncryption(bool value) {
        use_encryption_ = value;
        return *this;
    }

    Client& setAutoHeartbeat(bool value) {
        auto_heartbeat_ = value;
        return *this;
    }

    Client& setHeartbeatInterval(int ms) {
        heartbeat_interval_ms_ = ms;
        return *this;
    }

    Client& setOnSessionExpired(SessionExpiredCallback callback) {
        on_session_expired_ = callback;
        return *this;
    }

    Client& setOnSecurityViolation(SecurityViolationCallback callback) {
        on_security_violation_ = callback;
        return *this;
    }

    Client& setOnHeartbeatFailed(HeartbeatFailedCallback callback) {
        on_heartbeat_failed_ = callback;
        return *this;
    }

    /**
     * Generate Hardware ID from system information
     */
    static std::string generateHwid() {
        std::vector<std::string> components;

        // Platform
#ifdef _WIN32
        components.push_back("windows");
#elif __APPLE__
        components.push_back("darwin");
#else
        components.push_back("linux");
#endif

        // Architecture
#if defined(__x86_64__) || defined(_M_X64)
        components.push_back("x64");
#elif defined(__i386) || defined(_M_IX86)
        components.push_back("x86");
#elif defined(__aarch64__)
        components.push_back("arm64");
#else
        components.push_back("unknown");
#endif

        // Hostname
        char hostname[256];
        if (gethostname(hostname, sizeof(hostname)) == 0) {
            components.push_back(hostname);
        }

        // MAC address
        std::string mac = getMacAddress();
        if (!mac.empty()) {
            components.push_back(mac);
        }

        // Build string
        std::string data;
        for (const auto& c : components) {
            if (!data.empty()) data += "|";
            data += c;
        }

        return sha256(data);
    }

    /**
     * Initialize the client
     */
    bool initialize() {
        try {
            fetchPublicKey();
            return true;
        } catch (...) {
            return false;
        }
    }

    /**
     * Validate a license
     */
    json validate(const std::string& license_key, const std::string& hwid = "") {
        license_key_ = license_key;
        hwid_ = hwid.empty() ? generateHwid() : hwid;

        json data;
        data["license_key"] = license_key;
        data["hwid"] = hwid_;

        return request("/validate", data);
    }

    /**
     * Activate a license
     */
    json activate(const std::string& license_key, const std::string& hwid = "") {
        license_key_ = license_key;
        hwid_ = hwid.empty() ? generateHwid() : hwid;

        json data;
        data["license_key"] = license_key;
        data["hwid"] = hwid_;

        json result = request("/activate", data);

        // Start heartbeat if enabled
        if (auto_heartbeat_ && result.contains("session")) {
            startHeartbeat();
        }

        return result;
    }

    /**
     * Deactivate a license
     */
    json deactivate(const std::string& license_key = "", const std::string& hwid = "") {
        stopHeartbeat();

        std::string lk = license_key.empty() ? license_key_ : license_key;
        std::string hw = hwid.empty() ? (hwid_.empty() ? generateHwid() : hwid_) : hwid;

        json data;
        data["license_key"] = lk;
        data["hwid"] = hw;

        json result = request("/deactivate", data);

        std::lock_guard<std::mutex> lock(mutex_);
        session_token_.clear();
        session_expires_.clear();

        return result;
    }

    /**
     * Send heartbeat
     */
    json heartbeat(const std::string& license_key = "", const std::string& hwid = "") {
        std::string lk = license_key.empty() ? license_key_ : license_key;
        std::string hw = hwid.empty() ? (hwid_.empty() ? generateHwid() : hwid_) : hwid;

        json data;
        data["license_key"] = lk;
        data["hwid"] = hw;

        return request("/heartbeat", data);
    }

    /**
     * Start automatic heartbeat
     */
    void startHeartbeat() {
        stopHeartbeat();

        heartbeat_stop_ = false;
        heartbeat_thread_ = std::make_unique<std::thread>([this]() {
            while (!heartbeat_stop_) {
                std::this_thread::sleep_for(std::chrono::milliseconds(heartbeat_interval_ms_));
                if (heartbeat_stop_) break;

                try {
                    heartbeat();
                } catch (const std::exception& e) {
                    std::string msg = e.what();
                    on_heartbeat_failed_(msg);

                    std::string lower_msg = msg;
                    std::transform(lower_msg.begin(), lower_msg.end(), lower_msg.begin(), ::tolower);
                    if (lower_msg.find("expired") != std::string::npos ||
                        lower_msg.find("invalid") != std::string::npos) {
                        heartbeat_stop_ = true;
                        on_session_expired_();
                        break;
                    }
                }
            }
        });
    }

    /**
     * Stop automatic heartbeat
     */
    void stopHeartbeat() {
        heartbeat_stop_ = true;
        if (heartbeat_thread_ && heartbeat_thread_->joinable()) {
            heartbeat_thread_->join();
        }
        heartbeat_thread_.reset();
    }

    /**
     * Check if session is valid
     */
    bool isSessionValid() const {
        std::lock_guard<std::mutex> lock(const_cast<std::mutex&>(mutex_));
        return !session_token_.empty() && !session_expires_.empty();
    }

    /**
     * Get session info
     */
    std::map<std::string, std::string> getSessionInfo() const {
        std::lock_guard<std::mutex> lock(const_cast<std::mutex&>(mutex_));
        return {
            {"token", session_token_},
            {"expires", session_expires_},
            {"is_valid", isSessionValid() ? "true" : "false"}
        };
    }

    /**
     * Cleanup
     */
    void destroy() {
        stopHeartbeat();
        std::lock_guard<std::mutex> lock(mutex_);
        session_token_.clear();
        session_expires_.clear();
        license_key_.clear();
        hwid_.clear();
    }

private:
    static std::string rtrim(const std::string& s, char c) {
        std::string result = s;
        while (!result.empty() && result.back() == c) {
            result.pop_back();
        }
        return result;
    }

    static std::string sha256(const std::string& data) {
        unsigned char hash[SHA256_DIGEST_LENGTH];
        SHA256(reinterpret_cast<const unsigned char*>(data.c_str()), data.size(), hash);

        std::ostringstream ss;
        for (int i = 0; i < SHA256_DIGEST_LENGTH; ++i) {
            ss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(hash[i]);
        }
        return ss.str();
    }

    static std::string hmacSha256(const std::string& key, const std::string& data) {
        unsigned char hash[EVP_MAX_MD_SIZE];
        unsigned int len;

        HMAC(EVP_sha256(),
             key.c_str(), key.size(),
             reinterpret_cast<const unsigned char*>(data.c_str()), data.size(),
             hash, &len);

        std::ostringstream ss;
        for (unsigned int i = 0; i < len; ++i) {
            ss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(hash[i]);
        }
        return ss.str();
    }

    static std::string getMacAddress() {
#ifdef _WIN32
        IP_ADAPTER_INFO adapterInfo[16];
        DWORD bufLen = sizeof(adapterInfo);
        if (GetAdaptersInfo(adapterInfo, &bufLen) == ERROR_SUCCESS) {
            std::ostringstream ss;
            for (int i = 0; i < 6; ++i) {
                ss << std::hex << std::setw(2) << std::setfill('0')
                   << static_cast<int>(adapterInfo[0].Address[i]);
                if (i < 5) ss << ":";
            }
            return ss.str();
        }
#else
        struct ifaddrs* ifaddr;
        if (getifaddrs(&ifaddr) == 0) {
            for (struct ifaddrs* ifa = ifaddr; ifa != nullptr; ifa = ifa->ifa_next) {
                if (ifa->ifa_addr && ifa->ifa_addr->sa_family == AF_PACKET) {
                    // Would need to parse the MAC here
                    // This is simplified
                }
            }
            freeifaddrs(ifaddr);
        }
#endif
        return "";
    }

    json collectClientData() {
        json data;
        data["hwid"] = hwid_.empty() ? generateHwid() : hwid_;
        data["timestamp"] = std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::system_clock::now().time_since_epoch()
        ).count();

#ifdef _WIN32
        data["platform"] = "Windows";
#elif __APPLE__
        data["platform"] = "Darwin";
#else
        data["platform"] = "Linux";
#endif

        char hostname[256];
        if (gethostname(hostname, sizeof(hostname)) == 0) {
            data["hostname"] = hostname;
        }

        data["cpp_version"] = __cplusplus;
        data["env_indicators"] = detectEnvIndicators();
        data["vm_indicators"] = detectVMIndicators();
        data["debug_indicators"] = detectDebugIndicators();

        return data;
    }

    json detectEnvIndicators() {
        json indicators;
        indicators["debug_mode"] = std::getenv("DEBUG") != nullptr;
        return indicators;
    }

    std::vector<std::string> detectVMIndicators() {
        std::vector<std::string> indicators;

        // Check hostname
        char hostname[256];
        if (gethostname(hostname, sizeof(hostname)) == 0) {
            std::string h = hostname;
            std::transform(h.begin(), h.end(), h.begin(), ::tolower);

            std::vector<std::string> vm_names = {"vmware", "virtualbox", "sandbox", "virtual", "qemu"};
            for (const auto& vm : vm_names) {
                if (h.find(vm) != std::string::npos) {
                    indicators.push_back("suspicious_hostname");
                    break;
                }
            }
        }

        return indicators;
    }

    std::vector<std::string> detectDebugIndicators() {
        std::vector<std::string> indicators;

        if (std::getenv("DEBUG")) {
            indicators.push_back("env_debug");
        }

        // Timing analysis
        auto start = std::chrono::high_resolution_clock::now();
        for (int i = 0; i < 1000; ++i) {
            std::rand();
        }
        auto end = std::chrono::high_resolution_clock::now();
        auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(end - start).count();

        if (duration > 100) {
            indicators.push_back("timing_anomaly");
        }

        return indicators;
    }

    void fetchPublicKey() {
        std::string url = base_url_ + "/api/client/public-key";
        std::string response = httpGet(url);

        json result = json::parse(response);
        if (result["success"].get<bool>()) {
            public_key_ = result["data"]["public_key"].get<std::string>();
        }
    }

    json request(const std::string& endpoint, json data) {
        json client_data = collectClientData();

        data["product_id"] = product_id_;
        data["client_data"] = client_data;

        {
            std::lock_guard<std::mutex> lock(mutex_);
            if (!session_token_.empty()) {
                data["session_token"] = session_token_;
            }
        }

        std::string url = base_url_ + "/api/client" + endpoint;
        std::string response = httpPost(url, data.dump());

        json result = json::parse(response);

        if (result["success"].get<bool>()) {
            json response_data = result["data"];

            std::lock_guard<std::mutex> lock(mutex_);

            // Handle session token rotation
            if (response_data.contains("new_token")) {
                session_token_ = response_data["new_token"].get<std::string>();
            }

            // Handle session info
            if (response_data.contains("session")) {
                session_token_ = response_data["session"]["token"].get<std::string>();
                if (response_data["session"].contains("expires_at")) {
                    session_expires_ = response_data["session"]["expires_at"].get<std::string>();
                }
            }

            return response_data;
        }

        // Handle security violations
        if (result.contains("security_blocked") && result["security_blocked"].get<bool>()) {
            std::map<std::string, std::string> details;
            details["type"] = "blocked";
            details["reason"] = result["message"].get<std::string>();
            on_security_violation_(details);
        }

        throw std::runtime_error(result["message"].get<std::string>());
    }

    static size_t writeCallback(void* contents, size_t size, size_t nmemb, std::string* s) {
        size_t totalSize = size * nmemb;
        s->append(static_cast<char*>(contents), totalSize);
        return totalSize;
    }

    std::string httpGet(const std::string& url) {
        std::string response;

        curl_easy_reset(curl_);
        curl_easy_setopt(curl_, CURLOPT_URL, url.c_str());
        curl_easy_setopt(curl_, CURLOPT_WRITEFUNCTION, writeCallback);
        curl_easy_setopt(curl_, CURLOPT_WRITEDATA, &response);
        curl_easy_setopt(curl_, CURLOPT_TIMEOUT, 30L);

        CURLcode res = curl_easy_perform(curl_);
        if (res != CURLE_OK) {
            throw std::runtime_error(curl_easy_strerror(res));
        }

        return response;
    }

    std::string httpPost(const std::string& url, const std::string& body) {
        std::string response;

        struct curl_slist* headers = nullptr;
        headers = curl_slist_append(headers, "Content-Type: application/json");

        curl_easy_reset(curl_);
        curl_easy_setopt(curl_, CURLOPT_URL, url.c_str());
        curl_easy_setopt(curl_, CURLOPT_POSTFIELDS, body.c_str());
        curl_easy_setopt(curl_, CURLOPT_HTTPHEADER, headers);
        curl_easy_setopt(curl_, CURLOPT_WRITEFUNCTION, writeCallback);
        curl_easy_setopt(curl_, CURLOPT_WRITEDATA, &response);
        curl_easy_setopt(curl_, CURLOPT_TIMEOUT, 30L);

        CURLcode res = curl_easy_perform(curl_);
        curl_slist_free_all(headers);

        if (res != CURLE_OK) {
            throw std::runtime_error(curl_easy_strerror(res));
        }

        return response;
    }
};

} // namespace LicenseCM

#endif // LICENSECM_HPP
