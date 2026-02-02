//! LicenseCM Rust SDK with Enhanced Security Features
//!
//! # Example
//! ```no_run
//! use licensecm::LicenseCMClient;
//!
//! #[tokio::main]
//! async fn main() -> Result<(), Box<dyn std::error::Error>> {
//!     let mut client = LicenseCMClient::new(
//!         "http://localhost:3000",
//!         "your-product-id",
//!         "your-secret-key",
//!     );
//!
//!     client.initialize().await?;
//!     let result = client.activate("XXXX-XXXX-XXXX-XXXX", None).await?;
//!     println!("Activated: {:?}", result);
//!
//!     Ok(())
//! }
//! ```

use aes_gcm::{
    aead::{Aead, KeyInit, Payload},
    Aes256Gcm, Nonce,
};
use hmac::{Hmac, Mac};
use reqwest::Client;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::sync::mpsc;
use tokio::time;

type HmacSha256 = Hmac<Sha256>;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClientData {
    pub hwid: String,
    pub timestamp: u64,
    pub platform: String,
    pub architecture: String,
    pub hostname: String,
    pub rust_version: String,
    pub env_indicators: HashMap<String, bool>,
    pub vm_indicators: Vec<String>,
    pub debug_indicators: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionInfo {
    pub token: Option<String>,
    pub expires: Option<String>,
    pub is_valid: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LicenseResponse {
    pub success: bool,
    pub message: Option<String>,
    pub data: Option<serde_json::Value>,
}

pub struct LicenseCMClient {
    base_url: String,
    product_id: String,
    secret_key: String,
    use_encryption: bool,
    auto_heartbeat: bool,
    heartbeat_interval: Duration,

    // Session state
    session_token: Arc<Mutex<Option<String>>>,
    session_expires: Arc<Mutex<Option<String>>>,
    license_key: Arc<Mutex<Option<String>>>,
    hwid: Arc<Mutex<Option<String>>>,
    public_key: Arc<Mutex<Option<String>>>,

    // Heartbeat control
    heartbeat_stop_tx: Option<mpsc::Sender<()>>,

    http_client: Client,
}

impl LicenseCMClient {
    pub fn new(base_url: &str, product_id: &str, secret_key: &str) -> Self {
        Self {
            base_url: base_url.trim_end_matches('/').to_string(),
            product_id: product_id.to_string(),
            secret_key: secret_key.to_string(),
            use_encryption: false,
            auto_heartbeat: true,
            heartbeat_interval: Duration::from_secs(300), // 5 minutes

            session_token: Arc::new(Mutex::new(None)),
            session_expires: Arc::new(Mutex::new(None)),
            license_key: Arc::new(Mutex::new(None)),
            hwid: Arc::new(Mutex::new(None)),
            public_key: Arc::new(Mutex::new(None)),
            heartbeat_stop_tx: None,

            http_client: Client::new(),
        }
    }

    pub fn set_use_encryption(&mut self, value: bool) -> &mut Self {
        self.use_encryption = value;
        self
    }

    pub fn set_auto_heartbeat(&mut self, value: bool) -> &mut Self {
        self.auto_heartbeat = value;
        self
    }

    pub fn set_heartbeat_interval(&mut self, duration: Duration) -> &mut Self {
        self.heartbeat_interval = duration;
        self
    }

    /// Generate Hardware ID from system information
    pub fn generate_hwid() -> String {
        let mut components = Vec::new();

        // OS info
        components.push(std::env::consts::OS.to_string());
        components.push(std::env::consts::ARCH.to_string());

        // Hostname
        if let Ok(hostname) = hostname::get() {
            components.push(hostname.to_string_lossy().to_string());
        }

        // CPU count
        components.push(num_cpus::get().to_string());

        let data = components.join("|");
        let mut hasher = Sha256::new();
        hasher.update(data.as_bytes());
        hex::encode(hasher.finalize())
    }

    fn collect_client_data(&self) -> ClientData {
        let hwid_guard = self.hwid.lock().unwrap();
        let hwid = hwid_guard.clone().unwrap_or_else(Self::generate_hwid);

        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_millis() as u64;

        let hostname = hostname::get()
            .map(|h| h.to_string_lossy().to_string())
            .unwrap_or_else(|_| "unknown".to_string());

        let mut env_indicators = HashMap::new();
        env_indicators.insert("debug_mode".to_string(), std::env::var("DEBUG").is_ok());
        env_indicators.insert("rust_backtrace".to_string(), std::env::var("RUST_BACKTRACE").is_ok());

        ClientData {
            hwid,
            timestamp,
            platform: std::env::consts::OS.to_string(),
            architecture: std::env::consts::ARCH.to_string(),
            hostname,
            rust_version: env!("CARGO_PKG_RUST_VERSION").to_string(),
            env_indicators,
            vm_indicators: self.detect_vm_indicators(),
            debug_indicators: self.detect_debug_indicators(),
        }
    }

    fn detect_vm_indicators(&self) -> Vec<String> {
        let mut indicators = Vec::new();

        // Check hostname patterns
        if let Ok(hostname) = hostname::get() {
            let hostname_lower = hostname.to_string_lossy().to_lowercase();
            let vm_hostnames = ["vmware", "virtualbox", "sandbox", "virtual", "qemu"];
            for vm in vm_hostnames {
                if hostname_lower.contains(vm) {
                    indicators.push("suspicious_hostname".to_string());
                    break;
                }
            }
        }

        // Check CPU count
        if num_cpus::get() < 2 {
            indicators.push("single_cpu".to_string());
        }

        indicators
    }

    fn detect_debug_indicators(&self) -> Vec<String> {
        let mut indicators = Vec::new();

        // Check environment variables
        if std::env::var("DEBUG").is_ok() {
            indicators.push("env_debug".to_string());
        }

        if std::env::var("RUST_BACKTRACE").is_ok() {
            indicators.push("env_rust_backtrace".to_string());
        }

        // Timing analysis
        let start = std::time::Instant::now();
        for _ in 0..1000 {
            let _ = rand::random::<u64>();
        }
        let duration = start.elapsed();

        if duration.as_millis() > 100 {
            indicators.push("timing_anomaly".to_string());
        }

        indicators
    }

    fn encrypt(&self, data: &serde_json::Value) -> Result<HashMap<String, String>, Box<dyn std::error::Error>> {
        let key = self.pad_key(&self.secret_key);
        let cipher = Aes256Gcm::new_from_slice(&key)?;

        let iv: [u8; 12] = rand::random();
        let nonce = Nonce::from_slice(&iv);

        let plaintext = serde_json::to_string(data)?;
        let ciphertext = cipher
            .encrypt(nonce, plaintext.as_bytes())
            .map_err(|e| format!("Encryption error: {}", e))?;

        // Split ciphertext and tag (last 16 bytes is the tag)
        let tag_start = ciphertext.len() - 16;
        let encrypted_data = &ciphertext[..tag_start];
        let tag = &ciphertext[tag_start..];

        let mut result = HashMap::new();
        result.insert("iv".to_string(), hex::encode(&iv));
        result.insert("data".to_string(), hex::encode(encrypted_data));
        result.insert("tag".to_string(), hex::encode(tag));

        Ok(result)
    }

    fn decrypt(&self, encrypted: &HashMap<String, serde_json::Value>) -> Result<serde_json::Value, Box<dyn std::error::Error>> {
        let key = self.pad_key(&self.secret_key);
        let cipher = Aes256Gcm::new_from_slice(&key)?;

        let iv = hex::decode(encrypted.get("iv").unwrap().as_str().unwrap())?;
        let data = hex::decode(encrypted.get("data").unwrap().as_str().unwrap())?;
        let tag = hex::decode(encrypted.get("tag").unwrap().as_str().unwrap())?;

        // Combine data and tag
        let mut ciphertext = data;
        ciphertext.extend_from_slice(&tag);

        let nonce = Nonce::from_slice(&iv[..12]);
        let plaintext = cipher
            .decrypt(nonce, ciphertext.as_ref())
            .map_err(|e| format!("Decryption error: {}", e))?;

        let result: serde_json::Value = serde_json::from_slice(&plaintext)?;
        Ok(result)
    }

    fn sign(&self, data: &str) -> String {
        let mut mac = HmacSha256::new_from_slice(self.secret_key.as_bytes())
            .expect("HMAC can take key of any size");
        mac.update(data.as_bytes());
        hex::encode(mac.finalize().into_bytes())
    }

    fn pad_key(&self, key: &str) -> [u8; 32] {
        let mut padded = [0u8; 32];
        let bytes = key.as_bytes();
        let len = std::cmp::min(bytes.len(), 32);
        padded[..len].copy_from_slice(&bytes[..len]);
        padded
    }

    /// Fetch public key from server
    pub async fn fetch_public_key(&self) -> Result<String, Box<dyn std::error::Error>> {
        let url = format!("{}/api/client/public-key", self.base_url);
        let response: serde_json::Value = self.http_client.get(&url).send().await?.json().await?;

        if response.get("success").and_then(|v| v.as_bool()).unwrap_or(false) {
            if let Some(pk) = response
                .get("data")
                .and_then(|d| d.get("public_key"))
                .and_then(|p| p.as_str())
            {
                let mut guard = self.public_key.lock().unwrap();
                *guard = Some(pk.to_string());
                return Ok(pk.to_string());
            }
        }

        Err("Failed to fetch public key".into())
    }

    /// Initialize the client
    pub async fn initialize(&self) -> Result<(), Box<dyn std::error::Error>> {
        let _ = self.fetch_public_key().await;
        Ok(())
    }

    async fn request(&self, endpoint: &str, data: serde_json::Value) -> Result<serde_json::Value, Box<dyn std::error::Error>> {
        let client_data = self.collect_client_data();

        let mut body = data.as_object().unwrap().clone();
        body.insert("product_id".to_string(), serde_json::json!(self.product_id));
        body.insert("client_data".to_string(), serde_json::to_value(&client_data)?);

        // Add session token if available
        if let Some(token) = self.session_token.lock().unwrap().as_ref() {
            body.insert("session_token".to_string(), serde_json::json!(token));
        }

        let request_body: serde_json::Value;

        if self.use_encryption && !self.secret_key.is_empty() {
            let timestamp = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_millis() as u64;

            let encrypted = self.encrypt(&serde_json::Value::Object(body.clone()))?;
            let signature_payload = format!(
                "{}:{}:{}:{}",
                encrypted.get("iv").unwrap(),
                encrypted.get("data").unwrap(),
                encrypted.get("tag").unwrap(),
                timestamp
            );
            let signature = self.sign(&signature_payload);

            request_body = serde_json::json!({
                "encrypted": true,
                "iv": encrypted.get("iv"),
                "data": encrypted.get("data"),
                "tag": encrypted.get("tag"),
                "signature": signature,
                "product_id": self.product_id,
                "timestamp": timestamp
            });
        } else {
            request_body = serde_json::Value::Object(body);
        }

        let url = format!("{}/api/client{}", self.base_url, endpoint);
        let response: serde_json::Value = self
            .http_client
            .post(&url)
            .json(&request_body)
            .send()
            .await?
            .json()
            .await?;

        // Decrypt if encrypted
        let response = if self.use_encryption
            && response.get("encrypted").and_then(|v| v.as_bool()).unwrap_or(false)
        {
            let encrypted: HashMap<String, serde_json::Value> =
                serde_json::from_value(response)?;
            self.decrypt(&encrypted)?
        } else {
            response
        };

        if response.get("success").and_then(|v| v.as_bool()).unwrap_or(false) {
            let data = response.get("data").cloned().unwrap_or(serde_json::json!({}));

            // Handle session token rotation
            if let Some(new_token) = data.get("new_token").and_then(|v| v.as_str()) {
                let mut guard = self.session_token.lock().unwrap();
                *guard = Some(new_token.to_string());
            }

            // Handle session info
            if let Some(session) = data.get("session") {
                if let Some(token) = session.get("token").and_then(|v| v.as_str()) {
                    let mut guard = self.session_token.lock().unwrap();
                    *guard = Some(token.to_string());
                }
                if let Some(expires) = session.get("expires_at").and_then(|v| v.as_str()) {
                    let mut guard = self.session_expires.lock().unwrap();
                    *guard = Some(expires.to_string());
                }
            }

            return Ok(data);
        }

        // Handle security violations
        if response.get("security_blocked").and_then(|v| v.as_bool()).unwrap_or(false) {
            // In a real implementation, you'd call a callback here
        }

        Err(response
            .get("message")
            .and_then(|v| v.as_str())
            .unwrap_or("Unknown error")
            .into())
    }

    /// Validate a license
    pub async fn validate(
        &self,
        license_key: &str,
        hwid: Option<&str>,
    ) -> Result<serde_json::Value, Box<dyn std::error::Error>> {
        {
            let mut guard = self.license_key.lock().unwrap();
            *guard = Some(license_key.to_string());
        }

        let hwid_value = hwid.map(String::from).unwrap_or_else(Self::generate_hwid);
        {
            let mut guard = self.hwid.lock().unwrap();
            *guard = Some(hwid_value.clone());
        }

        self.request(
            "/validate",
            serde_json::json!({
                "license_key": license_key,
                "hwid": hwid_value
            }),
        )
        .await
    }

    /// Activate a license
    pub async fn activate(
        &mut self,
        license_key: &str,
        hwid: Option<&str>,
    ) -> Result<serde_json::Value, Box<dyn std::error::Error>> {
        {
            let mut guard = self.license_key.lock().unwrap();
            *guard = Some(license_key.to_string());
        }

        let hwid_value = hwid.map(String::from).unwrap_or_else(Self::generate_hwid);
        {
            let mut guard = self.hwid.lock().unwrap();
            *guard = Some(hwid_value.clone());
        }

        let result = self
            .request(
                "/activate",
                serde_json::json!({
                    "license_key": license_key,
                    "hwid": hwid_value
                }),
            )
            .await?;

        // Start heartbeat if enabled
        if self.auto_heartbeat && result.get("session").is_some() {
            self.start_heartbeat();
        }

        Ok(result)
    }

    /// Deactivate a license
    pub async fn deactivate(
        &mut self,
        license_key: Option<&str>,
        hwid: Option<&str>,
    ) -> Result<serde_json::Value, Box<dyn std::error::Error>> {
        self.stop_heartbeat();

        let lk = license_key
            .map(String::from)
            .or_else(|| self.license_key.lock().unwrap().clone())
            .unwrap_or_default();

        let hw = hwid
            .map(String::from)
            .or_else(|| self.hwid.lock().unwrap().clone())
            .unwrap_or_else(Self::generate_hwid);

        let result = self
            .request(
                "/deactivate",
                serde_json::json!({
                    "license_key": lk,
                    "hwid": hw
                }),
            )
            .await?;

        *self.session_token.lock().unwrap() = None;
        *self.session_expires.lock().unwrap() = None;

        Ok(result)
    }

    /// Send heartbeat
    pub async fn heartbeat(
        &self,
        license_key: Option<&str>,
        hwid: Option<&str>,
    ) -> Result<serde_json::Value, Box<dyn std::error::Error>> {
        let lk = license_key
            .map(String::from)
            .or_else(|| self.license_key.lock().unwrap().clone())
            .unwrap_or_default();

        let hw = hwid
            .map(String::from)
            .or_else(|| self.hwid.lock().unwrap().clone())
            .unwrap_or_else(Self::generate_hwid);

        self.request(
            "/heartbeat",
            serde_json::json!({
                "license_key": lk,
                "hwid": hw
            }),
        )
        .await
    }

    /// Start automatic heartbeat
    pub fn start_heartbeat(&mut self) {
        self.stop_heartbeat();

        let (tx, mut rx) = mpsc::channel(1);
        self.heartbeat_stop_tx = Some(tx);

        let session_token = Arc::clone(&self.session_token);
        let license_key = Arc::clone(&self.license_key);
        let hwid = Arc::clone(&self.hwid);
        let base_url = self.base_url.clone();
        let product_id = self.product_id.clone();
        let interval = self.heartbeat_interval;
        let http_client = self.http_client.clone();

        tokio::spawn(async move {
            let mut interval_timer = time::interval(interval);
            loop {
                tokio::select! {
                    _ = rx.recv() => break,
                    _ = interval_timer.tick() => {
                        let lk = license_key.lock().unwrap().clone().unwrap_or_default();
                        let hw = hwid.lock().unwrap().clone().unwrap_or_else(LicenseCMClient::generate_hwid);

                        let body = serde_json::json!({
                            "license_key": lk,
                            "hwid": hw,
                            "product_id": product_id
                        });

                        let url = format!("{}/api/client/heartbeat", base_url);
                        let _ = http_client.post(&url).json(&body).send().await;
                    }
                }
            }
        });
    }

    /// Stop automatic heartbeat
    pub fn stop_heartbeat(&mut self) {
        if let Some(tx) = self.heartbeat_stop_tx.take() {
            let _ = tx.try_send(());
        }
    }

    /// Check if session is valid
    pub fn is_session_valid(&self) -> bool {
        let token = self.session_token.lock().unwrap();
        let expires = self.session_expires.lock().unwrap();

        token.is_some() && expires.is_some()
    }

    /// Get session info
    pub fn get_session_info(&self) -> SessionInfo {
        SessionInfo {
            token: self.session_token.lock().unwrap().clone(),
            expires: self.session_expires.lock().unwrap().clone(),
            is_valid: self.is_session_valid(),
        }
    }

    /// Cleanup
    pub fn destroy(&mut self) {
        self.stop_heartbeat();
        *self.session_token.lock().unwrap() = None;
        *self.session_expires.lock().unwrap() = None;
        *self.license_key.lock().unwrap() = None;
        *self.hwid.lock().unwrap() = None;
    }
}

impl Drop for LicenseCMClient {
    fn drop(&mut self) {
        self.destroy();
    }
}
