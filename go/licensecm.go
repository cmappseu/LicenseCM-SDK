// LicenseCM Go SDK with Enhanced Security Features
package licensecm

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"sync"
	"time"
)

// Client represents the LicenseCM client
type Client struct {
	BaseURL           string
	ProductID         string
	SecretKey         string
	UseEncryption     bool
	AutoHeartbeat     bool
	HeartbeatInterval time.Duration

	// Session state
	sessionToken   string
	sessionExpires *time.Time
	heartbeatStop  chan struct{}
	licenseKey     string
	hwid           string
	publicKey      string
	mu             sync.Mutex

	// Callbacks
	OnSessionExpired    func()
	OnSecurityViolation func(details map[string]interface{})
	OnHeartbeatFailed   func(err error)

	httpClient *http.Client
}

// NewClient creates a new LicenseCM client
func NewClient(baseURL, productID, secretKey string) *Client {
	return &Client{
		BaseURL:           strings.TrimRight(baseURL, "/"),
		ProductID:         productID,
		SecretKey:         secretKey,
		UseEncryption:     false,
		AutoHeartbeat:     true,
		HeartbeatInterval: 5 * time.Minute,
		httpClient:        &http.Client{Timeout: 30 * time.Second},
		OnSessionExpired:  func() {},
		OnSecurityViolation: func(details map[string]interface{}) {},
		OnHeartbeatFailed: func(err error) {},
	}
}

// GenerateHWID generates a hardware ID from system info
func GenerateHWID() string {
	var components []string

	// Platform info
	components = append(components, runtime.GOOS, runtime.GOARCH)

	// Hostname
	if hostname, err := os.Hostname(); err == nil {
		components = append(components, hostname)
	}

	// MAC address
	if interfaces, err := net.Interfaces(); err == nil {
		for _, iface := range interfaces {
			if iface.Flags&net.FlagLoopback == 0 && len(iface.HardwareAddr) > 0 {
				components = append(components, iface.HardwareAddr.String())
				break
			}
		}
	}

	// CPU count
	components = append(components, fmt.Sprintf("%d", runtime.NumCPU()))

	// Disk serial (Windows)
	if runtime.GOOS == "windows" {
		if out, err := exec.Command("wmic", "diskdrive", "get", "serialnumber").Output(); err == nil {
			lines := strings.Split(string(out), "\n")
			if len(lines) > 1 {
				serial := strings.TrimSpace(lines[1])
				if serial != "" {
					components = append(components, serial)
				}
			}
		}
	}

	data := strings.Join(components, "|")
	hash := sha256.Sum256([]byte(data))
	return hex.EncodeToString(hash[:])
}

// ClientData represents client environment data
type ClientData struct {
	HWID            string                 `json:"hwid"`
	Timestamp       int64                  `json:"timestamp"`
	Platform        string                 `json:"platform"`
	Architecture    string                 `json:"architecture"`
	Hostname        string                 `json:"hostname"`
	GoVersion       string                 `json:"go_version"`
	CPUCount        int                    `json:"cpu_count"`
	EnvIndicators   map[string]interface{} `json:"env_indicators"`
	VMIndicators    []string               `json:"vm_indicators"`
	DebugIndicators []string               `json:"debug_indicators"`
}

func (c *Client) collectClientData() ClientData {
	hostname, _ := os.Hostname()

	data := ClientData{
		HWID:         c.hwid,
		Timestamp:    time.Now().UnixMilli(),
		Platform:     runtime.GOOS,
		Architecture: runtime.GOARCH,
		Hostname:     hostname,
		GoVersion:    runtime.Version(),
		CPUCount:     runtime.NumCPU(),
		EnvIndicators: map[string]interface{}{
			"debug_mode":  os.Getenv("DEBUG") != "",
			"go_debug":    os.Getenv("GODEBUG") != "",
			"num_goroutines": runtime.NumGoroutine(),
		},
		VMIndicators:    c.detectVMIndicators(),
		DebugIndicators: c.detectDebugIndicators(),
	}

	if data.HWID == "" {
		data.HWID = GenerateHWID()
	}

	return data
}

func (c *Client) detectVMIndicators() []string {
	var indicators []string

	hostname, _ := os.Hostname()
	hostnameLower := strings.ToLower(hostname)

	// Check hostname patterns
	vmHostnames := []string{"vmware", "virtualbox", "sandbox", "virtual", "qemu"}
	for _, vm := range vmHostnames {
		if strings.Contains(hostnameLower, vm) {
			indicators = append(indicators, "suspicious_hostname")
			break
		}
	}

	// Check MAC address prefixes
	vmMacPrefixes := []string{
		"00:0c:29", "00:50:56", "00:05:69", // VMware
		"08:00:27", "0a:00:27", // VirtualBox
		"00:15:5d", // Hyper-V
		"00:16:3e", // Xen
		"52:54:00", // QEMU
	}

	if interfaces, err := net.Interfaces(); err == nil {
		for _, iface := range interfaces {
			mac := strings.ToLower(iface.HardwareAddr.String())
			for _, prefix := range vmMacPrefixes {
				if strings.HasPrefix(mac, prefix) {
					indicators = append(indicators, "vm_mac_address")
					break
				}
			}
		}
	}

	// Check CPU count
	if runtime.NumCPU() < 2 {
		indicators = append(indicators, "single_cpu")
	}

	return indicators
}

func (c *Client) detectDebugIndicators() []string {
	var indicators []string

	// Check environment variables
	debugEnvVars := []string{"DEBUG", "GODEBUG"}
	for _, env := range debugEnvVars {
		if os.Getenv(env) != "" {
			indicators = append(indicators, "env_"+strings.ToLower(env))
		}
	}

	// Timing analysis
	start := time.Now()
	for i := 0; i < 1000; i++ {
		_ = time.Now().UnixNano()
	}
	duration := time.Since(start)

	if duration.Milliseconds() > 100 {
		indicators = append(indicators, "timing_anomaly")
	}

	return indicators
}

// Encrypt encrypts data using AES-256-GCM
func (c *Client) encrypt(data interface{}) (map[string]string, error) {
	key := []byte(c.SecretKey)
	if len(key) > 32 {
		key = key[:32]
	} else if len(key) < 32 {
		key = append(key, make([]byte, 32-len(key))...)
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	iv := make([]byte, 16)
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return nil, err
	}

	plaintext, err := json.Marshal(data)
	if err != nil {
		return nil, err
	}

	ciphertext := gcm.Seal(nil, iv[:gcm.NonceSize()], plaintext, nil)

	// Separate auth tag
	tagStart := len(ciphertext) - gcm.Overhead()
	tag := ciphertext[tagStart:]
	ciphertext = ciphertext[:tagStart]

	return map[string]string{
		"iv":   hex.EncodeToString(iv),
		"data": hex.EncodeToString(ciphertext),
		"tag":  hex.EncodeToString(tag),
	}, nil
}

// Decrypt decrypts data using AES-256-GCM
func (c *Client) decrypt(encrypted map[string]interface{}) (map[string]interface{}, error) {
	key := []byte(c.SecretKey)
	if len(key) > 32 {
		key = key[:32]
	} else if len(key) < 32 {
		key = append(key, make([]byte, 32-len(key))...)
	}

	iv, _ := hex.DecodeString(encrypted["iv"].(string))
	ciphertext, _ := hex.DecodeString(encrypted["data"].(string))
	tag, _ := hex.DecodeString(encrypted["tag"].(string))

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	// Append tag to ciphertext
	ciphertext = append(ciphertext, tag...)

	plaintext, err := gcm.Open(nil, iv[:gcm.NonceSize()], ciphertext, nil)
	if err != nil {
		return nil, err
	}

	var result map[string]interface{}
	err = json.Unmarshal(plaintext, &result)
	return result, err
}

// Sign creates HMAC-SHA256 signature
func (c *Client) sign(data string) string {
	h := hmac.New(sha256.New, []byte(c.SecretKey))
	h.Write([]byte(data))
	return hex.EncodeToString(h.Sum(nil))
}

// FetchPublicKey fetches the public key from server
func (c *Client) FetchPublicKey() error {
	resp, err := c.httpClient.Get(c.BaseURL + "/api/client/public-key")
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	var result map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return err
	}

	if success, ok := result["success"].(bool); ok && success {
		if data, ok := result["data"].(map[string]interface{}); ok {
			if pk, ok := data["public_key"].(string); ok {
				c.publicKey = pk
				return nil
			}
		}
	}

	return errors.New("failed to fetch public key")
}

// Initialize initializes the client
func (c *Client) Initialize() error {
	return c.FetchPublicKey()
}

// Request makes an API request
func (c *Client) request(endpoint string, data map[string]interface{}) (map[string]interface{}, error) {
	clientData := c.collectClientData()

	body := map[string]interface{}{
		"product_id":  c.ProductID,
		"client_data": clientData,
	}

	for k, v := range data {
		body[k] = v
	}

	c.mu.Lock()
	if c.sessionToken != "" {
		body["session_token"] = c.sessionToken
	}
	c.mu.Unlock()

	var requestBody []byte
	var err error

	if c.UseEncryption && c.SecretKey != "" {
		timestamp := time.Now().UnixMilli()
		encrypted, err := c.encrypt(body)
		if err != nil {
			return nil, err
		}

		signaturePayload := fmt.Sprintf("%s:%s:%s:%d",
			encrypted["iv"], encrypted["data"], encrypted["tag"], timestamp)
		signature := c.sign(signaturePayload)

		encryptedBody := map[string]interface{}{
			"encrypted":  true,
			"iv":         encrypted["iv"],
			"data":       encrypted["data"],
			"tag":        encrypted["tag"],
			"signature":  signature,
			"product_id": c.ProductID,
			"timestamp":  timestamp,
		}
		requestBody, err = json.Marshal(encryptedBody)
	} else {
		requestBody, err = json.Marshal(body)
	}

	if err != nil {
		return nil, err
	}

	resp, err := c.httpClient.Post(
		c.BaseURL+"/api/client"+endpoint,
		"application/json",
		bytes.NewReader(requestBody),
	)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var response map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&response); err != nil {
		return nil, err
	}

	// Decrypt if encrypted
	if encrypted, ok := response["encrypted"].(bool); ok && encrypted && c.UseEncryption {
		response, err = c.decrypt(response)
		if err != nil {
			return nil, err
		}
	}

	if success, ok := response["success"].(bool); ok && success {
		data := response["data"].(map[string]interface{})

		c.mu.Lock()
		// Handle session token rotation
		if newToken, ok := data["new_token"].(string); ok {
			c.sessionToken = newToken
		}

		// Handle session info
		if session, ok := data["session"].(map[string]interface{}); ok {
			if token, ok := session["token"].(string); ok {
				c.sessionToken = token
			}
			if expiresAt, ok := session["expires_at"].(string); ok {
				if t, err := time.Parse(time.RFC3339, expiresAt); err == nil {
					c.sessionExpires = &t
				}
			}
		}
		c.mu.Unlock()

		return data, nil
	}

	// Handle security violations
	if blocked, ok := response["security_blocked"].(bool); ok && blocked {
		c.OnSecurityViolation(map[string]interface{}{
			"type":   "blocked",
			"reason": response["message"],
		})
	}

	return nil, errors.New(response["message"].(string))
}

// Validate validates a license
func (c *Client) Validate(licenseKey string, hwid string) (map[string]interface{}, error) {
	c.licenseKey = licenseKey
	if hwid == "" {
		hwid = GenerateHWID()
	}
	c.hwid = hwid

	return c.request("/validate", map[string]interface{}{
		"license_key": licenseKey,
		"hwid":        hwid,
	})
}

// Activate activates a license
func (c *Client) Activate(licenseKey string, hwid string) (map[string]interface{}, error) {
	c.licenseKey = licenseKey
	if hwid == "" {
		hwid = GenerateHWID()
	}
	c.hwid = hwid

	result, err := c.request("/activate", map[string]interface{}{
		"license_key": licenseKey,
		"hwid":        hwid,
	})

	if err == nil && c.AutoHeartbeat {
		if _, ok := result["session"]; ok {
			c.StartHeartbeat()
		}
	}

	return result, err
}

// Deactivate deactivates a license
func (c *Client) Deactivate(licenseKey, hwid string) (map[string]interface{}, error) {
	c.StopHeartbeat()

	if licenseKey == "" {
		licenseKey = c.licenseKey
	}
	if hwid == "" {
		hwid = c.hwid
		if hwid == "" {
			hwid = GenerateHWID()
		}
	}

	result, err := c.request("/deactivate", map[string]interface{}{
		"license_key": licenseKey,
		"hwid":        hwid,
	})

	c.mu.Lock()
	c.sessionToken = ""
	c.sessionExpires = nil
	c.mu.Unlock()

	return result, err
}

// Heartbeat sends a heartbeat
func (c *Client) Heartbeat(licenseKey, hwid string) (map[string]interface{}, error) {
	if licenseKey == "" {
		licenseKey = c.licenseKey
	}
	if hwid == "" {
		hwid = c.hwid
		if hwid == "" {
			hwid = GenerateHWID()
		}
	}

	return c.request("/heartbeat", map[string]interface{}{
		"license_key": licenseKey,
		"hwid":        hwid,
	})
}

// StartHeartbeat starts automatic heartbeat
func (c *Client) StartHeartbeat() {
	c.StopHeartbeat()

	c.heartbeatStop = make(chan struct{})

	go func() {
		ticker := time.NewTicker(c.HeartbeatInterval)
		defer ticker.Stop()

		for {
			select {
			case <-ticker.C:
				if _, err := c.Heartbeat("", ""); err != nil {
					c.OnHeartbeatFailed(err)

					errMsg := strings.ToLower(err.Error())
					if strings.Contains(errMsg, "expired") || strings.Contains(errMsg, "invalid") {
						c.StopHeartbeat()
						c.OnSessionExpired()
						return
					}
				}
			case <-c.heartbeatStop:
				return
			}
		}
	}()
}

// StopHeartbeat stops automatic heartbeat
func (c *Client) StopHeartbeat() {
	if c.heartbeatStop != nil {
		close(c.heartbeatStop)
		c.heartbeatStop = nil
	}
}

// IsSessionValid checks if session is valid
func (c *Client) IsSessionValid() bool {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.sessionToken == "" || c.sessionExpires == nil {
		return false
	}
	return time.Now().Before(*c.sessionExpires)
}

// GetSessionInfo returns session info
func (c *Client) GetSessionInfo() map[string]interface{} {
	c.mu.Lock()
	defer c.mu.Unlock()

	var expires interface{}
	if c.sessionExpires != nil {
		expires = c.sessionExpires.Format(time.RFC3339)
	}

	return map[string]interface{}{
		"token":    c.sessionToken,
		"expires":  expires,
		"is_valid": c.IsSessionValid(),
	}
}

// Destroy cleans up resources
func (c *Client) Destroy() {
	c.StopHeartbeat()
	c.mu.Lock()
	c.sessionToken = ""
	c.sessionExpires = nil
	c.licenseKey = ""
	c.hwid = ""
	c.mu.Unlock()
}
