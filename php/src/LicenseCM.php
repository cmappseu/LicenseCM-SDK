<?php
/**
 * LicenseCM PHP SDK with Enhanced Security Features
 *
 * @package LicenseCM
 * @version 1.0.0
 */

namespace LicenseCM;

class LicenseCMClient
{
    private string $baseUrl;
    private string $productId;
    private string $secretKey;
    private bool $useEncryption = false;
    private bool $autoHeartbeat = true;
    private int $heartbeatInterval = 300; // 5 minutes in seconds

    // Session state
    private ?string $sessionToken = null;
    private ?\DateTime $sessionExpires = null;
    private ?string $licenseKey = null;
    private ?string $hwid = null;
    private ?string $publicKey = null;

    // Callbacks
    private $onSessionExpired;
    private $onSecurityViolation;
    private $onHeartbeatFailed;

    public function __construct(
        string $baseUrl,
        string $productId,
        string $secretKey = ''
    ) {
        $this->baseUrl = rtrim($baseUrl, '/');
        $this->productId = $productId;
        $this->secretKey = $secretKey;

        $this->onSessionExpired = function() {};
        $this->onSecurityViolation = function($details) {};
        $this->onHeartbeatFailed = function($error) {};
    }

    // Setters for configuration
    public function setUseEncryption(bool $value): self
    {
        $this->useEncryption = $value;
        return $this;
    }

    public function setAutoHeartbeat(bool $value): self
    {
        $this->autoHeartbeat = $value;
        return $this;
    }

    public function setHeartbeatInterval(int $seconds): self
    {
        $this->heartbeatInterval = $seconds;
        return $this;
    }

    public function setOnSessionExpired(callable $callback): self
    {
        $this->onSessionExpired = $callback;
        return $this;
    }

    public function setOnSecurityViolation(callable $callback): self
    {
        $this->onSecurityViolation = $callback;
        return $this;
    }

    public function setOnHeartbeatFailed(callable $callback): self
    {
        $this->onHeartbeatFailed = $callback;
        return $this;
    }

    /**
     * Generate Hardware ID from system information
     */
    public static function generateHwid(): string
    {
        $components = [];

        // OS info
        $components[] = PHP_OS;
        $components[] = php_uname('m');
        $components[] = gethostname();

        // MAC address
        $mac = self::getMacAddress();
        if ($mac) {
            $components[] = $mac;
        }

        // Disk serial (Windows)
        if (strtoupper(substr(PHP_OS, 0, 3)) === 'WIN') {
            $serial = self::getDiskSerial();
            if ($serial) {
                $components[] = $serial;
            }
        }

        $data = implode('|', $components);
        return hash('sha256', $data);
    }

    private static function getMacAddress(): ?string
    {
        if (strtoupper(substr(PHP_OS, 0, 3)) === 'WIN') {
            $output = shell_exec('getmac');
            if (preg_match('/([0-9A-F]{2}[:-]){5}[0-9A-F]{2}/i', $output, $matches)) {
                return $matches[0];
            }
        } else {
            $output = shell_exec("ip link show 2>/dev/null | grep -oE 'link/ether [0-9a-f:]+' | head -1");
            if ($output && preg_match('/([0-9a-f]{2}:){5}[0-9a-f]{2}/i', $output, $matches)) {
                return $matches[0];
            }
        }
        return null;
    }

    private static function getDiskSerial(): ?string
    {
        $output = shell_exec('wmic diskdrive get serialnumber 2>nul');
        if ($output) {
            $lines = explode("\n", trim($output));
            if (isset($lines[1])) {
                return trim($lines[1]);
            }
        }
        return null;
    }

    /**
     * Collect client data for security analysis
     */
    private function collectClientData(): array
    {
        return [
            'hwid' => $this->hwid ?? self::generateHwid(),
            'timestamp' => (int)(microtime(true) * 1000),
            'platform' => PHP_OS,
            'os_version' => php_uname('r'),
            'architecture' => php_uname('m'),
            'hostname' => gethostname(),
            'php_version' => PHP_VERSION,
            'env_indicators' => [
                'debug_mode' => getenv('DEBUG') !== false,
                'display_errors' => ini_get('display_errors') === '1',
            ],
            'vm_indicators' => $this->detectVMIndicators(),
            'debug_indicators' => $this->detectDebugIndicators(),
        ];
    }

    private function detectVMIndicators(): array
    {
        $indicators = [];

        // Check hostname patterns
        $hostname = strtolower(gethostname());
        $vmHostnames = ['vmware', 'virtualbox', 'sandbox', 'virtual', 'qemu'];
        foreach ($vmHostnames as $vm) {
            if (strpos($hostname, $vm) !== false) {
                $indicators[] = 'suspicious_hostname';
                break;
            }
        }

        // Check MAC address prefixes
        $mac = self::getMacAddress();
        if ($mac) {
            $vmMacPrefixes = [
                '00:0c:29', '00:50:56', '00:05:69', // VMware
                '08:00:27', '0a:00:27',             // VirtualBox
                '00:15:5d',                         // Hyper-V
                '00:16:3e',                         // Xen
                '52:54:00',                         // QEMU
            ];

            $macLower = strtolower($mac);
            foreach ($vmMacPrefixes as $prefix) {
                if (strpos($macLower, $prefix) === 0) {
                    $indicators[] = 'vm_mac_address';
                    break;
                }
            }
        }

        return $indicators;
    }

    private function detectDebugIndicators(): array
    {
        $indicators = [];

        // Check environment variables
        if (getenv('DEBUG') !== false) {
            $indicators[] = 'env_debug';
        }

        if (getenv('XDEBUG_SESSION') !== false) {
            $indicators[] = 'xdebug_session';
        }

        // Timing analysis
        $start = hrtime(true);
        for ($i = 0; $i < 1000; $i++) {
            random_int(0, 1000);
        }
        $duration = (hrtime(true) - $start) / 1e6;

        if ($duration > 100) {
            $indicators[] = 'timing_anomaly';
        }

        return $indicators;
    }

    /**
     * Encrypt data using AES-256-GCM
     */
    private function encrypt(array $data): array
    {
        $key = substr(str_pad($this->secretKey, 32, "\0"), 0, 32);
        $iv = random_bytes(16);
        $plaintext = json_encode($data);

        $ciphertext = openssl_encrypt(
            $plaintext,
            'aes-256-gcm',
            $key,
            OPENSSL_RAW_DATA,
            $iv,
            $tag,
            '',
            16
        );

        return [
            'iv' => bin2hex($iv),
            'data' => bin2hex($ciphertext),
            'tag' => bin2hex($tag),
        ];
    }

    /**
     * Decrypt data using AES-256-GCM
     */
    private function decrypt(array $encrypted): array
    {
        $key = substr(str_pad($this->secretKey, 32, "\0"), 0, 32);
        $iv = hex2bin($encrypted['iv']);
        $ciphertext = hex2bin($encrypted['data']);
        $tag = hex2bin($encrypted['tag']);

        $plaintext = openssl_decrypt(
            $ciphertext,
            'aes-256-gcm',
            $key,
            OPENSSL_RAW_DATA,
            $iv,
            $tag
        );

        return json_decode($plaintext, true);
    }

    /**
     * Generate HMAC-SHA256 signature
     */
    private function sign(string $data): string
    {
        return hash_hmac('sha256', $data, $this->secretKey);
    }

    /**
     * Fetch public key from server
     */
    public function fetchPublicKey(): ?string
    {
        $ch = curl_init($this->baseUrl . '/api/client/public-key');
        curl_setopt_array($ch, [
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_TIMEOUT => 30,
        ]);

        $response = curl_exec($ch);
        curl_close($ch);

        if ($response) {
            $data = json_decode($response, true);
            if ($data['success'] ?? false) {
                $this->publicKey = $data['data']['public_key'] ?? null;
                return $this->publicKey;
            }
        }

        return null;
    }

    /**
     * Initialize the client
     */
    public function initialize(): bool
    {
        try {
            $this->fetchPublicKey();
            return true;
        } catch (\Exception $e) {
            return false;
        }
    }

    /**
     * Make API request
     */
    private function request(string $endpoint, array $data): array
    {
        $clientData = $this->collectClientData();

        $body = array_merge($data, [
            'product_id' => $this->productId,
            'client_data' => $clientData,
        ]);

        if ($this->sessionToken) {
            $body['session_token'] = $this->sessionToken;
        }

        if ($this->useEncryption && $this->secretKey) {
            $timestamp = (int)(microtime(true) * 1000);
            $encrypted = $this->encrypt($body);
            $signaturePayload = sprintf(
                '%s:%s:%s:%d',
                $encrypted['iv'],
                $encrypted['data'],
                $encrypted['tag'],
                $timestamp
            );
            $signature = $this->sign($signaturePayload);

            $body = [
                'encrypted' => true,
                'iv' => $encrypted['iv'],
                'data' => $encrypted['data'],
                'tag' => $encrypted['tag'],
                'signature' => $signature,
                'product_id' => $this->productId,
                'timestamp' => $timestamp,
            ];
        }

        $ch = curl_init($this->baseUrl . '/api/client' . $endpoint);
        curl_setopt_array($ch, [
            CURLOPT_POST => true,
            CURLOPT_POSTFIELDS => json_encode($body),
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_HTTPHEADER => ['Content-Type: application/json'],
            CURLOPT_TIMEOUT => 30,
        ]);

        $response = curl_exec($ch);
        $httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
        curl_close($ch);

        if (!$response) {
            throw new \Exception('Failed to connect to server');
        }

        $responseData = json_decode($response, true);

        // Decrypt if encrypted
        if ($this->useEncryption && ($responseData['encrypted'] ?? false)) {
            $responseData = $this->decrypt($responseData);
        }

        if ($responseData['success'] ?? false) {
            $result = $responseData['data'] ?? [];

            // Handle session token rotation
            if (isset($result['new_token'])) {
                $this->sessionToken = $result['new_token'];
            }

            // Handle session info
            if (isset($result['session'])) {
                $this->sessionToken = $result['session']['token'] ?? null;
                if (isset($result['session']['expires_at'])) {
                    $this->sessionExpires = new \DateTime($result['session']['expires_at']);
                }
            }

            return $result;
        }

        // Handle security violations
        if ($responseData['security_blocked'] ?? false) {
            ($this->onSecurityViolation)([
                'type' => 'blocked',
                'reason' => $responseData['message'] ?? 'Unknown',
            ]);
        }

        throw new \Exception($responseData['message'] ?? 'Unknown error');
    }

    /**
     * Validate a license
     */
    public function validate(string $licenseKey, ?string $hwid = null): array
    {
        $this->licenseKey = $licenseKey;
        $this->hwid = $hwid ?? self::generateHwid();

        return $this->request('/validate', [
            'license_key' => $licenseKey,
            'hwid' => $this->hwid,
        ]);
    }

    /**
     * Activate a license
     */
    public function activate(string $licenseKey, ?string $hwid = null): array
    {
        $this->licenseKey = $licenseKey;
        $this->hwid = $hwid ?? self::generateHwid();

        $result = $this->request('/activate', [
            'license_key' => $licenseKey,
            'hwid' => $this->hwid,
        ]);

        return $result;
    }

    /**
     * Deactivate a license
     */
    public function deactivate(?string $licenseKey = null, ?string $hwid = null): array
    {
        $licenseKey = $licenseKey ?? $this->licenseKey;
        $hwid = $hwid ?? $this->hwid ?? self::generateHwid();

        $result = $this->request('/deactivate', [
            'license_key' => $licenseKey,
            'hwid' => $hwid,
        ]);

        $this->sessionToken = null;
        $this->sessionExpires = null;

        return $result;
    }

    /**
     * Send heartbeat
     */
    public function heartbeat(?string $licenseKey = null, ?string $hwid = null): array
    {
        $licenseKey = $licenseKey ?? $this->licenseKey;
        $hwid = $hwid ?? $this->hwid ?? self::generateHwid();

        return $this->request('/heartbeat', [
            'license_key' => $licenseKey,
            'hwid' => $hwid,
        ]);
    }

    /**
     * Check if session is valid
     */
    public function isSessionValid(): bool
    {
        if (!$this->sessionToken || !$this->sessionExpires) {
            return false;
        }
        return new \DateTime() < $this->sessionExpires;
    }

    /**
     * Get session info
     */
    public function getSessionInfo(): array
    {
        return [
            'token' => $this->sessionToken,
            'expires' => $this->sessionExpires ? $this->sessionExpires->format('c') : null,
            'is_valid' => $this->isSessionValid(),
        ];
    }

    /**
     * Cleanup
     */
    public function destroy(): void
    {
        $this->sessionToken = null;
        $this->sessionExpires = null;
        $this->licenseKey = null;
        $this->hwid = null;
    }
}

// Example usage
if (basename(__FILE__) === basename($_SERVER['PHP_SELF'] ?? '')) {
    $client = new LicenseCMClient(
        'http://localhost:3000',
        'your-product-id',
        'your-secret-key'
    );

    $client->setUseEncryption(true)
           ->setAutoHeartbeat(true)
           ->setOnSessionExpired(function() {
               echo "Session expired! Please re-activate.\n";
               exit(1);
           })
           ->setOnSecurityViolation(function($details) {
               echo "Security violation: " . json_encode($details) . "\n";
               exit(1);
           })
           ->setOnHeartbeatFailed(function($error) {
               echo "Heartbeat failed: " . $error . "\n";
           });

    $licenseKey = 'XXXX-XXXX-XXXX-XXXX';

    try {
        // Initialize
        $client->initialize();

        // Activate
        $result = $client->activate($licenseKey);
        echo "License activated: " . json_encode($result) . "\n";

        // Heartbeat example (in a real app, you'd use a cron job or background process)
        // $client->heartbeat();

    } catch (\Exception $e) {
        echo "Error: " . $e->getMessage() . "\n";
    }
}
