const crypto = require('crypto');
const https = require('https');
const http = require('http');
const os = require('os');
const { execSync } = require('child_process');

class LicenseCM {
  constructor(options) {
    this.baseUrl = options.baseUrl || 'http://localhost:3000';
    this.productId = options.productId;
    this.secretKey = options.secretKey;
    this.useEncryption = options.useEncryption || false;
    this.autoHeartbeat = options.autoHeartbeat !== false;
    this.heartbeatInterval = options.heartbeatInterval || 5 * 60 * 1000; // 5 minutes

    // Session state
    this.sessionToken = null;
    this.sessionExpires = null;
    this.heartbeatTimer = null;
    this.licenseKey = null;
    this.hwid = null;

    // Public key for signature verification (fetched from server)
    this.publicKey = null;

    // Security callbacks
    this.onSessionExpired = options.onSessionExpired || (() => {});
    this.onSecurityViolation = options.onSecurityViolation || (() => {});
    this.onHeartbeatFailed = options.onHeartbeatFailed || (() => {});
  }

  // Enhanced HWID generation with more hardware components
  static generateHwid() {
    const cpus = os.cpus();
    const networkInterfaces = os.networkInterfaces();

    // Get primary MAC address
    const mac = Object.values(networkInterfaces)
      .flat()
      .find(i => !i.internal && i.mac !== '00:00:00:00:00:00')?.mac || '';

    // Get disk serial (platform-specific)
    let diskSerial = '';
    try {
      if (os.platform() === 'win32') {
        diskSerial = execSync('wmic diskdrive get serialnumber', { encoding: 'utf8' })
          .split('\n')[1]?.trim() || '';
      } else if (os.platform() === 'linux') {
        diskSerial = execSync('cat /sys/class/dmi/id/product_serial 2>/dev/null || echo ""', { encoding: 'utf8' }).trim();
      } else if (os.platform() === 'darwin') {
        diskSerial = execSync('ioreg -l | grep IOPlatformSerialNumber', { encoding: 'utf8' })
          .match(/= "(.+)"/)?.[1] || '';
      }
    } catch (e) {
      // Disk serial not available
    }

    const components = {
      platform: os.platform(),
      arch: os.arch(),
      cpuModel: cpus[0]?.model || '',
      cpuCores: cpus.length,
      totalMemory: os.totalmem(),
      hostname: os.hostname(),
      mac: mac,
      diskSerial: diskSerial
    };

    const data = Object.values(components).join('|');
    return crypto.createHash('sha256').update(data).digest('hex');
  }

  // Collect extended client data for security analysis
  collectClientData() {
    const data = {
      hwid: this.hwid || LicenseCM.generateHwid(),
      timestamp: Date.now(),
      platform: os.platform(),
      os_version: os.release(),
      architecture: os.arch(),
      hostname: os.hostname(),
      uptime: os.uptime(),
      total_memory: os.totalmem(),
      free_memory: os.freemem(),
      cpu_model: os.cpus()[0]?.model,
      cpu_cores: os.cpus().length,

      // Environment indicators
      env_indicators: {
        node_env: process.env.NODE_ENV,
        debug_mode: !!process.env.DEBUG,
        is_electron: !!process.versions.electron,
        process_title: process.title
      },

      // Runtime info
      runtime: {
        node_version: process.version,
        pid: process.pid,
        ppid: process.ppid,
        exec_path: process.execPath
      }
    };

    // Detect VM/Sandbox indicators
    data.vm_indicators = this.detectVMIndicators();

    // Detect debug indicators
    data.debug_indicators = this.detectDebugIndicators();

    return data;
  }

  // Detect VM/Sandbox environment
  detectVMIndicators() {
    const indicators = [];
    const hostname = os.hostname().toLowerCase();

    // Check hostname patterns
    const vmHostnames = ['vmware', 'virtualbox', 'sandbox', 'virtual'];
    if (vmHostnames.some(vm => hostname.includes(vm))) {
      indicators.push('suspicious_hostname');
    }

    // Check MAC address prefixes for known VM vendors
    const vmMacPrefixes = [
      '00:0c:29', '00:50:56', '00:05:69', // VMware
      '08:00:27', '0a:00:27',              // VirtualBox
      '00:15:5d',                           // Hyper-V
      '00:16:3e',                           // Xen
      '52:54:00'                            // QEMU
    ];

    const macs = Object.values(os.networkInterfaces())
      .flat()
      .filter(i => !i.internal)
      .map(i => i.mac?.toLowerCase());

    for (const mac of macs) {
      if (vmMacPrefixes.some(prefix => mac?.startsWith(prefix))) {
        indicators.push('vm_mac_address');
        break;
      }
    }

    // Check for low resources (typical of sandboxes)
    if (os.totalmem() < 2 * 1024 * 1024 * 1024) { // Less than 2GB RAM
      indicators.push('low_memory');
    }

    if (os.cpus().length < 2) {
      indicators.push('single_cpu');
    }

    return indicators;
  }

  // Detect debugger/reverse engineering
  detectDebugIndicators() {
    const indicators = [];

    // Check for debug environment variables
    const debugEnvVars = ['DEBUG', 'NODE_DEBUG', 'ELECTRON_ENABLE_LOGGING'];
    for (const envVar of debugEnvVars) {
      if (process.env[envVar]) {
        indicators.push(`env_${envVar.toLowerCase()}`);
      }
    }

    // Check if running under electron dev tools
    if (process.env.ELECTRON_RUN_AS_NODE) {
      indicators.push('electron_dev_mode');
    }

    // Timing analysis (basic)
    const start = process.hrtime.bigint();
    // Perform some operations
    for (let i = 0; i < 1000; i++) {
      Math.random();
    }
    const end = process.hrtime.bigint();
    const duration = Number(end - start) / 1e6; // Convert to milliseconds

    // If operations take too long, might be stepping through
    if (duration > 100) {
      indicators.push('timing_anomaly');
    }

    return indicators;
  }

  // Encrypt payload (for secure communication)
  encrypt(data, key) {
    const iv = crypto.randomBytes(16);
    const keyBuffer = Buffer.from(key, 'utf8').slice(0, 32);
    const cipher = crypto.createCipheriv('aes-256-gcm', keyBuffer, iv);

    let encrypted = cipher.update(JSON.stringify(data), 'utf8', 'hex');
    encrypted += cipher.final('hex');

    const authTag = cipher.getAuthTag();

    return {
      iv: iv.toString('hex'),
      data: encrypted,
      tag: authTag.toString('hex')
    };
  }

  // Decrypt response
  decrypt(encryptedData, key) {
    const iv = Buffer.from(encryptedData.iv, 'hex');
    const authTag = Buffer.from(encryptedData.tag, 'hex');
    const keyBuffer = Buffer.from(key, 'utf8').slice(0, 32);
    const decipher = crypto.createDecipheriv('aes-256-gcm', keyBuffer, iv);

    decipher.setAuthTag(authTag);

    let decrypted = decipher.update(encryptedData.data, 'hex', 'utf8');
    decrypted += decipher.final('utf8');

    return JSON.parse(decrypted);
  }

  // Generate signature
  sign(data, secretKey) {
    const payload = typeof data === 'string' ? data : JSON.stringify(data);
    return crypto.createHmac('sha256', secretKey).update(payload).digest('hex');
  }

  // Verify RSA signature from server
  verifySignature(data, signature, algorithm = 'RSA-SHA512') {
    if (!this.publicKey) {
      console.warn('Public key not available for signature verification');
      return true; // Skip verification if no public key
    }

    const verify = crypto.createVerify(algorithm);
    verify.update(JSON.stringify(data));
    return verify.verify(this.publicKey, signature, 'base64');
  }

  // Fetch public key from server
  async fetchPublicKey() {
    return new Promise((resolve, reject) => {
      const url = new URL(`${this.baseUrl}/api/client/public-key`);
      const isHttps = url.protocol === 'https:';
      const client = isHttps ? https : http;

      const options = {
        hostname: url.hostname,
        port: url.port || (isHttps ? 443 : 80),
        path: url.pathname,
        method: 'GET'
      };

      const req = client.request(options, (res) => {
        let data = '';
        res.on('data', chunk => data += chunk);
        res.on('end', () => {
          try {
            const parsed = JSON.parse(data);
            if (parsed.success && parsed.data?.public_key) {
              this.publicKey = parsed.data.public_key;
              resolve(this.publicKey);
            } else {
              reject(new Error('Failed to fetch public key'));
            }
          } catch (err) {
            reject(err);
          }
        });
      });

      req.on('error', reject);
      req.end();
    });
  }

  // Make API request
  async request(endpoint, data) {
    return new Promise((resolve, reject) => {
      // Add client data for security analysis
      const clientData = this.collectClientData();

      let body = {
        ...data,
        product_id: this.productId,
        client_data: clientData
      };

      // Add session token if available
      if (this.sessionToken) {
        body.session_token = this.sessionToken;
      }

      if (this.useEncryption && this.secretKey) {
        const timestamp = Date.now();
        const encrypted = this.encrypt(body, this.secretKey);
        const signaturePayload = `${encrypted.iv}:${encrypted.data}:${encrypted.tag}:${timestamp}`;
        const signature = this.sign(signaturePayload, this.secretKey);

        body = {
          encrypted: true,
          ...encrypted,
          signature,
          product_id: this.productId,
          timestamp
        };
      }

      const url = new URL(`${this.baseUrl}/api/client${endpoint}`);
      const isHttps = url.protocol === 'https:';
      const client = isHttps ? https : http;

      const options = {
        hostname: url.hostname,
        port: url.port || (isHttps ? 443 : 80),
        path: url.pathname,
        method: 'POST',
        headers: {
          'Content-Type': 'application/json'
        }
      };

      const req = client.request(options, (res) => {
        let responseData = '';
        res.on('data', chunk => responseData += chunk);
        res.on('end', () => {
          try {
            let parsed = JSON.parse(responseData);

            if (parsed.encrypted && this.useEncryption && this.secretKey) {
              parsed = this.decrypt(parsed, this.secretKey);
            }

            if (parsed.success) {
              // Verify signature if present
              if (parsed.data?.signature && this.publicKey) {
                const isValid = this.verifySignature(parsed.data.data, parsed.data.signature);
                if (!isValid) {
                  this.onSecurityViolation({ type: 'invalid_signature' });
                  reject(new Error('Invalid server signature'));
                  return;
                }
              }

              // Handle session token rotation
              if (parsed.data?.new_token) {
                this.sessionToken = parsed.data.new_token;
              }

              // Handle session info
              if (parsed.data?.session) {
                this.sessionToken = parsed.data.session.token;
                this.sessionExpires = new Date(parsed.data.session.expires_at);
              }

              resolve(parsed.data);
            } else {
              // Handle security violations
              if (parsed.security_blocked) {
                this.onSecurityViolation({
                  type: 'blocked',
                  reason: parsed.message,
                  details: parsed.security_details
                });
              }
              reject(new Error(parsed.message));
            }
          } catch (err) {
            reject(err);
          }
        });
      });

      req.on('error', reject);
      req.write(JSON.stringify(body));
      req.end();
    });
  }

  // Initialize - fetch public key
  async initialize() {
    try {
      await this.fetchPublicKey();
      return true;
    } catch (error) {
      console.warn('Failed to fetch public key:', error.message);
      return false;
    }
  }

  // Validate license
  async validate(licenseKey, hwid = null) {
    this.licenseKey = licenseKey;
    this.hwid = hwid || LicenseCM.generateHwid();

    return this.request('/validate', {
      license_key: licenseKey,
      hwid: this.hwid
    });
  }

  // Activate license
  async activate(licenseKey, hwid = null) {
    this.licenseKey = licenseKey;
    this.hwid = hwid || LicenseCM.generateHwid();

    const result = await this.request('/activate', {
      license_key: licenseKey,
      hwid: this.hwid
    });

    // Start heartbeat if auto-heartbeat is enabled
    if (this.autoHeartbeat && result.session) {
      this.startHeartbeat();
    }

    return result;
  }

  // Deactivate license
  async deactivate(licenseKey = null, hwid = null) {
    // Stop heartbeat
    this.stopHeartbeat();

    const result = await this.request('/deactivate', {
      license_key: licenseKey || this.licenseKey,
      hwid: hwid || this.hwid || LicenseCM.generateHwid()
    });

    // Clear session
    this.sessionToken = null;
    this.sessionExpires = null;

    return result;
  }

  // Heartbeat
  async heartbeat(licenseKey = null, hwid = null) {
    return this.request('/heartbeat', {
      license_key: licenseKey || this.licenseKey,
      hwid: hwid || this.hwid || LicenseCM.generateHwid()
    });
  }

  // Start automatic heartbeat
  startHeartbeat() {
    if (this.heartbeatTimer) {
      clearInterval(this.heartbeatTimer);
    }

    this.heartbeatTimer = setInterval(async () => {
      try {
        await this.heartbeat();
      } catch (error) {
        console.error('Heartbeat failed:', error.message);
        this.onHeartbeatFailed({ error: error.message });

        // If session expired, stop heartbeat
        if (error.message.includes('expired') || error.message.includes('invalid')) {
          this.stopHeartbeat();
          this.onSessionExpired();
        }
      }
    }, this.heartbeatInterval);
  }

  // Stop automatic heartbeat
  stopHeartbeat() {
    if (this.heartbeatTimer) {
      clearInterval(this.heartbeatTimer);
      this.heartbeatTimer = null;
    }
  }

  // Verify challenge from server
  async verifyChallenge(challenge, expectedResponse) {
    // Generate response based on challenge
    const response = crypto.createHmac('sha256', this.hwid || LicenseCM.generateHwid())
      .update(challenge)
      .digest('hex');

    return this.request('/verify-challenge', {
      license_key: this.licenseKey,
      hwid: this.hwid || LicenseCM.generateHwid(),
      challenge,
      response
    });
  }

  // Check if session is valid
  isSessionValid() {
    if (!this.sessionToken || !this.sessionExpires) {
      return false;
    }
    return new Date() < this.sessionExpires;
  }

  // Get session info
  getSessionInfo() {
    return {
      token: this.sessionToken,
      expires: this.sessionExpires,
      isValid: this.isSessionValid()
    };
  }

  // Cleanup
  destroy() {
    this.stopHeartbeat();
    this.sessionToken = null;
    this.sessionExpires = null;
    this.licenseKey = null;
    this.hwid = null;
  }
}

module.exports = LicenseCM;

// Example usage
if (require.main === module) {
  const client = new LicenseCM({
    baseUrl: 'http://localhost:3000',
    productId: 'your-product-id',
    secretKey: 'your-secret-key',
    useEncryption: true,
    autoHeartbeat: true,
    heartbeatInterval: 5 * 60 * 1000, // 5 minutes

    // Security callbacks
    onSessionExpired: () => {
      console.log('Session expired! Please re-activate.');
      process.exit(1);
    },
    onSecurityViolation: (details) => {
      console.error('Security violation detected:', details);
      process.exit(1);
    },
    onHeartbeatFailed: (details) => {
      console.warn('Heartbeat failed:', details);
    }
  });

  const licenseKey = 'XXXX-XXXX-XXXX-XXXX';

  (async () => {
    try {
      // Initialize (fetch public key)
      await client.initialize();

      // Activate license
      const result = await client.activate(licenseKey);
      console.log('License activated:', result);

      // License is now active with automatic heartbeat
      // The client will send heartbeats every 5 minutes

      // To deactivate when done:
      // await client.deactivate();
      // client.destroy();

    } catch (err) {
      console.error('Activation failed:', err.message);
    }
  })();
}
