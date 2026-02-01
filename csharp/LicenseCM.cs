using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Net.Http;
using System.Net.NetworkInformation;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using System.Timers;

namespace LicenseCM
{
    public class SecurityViolationEventArgs : EventArgs
    {
        public string Type { get; set; }
        public string Reason { get; set; }
        public object Details { get; set; }
    }

    public class HeartbeatFailedEventArgs : EventArgs
    {
        public string Error { get; set; }
    }

    public class LicenseCMClient : IDisposable
    {
        private readonly string _baseUrl;
        private readonly string _productId;
        private readonly string _secretKey;
        private readonly bool _useEncryption;
        private readonly bool _autoHeartbeat;
        private readonly int _heartbeatIntervalMs;
        private readonly HttpClient _httpClient;

        // Session state
        private string _sessionToken;
        private DateTime? _sessionExpires;
        private System.Timers.Timer _heartbeatTimer;
        private string _licenseKey;
        private string _hwid;

        // Public key for signature verification
        private string _publicKey;

        // Events
        public event EventHandler SessionExpired;
        public event EventHandler<SecurityViolationEventArgs> SecurityViolation;
        public event EventHandler<HeartbeatFailedEventArgs> HeartbeatFailed;

        public LicenseCMClient(
            string baseUrl,
            string productId,
            string secretKey = null,
            bool useEncryption = false,
            bool autoHeartbeat = true,
            int heartbeatIntervalMs = 300000) // 5 minutes
        {
            _baseUrl = baseUrl.TrimEnd('/');
            _productId = productId;
            _secretKey = secretKey;
            _useEncryption = useEncryption && !string.IsNullOrEmpty(secretKey);
            _autoHeartbeat = autoHeartbeat;
            _heartbeatIntervalMs = heartbeatIntervalMs;
            _httpClient = new HttpClient { Timeout = TimeSpan.FromSeconds(30) };
        }

        #region HWID Generation

        public static string GenerateHwid()
        {
            var components = new List<string>
            {
                Environment.OSVersion.Platform.ToString(),
                RuntimeInformation.OSArchitecture.ToString(),
                Environment.MachineName,
                Environment.ProcessorCount.ToString()
            };

            // Get MAC address
            try
            {
                var mac = NetworkInterface.GetAllNetworkInterfaces()
                    .Where(nic => nic.OperationalStatus == OperationalStatus.Up &&
                                  nic.NetworkInterfaceType != NetworkInterfaceType.Loopback)
                    .Select(nic => nic.GetPhysicalAddress().ToString())
                    .FirstOrDefault();

                if (!string.IsNullOrEmpty(mac))
                    components.Add(mac);
            }
            catch { }

            // Get disk serial (Windows only)
            if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
            {
                try
                {
                    var psi = new ProcessStartInfo
                    {
                        FileName = "wmic",
                        Arguments = "diskdrive get serialnumber",
                        RedirectStandardOutput = true,
                        UseShellExecute = false,
                        CreateNoWindow = true
                    };

                    using var process = Process.Start(psi);
                    var output = process.StandardOutput.ReadToEnd();
                    var lines = output.Split('\n');
                    if (lines.Length > 1)
                    {
                        var serial = lines[1].Trim();
                        if (!string.IsNullOrEmpty(serial))
                            components.Add(serial);
                    }
                }
                catch { }
            }

            var data = string.Join("|", components);
            using var sha256 = SHA256.Create();
            var hash = sha256.ComputeHash(Encoding.UTF8.GetBytes(data));
            return BitConverter.ToString(hash).Replace("-", "").ToLower();
        }

        #endregion

        #region Security Detection

        private Dictionary<string, object> CollectClientData()
        {
            var data = new Dictionary<string, object>
            {
                ["hwid"] = _hwid ?? GenerateHwid(),
                ["timestamp"] = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds(),
                ["platform"] = Environment.OSVersion.Platform.ToString(),
                ["os_version"] = Environment.OSVersion.VersionString,
                ["architecture"] = RuntimeInformation.OSArchitecture.ToString(),
                ["hostname"] = Environment.MachineName,
                ["dotnet_version"] = RuntimeInformation.FrameworkDescription,
                ["cpu_count"] = Environment.ProcessorCount,
                ["env_indicators"] = new Dictionary<string, bool>
                {
                    ["debug_mode"] = Debugger.IsAttached,
                    ["is_64bit_process"] = Environment.Is64BitProcess,
                    ["is_64bit_os"] = Environment.Is64BitOperatingSystem
                },
                ["vm_indicators"] = DetectVMIndicators(),
                ["debug_indicators"] = DetectDebugIndicators()
            };

            return data;
        }

        private List<string> DetectVMIndicators()
        {
            var indicators = new List<string>();
            var hostname = Environment.MachineName.ToLower();

            // Check hostname patterns
            var vmHostnames = new[] { "vmware", "virtualbox", "sandbox", "virtual", "qemu" };
            if (vmHostnames.Any(vm => hostname.Contains(vm)))
                indicators.Add("suspicious_hostname");

            // Check MAC address prefixes
            var vmMacPrefixes = new[]
            {
                "000C29", "005056", "000569", // VMware
                "080027", "0A0027",           // VirtualBox
                "00155D",                      // Hyper-V
                "00163E",                      // Xen
                "525400"                       // QEMU
            };

            try
            {
                var macs = NetworkInterface.GetAllNetworkInterfaces()
                    .Where(nic => nic.NetworkInterfaceType != NetworkInterfaceType.Loopback)
                    .Select(nic => nic.GetPhysicalAddress().ToString().ToUpper());

                if (macs.Any(mac => vmMacPrefixes.Any(prefix => mac.StartsWith(prefix))))
                    indicators.Add("vm_mac_address");
            }
            catch { }

            // Check for low CPU count
            if (Environment.ProcessorCount < 2)
                indicators.Add("single_cpu");

            return indicators;
        }

        private List<string> DetectDebugIndicators()
        {
            var indicators = new List<string>();

            // Check if debugger is attached
            if (Debugger.IsAttached)
                indicators.Add("debugger_attached");

            // Timing analysis
            var sw = Stopwatch.StartNew();
            for (int i = 0; i < 1000; i++)
            {
                _ = Guid.NewGuid();
            }
            sw.Stop();

            if (sw.ElapsedMilliseconds > 100)
                indicators.Add("timing_anomaly");

            // Check for debug environment variables
            if (!string.IsNullOrEmpty(Environment.GetEnvironmentVariable("DEBUG")))
                indicators.Add("env_debug");

            return indicators;
        }

        #endregion

        #region Encryption

        private (string iv, string data, string tag) Encrypt(string plaintext)
        {
            using var aes = new AesGcm(Encoding.UTF8.GetBytes(_secretKey.PadRight(32).Substring(0, 32)));
            var iv = new byte[16];
            RandomNumberGenerator.Fill(iv);

            var plaintextBytes = Encoding.UTF8.GetBytes(plaintext);
            var ciphertext = new byte[plaintextBytes.Length];
            var tag = new byte[16];

            aes.Encrypt(iv, plaintextBytes, ciphertext, tag);

            return (
                BitConverter.ToString(iv).Replace("-", "").ToLower(),
                BitConverter.ToString(ciphertext).Replace("-", "").ToLower(),
                BitConverter.ToString(tag).Replace("-", "").ToLower()
            );
        }

        private string Decrypt(string iv, string data, string tag)
        {
            using var aes = new AesGcm(Encoding.UTF8.GetBytes(_secretKey.PadRight(32).Substring(0, 32)));
            var ivBytes = HexToBytes(iv);
            var ciphertext = HexToBytes(data);
            var tagBytes = HexToBytes(tag);
            var plaintext = new byte[ciphertext.Length];

            aes.Decrypt(ivBytes, ciphertext, tagBytes, plaintext);

            return Encoding.UTF8.GetString(plaintext);
        }

        private string Sign(string data)
        {
            using var hmac = new HMACSHA256(Encoding.UTF8.GetBytes(_secretKey));
            var hash = hmac.ComputeHash(Encoding.UTF8.GetBytes(data));
            return BitConverter.ToString(hash).Replace("-", "").ToLower();
        }

        private byte[] HexToBytes(string hex)
        {
            var bytes = new byte[hex.Length / 2];
            for (int i = 0; i < bytes.Length; i++)
            {
                bytes[i] = Convert.ToByte(hex.Substring(i * 2, 2), 16);
            }
            return bytes;
        }

        #endregion

        #region Public Key

        public async Task<string> FetchPublicKeyAsync()
        {
            try
            {
                var response = await _httpClient.GetAsync($"{_baseUrl}/api/client/public-key");
                var content = await response.Content.ReadAsStringAsync();
                var json = JsonSerializer.Deserialize<JsonElement>(content);

                if (json.GetProperty("success").GetBoolean())
                {
                    _publicKey = json.GetProperty("data").GetProperty("public_key").GetString();
                    return _publicKey;
                }
            }
            catch { }

            return null;
        }

        #endregion

        #region API Requests

        private async Task<JsonElement> RequestAsync(string endpoint, string licenseKey, string hwid)
        {
            var clientData = CollectClientData();

            var body = new Dictionary<string, object>
            {
                ["license_key"] = licenseKey,
                ["hwid"] = hwid,
                ["product_id"] = _productId,
                ["client_data"] = clientData
            };

            if (!string.IsNullOrEmpty(_sessionToken))
                body["session_token"] = _sessionToken;

            string jsonBody;

            if (_useEncryption)
            {
                var timestamp = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();
                var encrypted = Encrypt(JsonSerializer.Serialize(body));
                var signaturePayload = $"{encrypted.iv}:{encrypted.data}:{encrypted.tag}:{timestamp}";
                var signature = Sign(signaturePayload);

                var encryptedBody = new Dictionary<string, object>
                {
                    ["encrypted"] = true,
                    ["iv"] = encrypted.iv,
                    ["data"] = encrypted.data,
                    ["tag"] = encrypted.tag,
                    ["signature"] = signature,
                    ["product_id"] = _productId,
                    ["timestamp"] = timestamp
                };
                jsonBody = JsonSerializer.Serialize(encryptedBody);
            }
            else
            {
                jsonBody = JsonSerializer.Serialize(body);
            }

            var content = new StringContent(jsonBody, Encoding.UTF8, "application/json");
            var response = await _httpClient.PostAsync($"{_baseUrl}/api/client{endpoint}", content);
            var responseBody = await response.Content.ReadAsStringAsync();

            var responseJson = JsonSerializer.Deserialize<JsonElement>(responseBody);

            if (_useEncryption && responseJson.TryGetProperty("encrypted", out var enc) && enc.GetBoolean())
            {
                var decrypted = Decrypt(
                    responseJson.GetProperty("iv").GetString(),
                    responseJson.GetProperty("data").GetString(),
                    responseJson.GetProperty("tag").GetString()
                );
                responseJson = JsonSerializer.Deserialize<JsonElement>(decrypted);
            }

            if (responseJson.GetProperty("success").GetBoolean())
            {
                var data = responseJson.GetProperty("data");

                // Handle session token rotation
                if (data.TryGetProperty("new_token", out var newToken))
                    _sessionToken = newToken.GetString();

                // Handle session info
                if (data.TryGetProperty("session", out var session))
                {
                    _sessionToken = session.GetProperty("token").GetString();
                    if (session.TryGetProperty("expires_at", out var expiresAt))
                        _sessionExpires = DateTime.Parse(expiresAt.GetString());
                }

                return data;
            }
            else
            {
                // Handle security violations
                if (responseJson.TryGetProperty("security_blocked", out var blocked) && blocked.GetBoolean())
                {
                    SecurityViolation?.Invoke(this, new SecurityViolationEventArgs
                    {
                        Type = "blocked",
                        Reason = responseJson.GetProperty("message").GetString()
                    });
                }

                throw new Exception(responseJson.GetProperty("message").GetString());
            }
        }

        #endregion

        #region License Operations

        public async Task InitializeAsync()
        {
            await FetchPublicKeyAsync();
        }

        public async Task<JsonElement> ValidateAsync(string licenseKey, string hwid = null)
        {
            _licenseKey = licenseKey;
            _hwid = hwid ?? GenerateHwid();
            return await RequestAsync("/validate", licenseKey, _hwid);
        }

        public async Task<JsonElement> ActivateAsync(string licenseKey, string hwid = null)
        {
            _licenseKey = licenseKey;
            _hwid = hwid ?? GenerateHwid();

            var result = await RequestAsync("/activate", licenseKey, _hwid);

            // Start heartbeat if enabled
            if (_autoHeartbeat && result.TryGetProperty("session", out _))
                StartHeartbeat();

            return result;
        }

        public async Task<JsonElement> DeactivateAsync(string licenseKey = null, string hwid = null)
        {
            StopHeartbeat();

            var result = await RequestAsync("/deactivate",
                licenseKey ?? _licenseKey,
                hwid ?? _hwid ?? GenerateHwid());

            _sessionToken = null;
            _sessionExpires = null;

            return result;
        }

        public async Task<JsonElement> HeartbeatAsync(string licenseKey = null, string hwid = null)
        {
            return await RequestAsync("/heartbeat",
                licenseKey ?? _licenseKey,
                hwid ?? _hwid ?? GenerateHwid());
        }

        public async Task<JsonElement> VerifyChallengeAsync(string challenge)
        {
            var hwid = _hwid ?? GenerateHwid();
            using var hmac = new HMACSHA256(Encoding.UTF8.GetBytes(hwid));
            var response = BitConverter.ToString(
                hmac.ComputeHash(Encoding.UTF8.GetBytes(challenge))
            ).Replace("-", "").ToLower();

            var body = new Dictionary<string, object>
            {
                ["license_key"] = _licenseKey,
                ["hwid"] = hwid,
                ["challenge"] = challenge,
                ["response"] = response,
                ["product_id"] = _productId
            };

            var jsonBody = JsonSerializer.Serialize(body);
            var content = new StringContent(jsonBody, Encoding.UTF8, "application/json");
            var httpResponse = await _httpClient.PostAsync($"{_baseUrl}/api/client/verify-challenge", content);
            var responseBody = await httpResponse.Content.ReadAsStringAsync();

            return JsonSerializer.Deserialize<JsonElement>(responseBody);
        }

        #endregion

        #region Heartbeat Management

        public void StartHeartbeat()
        {
            StopHeartbeat();

            _heartbeatTimer = new System.Timers.Timer(_heartbeatIntervalMs);
            _heartbeatTimer.Elapsed += async (s, e) => await HeartbeatLoopAsync();
            _heartbeatTimer.AutoReset = true;
            _heartbeatTimer.Start();
        }

        public void StopHeartbeat()
        {
            _heartbeatTimer?.Stop();
            _heartbeatTimer?.Dispose();
            _heartbeatTimer = null;
        }

        private async Task HeartbeatLoopAsync()
        {
            try
            {
                await HeartbeatAsync();
            }
            catch (Exception ex)
            {
                HeartbeatFailed?.Invoke(this, new HeartbeatFailedEventArgs { Error = ex.Message });

                if (ex.Message.ToLower().Contains("expired") || ex.Message.ToLower().Contains("invalid"))
                {
                    StopHeartbeat();
                    SessionExpired?.Invoke(this, EventArgs.Empty);
                }
            }
        }

        #endregion

        #region Session Info

        public bool IsSessionValid()
        {
            return !string.IsNullOrEmpty(_sessionToken) &&
                   _sessionExpires.HasValue &&
                   DateTime.UtcNow < _sessionExpires.Value;
        }

        public (string Token, DateTime? Expires, bool IsValid) GetSessionInfo()
        {
            return (_sessionToken, _sessionExpires, IsSessionValid());
        }

        #endregion

        #region Disposal

        public void Dispose()
        {
            StopHeartbeat();
            _httpClient?.Dispose();
            _sessionToken = null;
            _sessionExpires = null;
            _licenseKey = null;
            _hwid = null;
        }

        #endregion
    }

    // Example usage
    class Program
    {
        static async Task Main(string[] args)
        {
            using var client = new LicenseCMClient(
                baseUrl: "http://localhost:3000",
                productId: "your-product-id",
                secretKey: "your-secret-key",
                useEncryption: true,
                autoHeartbeat: true,
                heartbeatIntervalMs: 300000 // 5 minutes
            );

            // Event handlers
            client.SessionExpired += (s, e) =>
            {
                Console.WriteLine("Session expired! Please re-activate.");
                Environment.Exit(1);
            };

            client.SecurityViolation += (s, e) =>
            {
                Console.WriteLine($"Security violation: {e.Type} - {e.Reason}");
                Environment.Exit(1);
            };

            client.HeartbeatFailed += (s, e) =>
            {
                Console.WriteLine($"Heartbeat failed: {e.Error}");
            };

            string licenseKey = "XXXX-XXXX-XXXX-XXXX";

            try
            {
                // Initialize (fetch public key)
                await client.InitializeAsync();

                // Activate license
                var result = await client.ActivateAsync(licenseKey);
                Console.WriteLine($"License activated: {result}");

                // License is now active with automatic heartbeat
                // The client will send heartbeats every 5 minutes

                // Keep running
                Console.WriteLine("Press Enter to exit...");
                Console.ReadLine();

                // Cleanup
                await client.DeactivateAsync();
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Activation failed: {ex.Message}");
            }
        }
    }
}
