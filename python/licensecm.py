#!/usr/bin/env python3
"""
LicenseCM Python SDK with Enhanced Security Features
"""

import hashlib
import hmac
import json
import platform
import socket
import time
import uuid
import os
import subprocess
import threading
from base64 import b64encode, b64decode
from typing import Optional, Dict, Any, Callable
from datetime import datetime, timedelta

try:
    from Crypto.Cipher import AES
    from Crypto.Random import get_random_bytes
    from Crypto.PublicKey import RSA
    from Crypto.Signature import pkcs1_15
    from Crypto.Hash import SHA512
    HAS_CRYPTO = True
except ImportError:
    HAS_CRYPTO = False

import urllib.request
import urllib.error


class LicenseCM:
    def __init__(
        self,
        base_url: str = "http://localhost:3000",
        product_id: str = "",
        secret_key: str = "",
        use_encryption: bool = False,
        auto_heartbeat: bool = True,
        heartbeat_interval: int = 300,  # 5 minutes in seconds
        on_session_expired: Optional[Callable] = None,
        on_security_violation: Optional[Callable[[Dict], None]] = None,
        on_heartbeat_failed: Optional[Callable[[Dict], None]] = None
    ):
        self.base_url = base_url.rstrip("/")
        self.product_id = product_id
        self.secret_key = secret_key
        self.use_encryption = use_encryption and HAS_CRYPTO
        self.auto_heartbeat = auto_heartbeat
        self.heartbeat_interval = heartbeat_interval

        # Session state
        self.session_token: Optional[str] = None
        self.session_expires: Optional[datetime] = None
        self.heartbeat_timer: Optional[threading.Timer] = None
        self.license_key: Optional[str] = None
        self.hwid: Optional[str] = None

        # Public key for signature verification
        self.public_key: Optional[str] = None

        # Callbacks
        self.on_session_expired = on_session_expired or (lambda: None)
        self.on_security_violation = on_security_violation or (lambda x: None)
        self.on_heartbeat_failed = on_heartbeat_failed or (lambda x: None)

    @staticmethod
    def generate_hwid() -> str:
        """Generate enhanced hardware ID from system info"""
        # Get MAC address
        mac = ':'.join(['{:02x}'.format((uuid.getnode() >> i) & 0xff) for i in range(0, 48, 8)][::-1])

        # Get disk serial (platform-specific)
        disk_serial = ""
        try:
            if platform.system() == "Windows":
                result = subprocess.run(
                    ["wmic", "diskdrive", "get", "serialnumber"],
                    capture_output=True, text=True, timeout=5
                )
                lines = result.stdout.strip().split('\n')
                if len(lines) > 1:
                    disk_serial = lines[1].strip()
            elif platform.system() == "Linux":
                try:
                    with open('/sys/class/dmi/id/product_serial', 'r') as f:
                        disk_serial = f.read().strip()
                except:
                    pass
            elif platform.system() == "Darwin":
                result = subprocess.run(
                    ["ioreg", "-l"],
                    capture_output=True, text=True, timeout=5
                )
                for line in result.stdout.split('\n'):
                    if 'IOPlatformSerialNumber' in line:
                        disk_serial = line.split('"')[-2]
                        break
        except:
            pass

        components = [
            platform.system(),
            platform.machine(),
            platform.processor(),
            socket.gethostname(),
            mac,
            disk_serial,
            str(os.cpu_count() or 0)
        ]
        data = "|".join(components)
        return hashlib.sha256(data.encode()).hexdigest()

    def collect_client_data(self) -> Dict[str, Any]:
        """Collect extended client data for security analysis"""
        data = {
            "hwid": self.hwid or self.generate_hwid(),
            "timestamp": int(time.time() * 1000),
            "platform": platform.system(),
            "os_version": platform.release(),
            "architecture": platform.machine(),
            "hostname": socket.gethostname(),
            "python_version": platform.python_version(),
            "cpu_count": os.cpu_count(),

            # Environment indicators
            "env_indicators": {
                "debug_mode": os.environ.get("DEBUG") is not None,
                "pythondontwritebytecode": os.environ.get("PYTHONDONTWRITEBYTECODE") is not None,
                "virtual_env": os.environ.get("VIRTUAL_ENV") is not None
            },

            # VM indicators
            "vm_indicators": self._detect_vm_indicators(),

            # Debug indicators
            "debug_indicators": self._detect_debug_indicators()
        }

        return data

    def _detect_vm_indicators(self) -> list:
        """Detect VM/Sandbox environment"""
        indicators = []
        hostname = socket.gethostname().lower()

        # Check hostname patterns
        vm_hostnames = ['vmware', 'virtualbox', 'sandbox', 'virtual', 'qemu']
        if any(vm in hostname for vm in vm_hostnames):
            indicators.append('suspicious_hostname')

        # Check MAC address prefixes for known VM vendors
        mac = uuid.getnode()
        mac_str = ':'.join(['{:02x}'.format((mac >> i) & 0xff) for i in range(0, 48, 8)][::-1])

        vm_mac_prefixes = [
            '00:0c:29', '00:50:56', '00:05:69',  # VMware
            '08:00:27', '0a:00:27',               # VirtualBox
            '00:15:5d',                           # Hyper-V
            '00:16:3e',                           # Xen
            '52:54:00'                            # QEMU
        ]

        for prefix in vm_mac_prefixes:
            if mac_str.lower().startswith(prefix):
                indicators.append('vm_mac_address')
                break

        # Check for low CPU count (typical of sandboxes)
        cpu_count = os.cpu_count() or 0
        if cpu_count < 2:
            indicators.append('single_cpu')

        return indicators

    def _detect_debug_indicators(self) -> list:
        """Detect debugger/reverse engineering"""
        indicators = []

        # Check for debug environment variables
        debug_env_vars = ['DEBUG', 'PYTHONBREAKPOINT', 'PYTHONINSPECT']
        for env_var in debug_env_vars:
            if os.environ.get(env_var):
                indicators.append(f'env_{env_var.lower()}')

        # Timing analysis
        start = time.perf_counter_ns()
        for _ in range(1000):
            _ = hash(time.time())
        duration_ms = (time.perf_counter_ns() - start) / 1e6

        if duration_ms > 100:
            indicators.append('timing_anomaly')

        return indicators

    def _encrypt(self, data: dict) -> dict:
        """Encrypt payload using AES-256-GCM"""
        if not HAS_CRYPTO:
            raise RuntimeError("PyCryptodome required for encryption")

        iv = get_random_bytes(16)
        key = self.secret_key.encode()[:32].ljust(32, b'\0')
        cipher = AES.new(key, AES.MODE_GCM, nonce=iv)

        plaintext = json.dumps(data).encode()
        ciphertext, tag = cipher.encrypt_and_digest(plaintext)

        return {
            "iv": iv.hex(),
            "data": ciphertext.hex(),
            "tag": tag.hex()
        }

    def _decrypt(self, encrypted_data: dict) -> dict:
        """Decrypt response"""
        if not HAS_CRYPTO:
            raise RuntimeError("PyCryptodome required for encryption")

        iv = bytes.fromhex(encrypted_data["iv"])
        tag = bytes.fromhex(encrypted_data["tag"])
        ciphertext = bytes.fromhex(encrypted_data["data"])
        key = self.secret_key.encode()[:32].ljust(32, b'\0')

        cipher = AES.new(key, AES.MODE_GCM, nonce=iv)
        plaintext = cipher.decrypt_and_verify(ciphertext, tag)

        return json.loads(plaintext.decode())

    def _sign(self, data: str) -> str:
        """Generate HMAC signature"""
        return hmac.new(
            self.secret_key.encode(),
            data.encode(),
            hashlib.sha256
        ).hexdigest()

    def _verify_signature(self, data: dict, signature: str) -> bool:
        """Verify RSA signature from server"""
        if not self.public_key or not HAS_CRYPTO:
            return True  # Skip if no public key

        try:
            key = RSA.import_key(self.public_key)
            h = SHA512.new(json.dumps(data).encode())
            pkcs1_15.new(key).verify(h, b64decode(signature))
            return True
        except:
            return False

    def fetch_public_key(self) -> Optional[str]:
        """Fetch public key from server"""
        url = f"{self.base_url}/api/client/public-key"

        try:
            req = urllib.request.Request(url, method="GET")
            with urllib.request.urlopen(req, timeout=30) as response:
                data = json.loads(response.read().decode())
                if data.get("success") and data.get("data", {}).get("public_key"):
                    self.public_key = data["data"]["public_key"]
                    return self.public_key
        except:
            pass

        return None

    def _request(self, endpoint: str, data: dict) -> dict:
        """Make API request"""
        # Add client data for security analysis
        client_data = self.collect_client_data()

        body = {
            **data,
            "product_id": self.product_id,
            "client_data": client_data
        }

        # Add session token if available
        if self.session_token:
            body["session_token"] = self.session_token

        if self.use_encryption and self.secret_key:
            timestamp = int(time.time() * 1000)
            encrypted = self._encrypt(body)
            signature_payload = f"{encrypted['iv']}:{encrypted['data']}:{encrypted['tag']}:{timestamp}"
            signature = self._sign(signature_payload)

            body = {
                "encrypted": True,
                **encrypted,
                "signature": signature,
                "product_id": self.product_id,
                "timestamp": timestamp
            }

        url = f"{self.base_url}/api/client{endpoint}"
        headers = {"Content-Type": "application/json"}
        request_body = json.dumps(body).encode()

        req = urllib.request.Request(url, data=request_body, headers=headers, method="POST")

        try:
            with urllib.request.urlopen(req, timeout=30) as response:
                response_data = json.loads(response.read().decode())

                if response_data.get("encrypted") and self.use_encryption:
                    response_data = self._decrypt(response_data)

                if response_data.get("success"):
                    result = response_data.get("data", {})

                    # Verify signature if present
                    if result.get("signature") and self.public_key:
                        if not self._verify_signature(result.get("data", {}), result["signature"]):
                            self.on_security_violation({"type": "invalid_signature"})
                            raise Exception("Invalid server signature")

                    # Handle session token rotation
                    if result.get("new_token"):
                        self.session_token = result["new_token"]

                    # Handle session info
                    if result.get("session"):
                        self.session_token = result["session"].get("token")
                        expires_at = result["session"].get("expires_at")
                        if expires_at:
                            self.session_expires = datetime.fromisoformat(expires_at.replace('Z', '+00:00'))

                    return result
                else:
                    # Handle security violations
                    if response_data.get("security_blocked"):
                        self.on_security_violation({
                            "type": "blocked",
                            "reason": response_data.get("message"),
                            "details": response_data.get("security_details")
                        })
                    raise Exception(response_data.get("message", "Unknown error"))

        except urllib.error.HTTPError as e:
            error_body = json.loads(e.read().decode())
            raise Exception(error_body.get("message", str(e)))

    def initialize(self) -> bool:
        """Initialize - fetch public key"""
        try:
            self.fetch_public_key()
            return True
        except:
            return False

    def validate(self, license_key: str, hwid: Optional[str] = None) -> dict:
        """Validate a license"""
        self.license_key = license_key
        self.hwid = hwid or self.generate_hwid()

        return self._request("/validate", {
            "license_key": license_key,
            "hwid": self.hwid
        })

    def activate(self, license_key: str, hwid: Optional[str] = None) -> dict:
        """Activate a license"""
        self.license_key = license_key
        self.hwid = hwid or self.generate_hwid()

        result = self._request("/activate", {
            "license_key": license_key,
            "hwid": self.hwid
        })

        # Start heartbeat if auto-heartbeat is enabled
        if self.auto_heartbeat and result.get("session"):
            self.start_heartbeat()

        return result

    def deactivate(self, license_key: Optional[str] = None, hwid: Optional[str] = None) -> dict:
        """Deactivate a license"""
        # Stop heartbeat
        self.stop_heartbeat()

        result = self._request("/deactivate", {
            "license_key": license_key or self.license_key,
            "hwid": hwid or self.hwid or self.generate_hwid()
        })

        # Clear session
        self.session_token = None
        self.session_expires = None

        return result

    def heartbeat(self, license_key: Optional[str] = None, hwid: Optional[str] = None) -> dict:
        """Send heartbeat"""
        return self._request("/heartbeat", {
            "license_key": license_key or self.license_key,
            "hwid": hwid or self.hwid or self.generate_hwid()
        })

    def _heartbeat_loop(self):
        """Internal heartbeat loop"""
        try:
            self.heartbeat()
        except Exception as e:
            error_msg = str(e)
            self.on_heartbeat_failed({"error": error_msg})

            if "expired" in error_msg.lower() or "invalid" in error_msg.lower():
                self.stop_heartbeat()
                self.on_session_expired()
                return

        # Schedule next heartbeat
        if self.heartbeat_timer:
            self.heartbeat_timer = threading.Timer(self.heartbeat_interval, self._heartbeat_loop)
            self.heartbeat_timer.daemon = True
            self.heartbeat_timer.start()

    def start_heartbeat(self):
        """Start automatic heartbeat"""
        self.stop_heartbeat()
        self.heartbeat_timer = threading.Timer(self.heartbeat_interval, self._heartbeat_loop)
        self.heartbeat_timer.daemon = True
        self.heartbeat_timer.start()

    def stop_heartbeat(self):
        """Stop automatic heartbeat"""
        if self.heartbeat_timer:
            self.heartbeat_timer.cancel()
            self.heartbeat_timer = None

    def verify_challenge(self, challenge: str) -> dict:
        """Verify challenge from server"""
        response = hmac.new(
            (self.hwid or self.generate_hwid()).encode(),
            challenge.encode(),
            hashlib.sha256
        ).hexdigest()

        return self._request("/verify-challenge", {
            "license_key": self.license_key,
            "hwid": self.hwid or self.generate_hwid(),
            "challenge": challenge,
            "response": response
        })

    def is_session_valid(self) -> bool:
        """Check if session is valid"""
        if not self.session_token or not self.session_expires:
            return False
        return datetime.now(self.session_expires.tzinfo) < self.session_expires

    def get_session_info(self) -> dict:
        """Get session info"""
        return {
            "token": self.session_token,
            "expires": self.session_expires.isoformat() if self.session_expires else None,
            "is_valid": self.is_session_valid()
        }

    def destroy(self):
        """Cleanup"""
        self.stop_heartbeat()
        self.session_token = None
        self.session_expires = None
        self.license_key = None
        self.hwid = None


# Example usage
if __name__ == "__main__":
    def on_session_expired():
        print("Session expired! Please re-activate.")
        exit(1)

    def on_security_violation(details):
        print(f"Security violation detected: {details}")
        exit(1)

    def on_heartbeat_failed(details):
        print(f"Heartbeat failed: {details}")

    client = LicenseCM(
        base_url="http://localhost:3000",
        product_id="your-product-id",
        secret_key="your-secret-key",
        use_encryption=True,
        auto_heartbeat=True,
        heartbeat_interval=300,  # 5 minutes
        on_session_expired=on_session_expired,
        on_security_violation=on_security_violation,
        on_heartbeat_failed=on_heartbeat_failed
    )

    license_key = "XXXX-XXXX-XXXX-XXXX"

    try:
        # Initialize (fetch public key)
        client.initialize()

        # Activate license
        result = client.activate(license_key)
        print(f"License activated: {result}")

        # License is now active with automatic heartbeat
        # The client will send heartbeats every 5 minutes

        # Keep running (for demo)
        import signal
        signal.pause()

    except Exception as e:
        print(f"Activation failed: {e}")
