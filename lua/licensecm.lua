--[[
    LicenseCM Lua SDK with Enhanced Security Features

    Dependencies:
    - lua-cjson (JSON encoding/decoding)
    - luasec (HTTPS support)
    - luasocket (HTTP requests)
    - luaossl or openssl-lua (AES-GCM encryption)

    Usage:
    local LicenseCM = require("licensecm")
    local client = LicenseCM.new({
        base_url = "http://localhost:3000",
        product_id = "your-product-id",
        secret_key = "your-secret-key"
    })

    client:activate("XXXX-XXXX-XXXX-XXXX")
]]

local json = require("cjson")
local http = require("socket.http")
local ltn12 = require("ltn12")
local socket = require("socket")

-- Try to load crypto libraries
local has_crypto = false
local openssl
pcall(function()
    openssl = require("openssl")
    has_crypto = true
end)

local LicenseCM = {}
LicenseCM.__index = LicenseCM

-- Helper function to convert bytes to hex
local function bytes_to_hex(bytes)
    local hex = ""
    for i = 1, #bytes do
        hex = hex .. string.format("%02x", string.byte(bytes, i))
    end
    return hex
end

-- Helper function to convert hex to bytes
local function hex_to_bytes(hex)
    local bytes = ""
    for i = 1, #hex, 2 do
        bytes = bytes .. string.char(tonumber(hex:sub(i, i + 1), 16))
    end
    return bytes
end

-- Simple SHA256 implementation (requires external library in production)
local function sha256(data)
    if has_crypto and openssl then
        local digest = openssl.digest.new("sha256")
        digest:update(data)
        return bytes_to_hex(digest:final())
    else
        -- Fallback: use system command
        local handle = io.popen('echo -n "' .. data .. '" | sha256sum')
        local result = handle:read("*a")
        handle:close()
        return result:match("^(%x+)")
    end
end

-- HMAC-SHA256
local function hmac_sha256(key, data)
    if has_crypto and openssl then
        local hmac = openssl.hmac.new("sha256", key)
        hmac:update(data)
        return bytes_to_hex(hmac:final())
    else
        -- Fallback: use system command
        local handle = io.popen('echo -n "' .. data .. '" | openssl dgst -sha256 -hmac "' .. key .. '"')
        local result = handle:read("*a")
        handle:close()
        return result:match("(%x+)%s*$")
    end
end

-- Generate Hardware ID
function LicenseCM.generate_hwid()
    local components = {}

    -- OS info
    local os_name = package.config:sub(1, 1) == "\\" and "windows" or "unix"
    table.insert(components, os_name)

    -- Hostname
    local handle = io.popen("hostname")
    local hostname = handle:read("*a"):gsub("%s+", "")
    handle:close()
    table.insert(components, hostname)

    -- MAC address
    local mac_cmd = os_name == "windows"
        and "getmac /fo csv /nh"
        or "ip link show 2>/dev/null | grep -o -E '([0-9a-f]{2}:){5}[0-9a-f]{2}' | head -1"
    handle = io.popen(mac_cmd)
    local mac = handle:read("*a"):match("([%x:%-]+)")
    handle:close()
    if mac then
        table.insert(components, mac)
    end

    local data = table.concat(components, "|")
    return sha256(data)
end

-- Create new client
function LicenseCM.new(options)
    local self = setmetatable({}, LicenseCM)

    self.base_url = (options.base_url or "http://localhost:3000"):gsub("/$", "")
    self.product_id = options.product_id or ""
    self.secret_key = options.secret_key or ""
    self.use_encryption = options.use_encryption or false
    self.auto_heartbeat = options.auto_heartbeat ~= false
    self.heartbeat_interval = options.heartbeat_interval or 300 -- 5 minutes

    -- Session state
    self.session_token = nil
    self.session_expires = nil
    self.license_key = nil
    self.hwid = nil
    self.public_key = nil
    self.heartbeat_timer = nil

    -- Callbacks
    self.on_session_expired = options.on_session_expired or function() end
    self.on_security_violation = options.on_security_violation or function() end
    self.on_heartbeat_failed = options.on_heartbeat_failed or function() end

    return self
end

-- Collect client data
function LicenseCM:collect_client_data()
    local os_name = package.config:sub(1, 1) == "\\" and "Windows" or "Unix"

    local hostname = ""
    local handle = io.popen("hostname")
    hostname = handle:read("*a"):gsub("%s+", "")
    handle:close()

    return {
        hwid = self.hwid or LicenseCM.generate_hwid(),
        timestamp = os.time() * 1000,
        platform = os_name,
        hostname = hostname,
        lua_version = _VERSION,
        env_indicators = {
            debug_mode = os.getenv("DEBUG") ~= nil
        },
        vm_indicators = self:detect_vm_indicators(),
        debug_indicators = self:detect_debug_indicators()
    }
end

function LicenseCM:detect_vm_indicators()
    local indicators = {}

    -- Check hostname
    local handle = io.popen("hostname")
    local hostname = handle:read("*a"):lower()
    handle:close()

    local vm_hostnames = {"vmware", "virtualbox", "sandbox", "virtual", "qemu"}
    for _, vm in ipairs(vm_hostnames) do
        if hostname:find(vm) then
            table.insert(indicators, "suspicious_hostname")
            break
        end
    end

    return indicators
end

function LicenseCM:detect_debug_indicators()
    local indicators = {}

    if os.getenv("DEBUG") then
        table.insert(indicators, "env_debug")
    end

    -- Timing analysis
    local start = socket.gettime()
    for i = 1, 1000 do
        math.random()
    end
    local duration = (socket.gettime() - start) * 1000

    if duration > 100 then
        table.insert(indicators, "timing_anomaly")
    end

    return indicators
end

-- Sign data
function LicenseCM:sign(data)
    return hmac_sha256(self.secret_key, data)
end

-- Make HTTP request
function LicenseCM:request(endpoint, data)
    local client_data = self:collect_client_data()

    local body = {}
    for k, v in pairs(data) do
        body[k] = v
    end
    body.product_id = self.product_id
    body.client_data = client_data

    if self.session_token then
        body.session_token = self.session_token
    end

    -- Encryption support would go here if needed

    local request_body = json.encode(body)
    local response_body = {}

    local url = self.base_url .. "/api/client" .. endpoint

    local res, code, headers = http.request{
        url = url,
        method = "POST",
        headers = {
            ["Content-Type"] = "application/json",
            ["Content-Length"] = #request_body
        },
        source = ltn12.source.string(request_body),
        sink = ltn12.sink.table(response_body)
    }

    if not res then
        error("Failed to connect to server")
    end

    local response = json.decode(table.concat(response_body))

    if response.success then
        local result = response.data or {}

        -- Handle session token rotation
        if result.new_token then
            self.session_token = result.new_token
        end

        -- Handle session info
        if result.session then
            self.session_token = result.session.token
            self.session_expires = result.session.expires_at
        end

        return result
    else
        -- Handle security violations
        if response.security_blocked then
            self.on_security_violation({
                type = "blocked",
                reason = response.message
            })
        end

        error(response.message or "Unknown error")
    end
end

-- Fetch public key
function LicenseCM:fetch_public_key()
    local response_body = {}

    http.request{
        url = self.base_url .. "/api/client/public-key",
        method = "GET",
        sink = ltn12.sink.table(response_body)
    }

    local response = json.decode(table.concat(response_body))

    if response.success and response.data then
        self.public_key = response.data.public_key
        return self.public_key
    end

    return nil
end

-- Initialize
function LicenseCM:initialize()
    pcall(function()
        self:fetch_public_key()
    end)
    return true
end

-- Validate license
function LicenseCM:validate(license_key, hwid)
    self.license_key = license_key
    self.hwid = hwid or LicenseCM.generate_hwid()

    return self:request("/validate", {
        license_key = license_key,
        hwid = self.hwid
    })
end

-- Activate license
function LicenseCM:activate(license_key, hwid)
    self.license_key = license_key
    self.hwid = hwid or LicenseCM.generate_hwid()

    local result = self:request("/activate", {
        license_key = license_key,
        hwid = self.hwid
    })

    -- Note: Heartbeat in Lua requires external timer/coroutine library

    return result
end

-- Deactivate license
function LicenseCM:deactivate(license_key, hwid)
    local lk = license_key or self.license_key
    local hw = hwid or self.hwid or LicenseCM.generate_hwid()

    local result = self:request("/deactivate", {
        license_key = lk,
        hwid = hw
    })

    self.session_token = nil
    self.session_expires = nil

    return result
end

-- Heartbeat
function LicenseCM:heartbeat(license_key, hwid)
    local lk = license_key or self.license_key
    local hw = hwid or self.hwid or LicenseCM.generate_hwid()

    return self:request("/heartbeat", {
        license_key = lk,
        hwid = hw
    })
end

-- Check session validity
function LicenseCM:is_session_valid()
    if not self.session_token or not self.session_expires then
        return false
    end
    -- Note: Proper date comparison would require a date parsing library
    return true
end

-- Get session info
function LicenseCM:get_session_info()
    return {
        token = self.session_token,
        expires = self.session_expires,
        is_valid = self:is_session_valid()
    }
end

-- Cleanup
function LicenseCM:destroy()
    self.session_token = nil
    self.session_expires = nil
    self.license_key = nil
    self.hwid = nil
end

return LicenseCM

--[[
Example usage:

local LicenseCM = require("licensecm")

local client = LicenseCM.new({
    base_url = "http://localhost:3000",
    product_id = "your-product-id",
    secret_key = "your-secret-key",
    use_encryption = false,
    auto_heartbeat = true,
    on_session_expired = function()
        print("Session expired!")
    end,
    on_security_violation = function(details)
        print("Security violation:", details.reason)
    end
})

-- Initialize
client:initialize()

-- Activate
local success, result = pcall(function()
    return client:activate("XXXX-XXXX-XXXX-XXXX")
end)

if success then
    print("License activated!")
    print("Session info:", client:get_session_info())
else
    print("Activation failed:", result)
end

-- Cleanup when done
client:destroy()
]]
