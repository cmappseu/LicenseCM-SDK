# frozen_string_literal: true

# LicenseCM Ruby SDK with Enhanced Security Features

require 'net/http'
require 'uri'
require 'json'
require 'openssl'
require 'socket'
require 'digest'
require 'securerandom'

module LicenseCM
  class Client
    attr_accessor :use_encryption, :auto_heartbeat, :heartbeat_interval
    attr_accessor :on_session_expired, :on_security_violation, :on_heartbeat_failed

    def initialize(base_url:, product_id:, secret_key: '')
      @base_url = base_url.chomp('/')
      @product_id = product_id
      @secret_key = secret_key
      @use_encryption = false
      @auto_heartbeat = true
      @heartbeat_interval = 300 # 5 minutes

      # Session state
      @session_token = nil
      @session_expires = nil
      @heartbeat_thread = nil
      @heartbeat_stop = false
      @license_key = nil
      @hwid = nil
      @public_key = nil

      # Callbacks
      @on_session_expired = -> {}
      @on_security_violation = ->(_details) {}
      @on_heartbeat_failed = ->(_error) {}
    end

    # Generate Hardware ID from system information
    def self.generate_hwid
      components = []

      # Platform info
      components << RUBY_PLATFORM
      components << Socket.gethostname

      # MAC address
      mac = get_mac_address
      components << mac if mac

      # CPU count
      components << (Etc.nprocessors rescue 1).to_s

      # Disk serial (Windows)
      if RUBY_PLATFORM =~ /mswin|mingw|cygwin/
        serial = get_disk_serial
        components << serial if serial
      end

      data = components.join('|')
      Digest::SHA256.hexdigest(data)
    end

    def self.get_mac_address
      if RUBY_PLATFORM =~ /mswin|mingw|cygwin/
        output = `getmac 2>nul`
        match = output.match(/([0-9A-F]{2}[:-]){5}[0-9A-F]{2}/i)
        match ? match[0] : nil
      else
        output = `ip link show 2>/dev/null || ifconfig 2>/dev/null`
        match = output.match(/([0-9a-f]{2}:){5}[0-9a-f]{2}/i)
        match ? match[0] : nil
      end
    rescue
      nil
    end

    def self.get_disk_serial
      output = `wmic diskdrive get serialnumber 2>nul`
      lines = output.strip.split("\n")
      lines.length > 1 ? lines[1].strip : nil
    rescue
      nil
    end

    private_class_method :get_mac_address, :get_disk_serial

    def collect_client_data
      {
        hwid: @hwid || self.class.generate_hwid,
        timestamp: (Time.now.to_f * 1000).to_i,
        platform: RUBY_PLATFORM,
        os_version: RUBY_VERSION,
        architecture: RbConfig::CONFIG['host_cpu'],
        hostname: Socket.gethostname,
        ruby_version: RUBY_VERSION,
        env_indicators: {
          debug_mode: !ENV['DEBUG'].nil?,
          rails_env: ENV['RAILS_ENV']
        },
        vm_indicators: detect_vm_indicators,
        debug_indicators: detect_debug_indicators
      }
    end

    def detect_vm_indicators
      indicators = []

      # Check hostname patterns
      hostname = Socket.gethostname.downcase
      vm_hostnames = %w[vmware virtualbox sandbox virtual qemu]
      indicators << 'suspicious_hostname' if vm_hostnames.any? { |vm| hostname.include?(vm) }

      # Check MAC address prefixes
      mac = self.class.send(:get_mac_address)
      if mac
        vm_mac_prefixes = [
          '00:0c:29', '00:50:56', '00:05:69', # VMware
          '08:00:27', '0a:00:27',             # VirtualBox
          '00:15:5d',                         # Hyper-V
          '00:16:3e',                         # Xen
          '52:54:00'                          # QEMU
        ]
        mac_lower = mac.downcase
        indicators << 'vm_mac_address' if vm_mac_prefixes.any? { |prefix| mac_lower.start_with?(prefix) }
      end

      # Check CPU count
      cpu_count = Etc.nprocessors rescue 1
      indicators << 'single_cpu' if cpu_count < 2

      indicators
    end

    def detect_debug_indicators
      indicators = []

      # Check environment variables
      indicators << 'env_debug' unless ENV['DEBUG'].nil?
      indicators << 'env_ruby_debug' unless ENV['RUBY_DEBUG'].nil?

      # Timing analysis
      start = Process.clock_gettime(Process::CLOCK_MONOTONIC)
      1000.times { rand }
      duration = (Process.clock_gettime(Process::CLOCK_MONOTONIC) - start) * 1000

      indicators << 'timing_anomaly' if duration > 100

      indicators
    end

    def encrypt(data)
      key = @secret_key.ljust(32, "\0")[0, 32]
      iv = SecureRandom.random_bytes(16)

      cipher = OpenSSL::Cipher.new('aes-256-gcm')
      cipher.encrypt
      cipher.key = key
      cipher.iv = iv

      ciphertext = cipher.update(data.to_json) + cipher.final
      tag = cipher.auth_tag

      {
        iv: iv.unpack1('H*'),
        data: ciphertext.unpack1('H*'),
        tag: tag.unpack1('H*')
      }
    end

    def decrypt(encrypted)
      key = @secret_key.ljust(32, "\0")[0, 32]
      iv = [encrypted['iv']].pack('H*')
      ciphertext = [encrypted['data']].pack('H*')
      tag = [encrypted['tag']].pack('H*')

      decipher = OpenSSL::Cipher.new('aes-256-gcm')
      decipher.decrypt
      decipher.key = key
      decipher.iv = iv
      decipher.auth_tag = tag

      plaintext = decipher.update(ciphertext) + decipher.final
      JSON.parse(plaintext)
    end

    def sign(data)
      OpenSSL::HMAC.hexdigest('SHA256', @secret_key, data)
    end

    def fetch_public_key
      uri = URI("#{@base_url}/api/client/public-key")
      response = Net::HTTP.get_response(uri)
      result = JSON.parse(response.body)

      if result['success']
        @public_key = result.dig('data', 'public_key')
      end
    rescue
      nil
    end

    def initialize_client
      fetch_public_key
      true
    rescue
      false
    end

    def request(endpoint, data)
      client_data = collect_client_data

      body = data.merge(
        product_id: @product_id,
        client_data: client_data
      )

      body[:session_token] = @session_token if @session_token

      if @use_encryption && !@secret_key.empty?
        timestamp = (Time.now.to_f * 1000).to_i
        encrypted = encrypt(body)
        signature_payload = "#{encrypted[:iv]}:#{encrypted[:data]}:#{encrypted[:tag]}:#{timestamp}"
        signature = sign(signature_payload)

        body = {
          encrypted: true,
          iv: encrypted[:iv],
          data: encrypted[:data],
          tag: encrypted[:tag],
          signature: signature,
          product_id: @product_id,
          timestamp: timestamp
        }
      end

      uri = URI("#{@base_url}/api/client#{endpoint}")
      http = Net::HTTP.new(uri.host, uri.port)
      http.use_ssl = (uri.scheme == 'https')
      http.open_timeout = 30
      http.read_timeout = 30

      request = Net::HTTP::Post.new(uri.path)
      request['Content-Type'] = 'application/json'
      request.body = body.to_json

      response = http.request(request)
      response_data = JSON.parse(response.body)

      # Decrypt if encrypted
      if @use_encryption && response_data['encrypted']
        response_data = decrypt(response_data)
      end

      if response_data['success']
        result = response_data['data'] || {}

        # Handle session token rotation
        @session_token = result['new_token'] if result['new_token']

        # Handle session info
        if result['session']
          @session_token = result.dig('session', 'token')
          if result.dig('session', 'expires_at')
            @session_expires = Time.parse(result['session']['expires_at'])
          end
        end

        result
      else
        # Handle security violations
        if response_data['security_blocked']
          @on_security_violation.call({
            type: 'blocked',
            reason: response_data['message']
          })
        end

        raise StandardError, response_data['message'] || 'Unknown error'
      end
    end

    def validate(license_key, hwid = nil)
      @license_key = license_key
      @hwid = hwid || self.class.generate_hwid

      request('/validate', {
        license_key: license_key,
        hwid: @hwid
      })
    end

    def activate(license_key, hwid = nil)
      @license_key = license_key
      @hwid = hwid || self.class.generate_hwid

      result = request('/activate', {
        license_key: license_key,
        hwid: @hwid
      })

      # Start heartbeat if enabled
      start_heartbeat if @auto_heartbeat && result['session']

      result
    end

    def deactivate(license_key = nil, hwid = nil)
      stop_heartbeat

      lk = license_key || @license_key
      hw = hwid || @hwid || self.class.generate_hwid

      result = request('/deactivate', {
        license_key: lk,
        hwid: hw
      })

      @session_token = nil
      @session_expires = nil

      result
    end

    def heartbeat(license_key = nil, hwid = nil)
      lk = license_key || @license_key
      hw = hwid || @hwid || self.class.generate_hwid

      request('/heartbeat', {
        license_key: lk,
        hwid: hw
      })
    end

    def start_heartbeat
      stop_heartbeat

      @heartbeat_stop = false
      @heartbeat_thread = Thread.new do
        until @heartbeat_stop
          sleep(@heartbeat_interval)
          break if @heartbeat_stop

          begin
            heartbeat
          rescue StandardError => e
            @on_heartbeat_failed.call(e.message)

            if e.message.downcase.include?('expired') || e.message.downcase.include?('invalid')
              stop_heartbeat
              @on_session_expired.call
              break
            end
          end
        end
      end
    end

    def stop_heartbeat
      @heartbeat_stop = true
      @heartbeat_thread&.kill
      @heartbeat_thread = nil
    end

    def session_valid?
      !@session_token.nil? && !@session_expires.nil? && Time.now < @session_expires
    end

    def session_info
      {
        token: @session_token,
        expires: @session_expires&.iso8601,
        is_valid: session_valid?
      }
    end

    def destroy
      stop_heartbeat
      @session_token = nil
      @session_expires = nil
      @license_key = nil
      @hwid = nil
    end
  end
end

# Example usage
if __FILE__ == $PROGRAM_NAME
  client = LicenseCM::Client.new(
    base_url: 'http://localhost:3000',
    product_id: 'your-product-id',
    secret_key: 'your-secret-key'
  )

  client.use_encryption = true
  client.auto_heartbeat = true

  client.on_session_expired = -> { puts 'Session expired! Please re-activate.' }
  client.on_security_violation = ->(details) { puts "Security violation: #{details}" }
  client.on_heartbeat_failed = ->(error) { puts "Heartbeat failed: #{error}" }

  license_key = 'XXXX-XXXX-XXXX-XXXX'

  begin
    # Initialize
    client.initialize_client

    # Activate
    result = client.activate(license_key)
    puts "License activated: #{result}"

    # Keep running
    puts 'Press Enter to exit...'
    gets

    # Deactivate
    client.deactivate

  rescue StandardError => e
    puts "Error: #{e.message}"
  ensure
    client.destroy
  end
end
