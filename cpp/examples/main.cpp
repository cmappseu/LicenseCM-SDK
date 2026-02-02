/**
 * LicenseCM C++ SDK Example
 *
 * Compile: g++ -std=c++17 -I../include -o example main.cpp -lcurl -lssl -lcrypto
 */

#include <iostream>
#include <string>
#include "licensecm.hpp"

int main() {
    LicenseCM::Client client(
        "http://localhost:3000",
        "your-product-id",
        "your-secret-key"
    );

    client.setUseEncryption(true)
          .setAutoHeartbeat(true)
          .setOnSessionExpired([]() {
              std::cout << "Session expired! Please re-activate." << std::endl;
              std::exit(1);
          })
          .setOnSecurityViolation([](const std::map<std::string, std::string>& details) {
              std::cout << "Security violation: " << details.at("reason") << std::endl;
              std::exit(1);
          })
          .setOnHeartbeatFailed([](const std::string& error) {
              std::cout << "Heartbeat failed: " << error << std::endl;
          });

    const std::string license_key = "XXXX-XXXX-XXXX-XXXX";

    try {
        // Initialize
        client.initialize();

        // Activate license
        auto result = client.activate(license_key);
        std::cout << "License activated: " << result.dump() << std::endl;

        // Session info
        auto session = client.getSessionInfo();
        std::cout << "Session token: " << session["token"] << std::endl;

        // Wait for user input
        std::cout << "Press Enter to exit..." << std::endl;
        std::cin.get();

        // Deactivate
        client.deactivate();

    } catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << std::endl;
        return 1;
    }

    return 0;
}
