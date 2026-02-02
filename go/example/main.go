package main

import (
	"fmt"
	"os"
	"os/signal"
	"syscall"

	licensecm "github.com/licensecm/sdk-go"
)

func main() {
	client := licensecm.NewClient(
		"http://localhost:3000",
		"your-product-id",
		"your-secret-key",
	)

	client.UseEncryption = true
	client.AutoHeartbeat = true

	// Set callbacks
	client.OnSessionExpired = func() {
		fmt.Println("Session expired! Please re-activate.")
		os.Exit(1)
	}

	client.OnSecurityViolation = func(details map[string]interface{}) {
		fmt.Printf("Security violation detected: %v\n", details)
		os.Exit(1)
	}

	client.OnHeartbeatFailed = func(err error) {
		fmt.Printf("Heartbeat failed: %v\n", err)
	}

	licenseKey := "XXXX-XXXX-XXXX-XXXX"

	// Initialize (fetch public key)
	if err := client.Initialize(); err != nil {
		fmt.Printf("Warning: Failed to initialize: %v\n", err)
	}

	// Activate license
	result, err := client.Activate(licenseKey, "")
	if err != nil {
		fmt.Printf("Activation failed: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("License activated: %v\n", result)

	// License is now active with automatic heartbeat
	// The client will send heartbeats every 5 minutes

	// Wait for interrupt signal
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
	<-sigChan

	// Cleanup
	fmt.Println("Shutting down...")
	client.Deactivate("", "")
	client.Destroy()
}
