//! Basic example of using LicenseCM SDK

use licensecm::LicenseCMClient;
use std::error::Error;

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let mut client = LicenseCMClient::new(
        "http://localhost:3000",
        "your-product-id",
        "your-secret-key",
    );

    client
        .set_use_encryption(true)
        .set_auto_heartbeat(true);

    let license_key = "XXXX-XXXX-XXXX-XXXX";

    // Initialize (fetch public key)
    client.initialize().await?;

    // Activate license
    let result = client.activate(license_key, None).await?;
    println!("License activated: {:?}", result);

    // License is now active with automatic heartbeat
    println!("Session info: {:?}", client.get_session_info());

    // Wait for user input
    println!("Press Enter to exit...");
    let mut input = String::new();
    std::io::stdin().read_line(&mut input)?;

    // Cleanup
    client.deactivate(None, None).await?;
    client.destroy();

    Ok(())
}
