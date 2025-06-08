use reqwest;
use std::env;
use serde::Deserialize;
use anyhow::{Context, Result};

#[derive(Deserialize, Debug)]
struct AccessTokenResponse {
    access_token: String,
    // token_type: String, // Optional: can be added if needed
    // scope: String,      // Optional: can be added if needed
}

pub async fn exchange_code(code: &str) -> Result<String> {
    let client_id = env::var("GITHUB_CLIENT_ID")
        .context("GITHUB_CLIENT_ID environment variable not set")?;
    let client_secret = env::var("GITHUB_CLIENT_SECRET")
        .context("GITHUB_CLIENT_SECRET environment variable not set")?;

    let client = reqwest::Client::new();
    let params = [
        ("client_id", client_id),
        ("client_secret", client_secret),
        ("code", code.to_string()),
    ];

    let res = client.post("https://github.com/login/oauth/access_token")
        .header("Accept", "application/json") // Ensure GitHub returns JSON
        .form(&params)
        .send()
        .await
        .context("Failed to send request to GitHub for token exchange")?;

    if !res.status().is_success() {
        let status = res.status();
        let error_body = res.text().await.unwrap_or_else(|_| "Could not retrieve error body".to_string());
        return Err(anyhow::anyhow!(
            "GitHub API request failed with status {}: {}",
            status,
            error_body
        ));
    }

    let token_response: AccessTokenResponse = res
        .json()
        .await
        .context("Failed to parse JSON response from GitHub")?;
    
    Ok(token_response.access_token)
}

// Example of how GITHUB_CLIENT_ID and GITHUB_CLIENT_SECRET should be set:
// export GITHUB_CLIENT_ID="your_client_id"
// export GITHUB_CLIENT_SECRET="your_client_secret"
// Or set them in a .env file and use a crate like `dotenv` to load them. 