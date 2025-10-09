#![forbid(unsafe_code)]

use futures::stream::{FuturesUnordered, StreamExt};
use indicatif::{ProgressBar, ProgressStyle};
use reqwest::Client;
use std::collections::HashMap;
use std::env;
use std::fs::File;
use std::fs::OpenOptions;
use std::io::{BufRead, BufReader};
use std::io::{BufWriter, Write};
use reqwest::header::{ACCEPT, AUTHORIZATION};
use serde_json::{Value, from_str};

use regex::Regex;
use log::{warn, error};
use std::process::exit;

/// Configuration struct to hold all API credentials
#[derive(Debug, Clone)]
struct ApiConfig {
    ipinfo_token: String,
    censys_org_id: String,
    censys_api_secret: String,
}


/// Type alias for the future used in IP info lookups.
type IpInfoFuture =
    futures::future::BoxFuture<'static, (String, usize, Result<IpInfo, Box<dyn std::error::Error + Send + Sync>>)>;

/// Checks if a string is a valid IPv4 or IPv6 address.
///
/// This function attempts to parse the input string as both an IPv4 and IPv6 address.
/// It returns `true` if the string is a valid IP address in either format, and `false` otherwise.
///
/// # Arguments
/// * `ip` - A string slice that may represent an IP address.
///
/// # Returns
/// * `true` if the input is a valid IPv4 or IPv6 address.
/// * `false` if the input is not a valid IP address.
///
/// # Examples
/// ```
/// assert!(is_valid_ip("192.168.1.1"));
/// assert!(is_valid_ip("2001:db8::1"));
/// assert!(!is_valid_ip("not.an.ip"));
/// ```
fn is_valid_ip(ip: &str) -> bool {
    // Try IPv4
    if ip.parse::<std::net::Ipv4Addr>().is_ok() {
        return true;
    }
    // Try IPv6
    if ip.parse::<std::net::Ipv6Addr>().is_ok() {
        return true;
    }
    false
}



/// Parses the log file and counts the occurrences of each IPv4 address.
///
/// Reads the specified log file line by line, extracts all IPv4 addresses using a regular
/// expression, and counts how many times each address appears.
///
/// # Arguments
/// * `file_path` - Path to the log file to parse.
///
/// # Returns
/// A `HashMap` where the keys are IP addresses as `String` and the values are the number of times each IP appears in the log.
///
/// # Panics
/// Panics if the file cannot be opened or the regex cannot be compiled.
fn parse_log_file(file_path: &str) -> HashMap<String, usize> {
    static IP_RE: std::sync::LazyLock<Regex> = std::sync::LazyLock::new(|| {
        // IPv4 and IPv6 regex
        Regex::new(r"((\d{1,3}\.){3}\d{1,3})|([a-fA-F0-9:]{2,39})").unwrap()
    });
    let file = match File::open(file_path) {
        Ok(f) => f,
        Err(e) => {
            error!("Failed to open log file: {e}");
            return HashMap::new();
        }
    };
    let reader = BufReader::new(file);
    let mut ip_counts: HashMap<String, usize> = HashMap::new();
    for line in reader.lines().map_while(Result::ok) {
        for cap in IP_RE.captures_iter(&line) {
            let ip = cap[0].to_string();
            if is_valid_ip(&ip) {
                *ip_counts.entry(ip).or_insert(0) += 1;
            }
        }
    }
    ip_counts
}

/// Looks up and prints information for each unique IP address, sorted by count.
///
/// For each unique IP address (sorted by occurrence count descending), this function:
/// - Checks a local cache for previous lookup results.
/// - If not cached, queries the ipinfo.io API for country and organization info.
/// - Caches new results to a file for future runs.
/// - Prints the results to standard output.
///
/// # Arguments
/// * `ip_counts` - A `HashMap` mapping IP addresses to their occurrence counts.
/// * `client` - A reference to a configured `reqwest::Client` for HTTP requests.
/// * `config` - A reference to `ApiConfig` containing API credentials.
///
/// # Side Effects
/// Writes new IP info results to a cache file (`ipinfo_cache.tsv`).
async fn print_ip_info_sorted(ip_counts: HashMap<String, usize>, client: &Client, config: &ApiConfig) {
    let mut ip_vec: Vec<_> = ip_counts.into_iter().collect();
    ip_vec.sort_by(|a, b| b.1.cmp(&a.1));

    // Load cache from file
    let cache_path = "ipinfo_cache.tsv";
    let (cache, initial_cache) = load_ip_cache(cache_path);
    
    // Process IP lookups with concurrency control
    let (results, new_cache_lines) = process_ip_lookups(ip_vec, &cache, &initial_cache, client, config).await;
    
    // Save new results to cache
    save_to_cache(cache_path, new_cache_lines);
    
    // Print sorted results
    print_results(results);
}

/// Load IP information from cache file
///
/// # Arguments
/// * `cache_path` - Path to the cache file
///
/// # Returns
/// A tuple containing:
/// * Current cache mapping IPs to their info
/// * Initial cache state for detecting new entries
fn load_ip_cache(cache_path: &str) -> (
    HashMap<String, (Option<String>, Option<String>, Option<String>, Option<String>)>,
    HashMap<String, (Option<String>, Option<String>, Option<String>, Option<String>)>
) {
    let mut cache = HashMap::new();
    let mut initial_cache = HashMap::new();
    
    match File::open(cache_path) {
        Ok(cache_file) => {
            let reader = BufReader::new(cache_file);
            for line in reader.lines() {
                match line {
                    Ok(line) => {
                        let parts: Vec<_> = line.splitn(5, '\t').collect();
                        if parts.len() >= 3 && is_valid_ip(parts[0]) {
                            // Extract country and org
                            let country = Some(parts[1].to_string()).filter(|s| s != "N/A");
                            let org = Some(parts[2].to_string()).filter(|s| s != "N/A");
                            
                            // Extract censys data if available
                            let censys_country = if parts.len() >= 4 { 
                                Some(parts[3].to_string()).filter(|s| s != "N/A") 
                            } else { 
                                None 
                            };
                            
                            let censys_org = if parts.len() >= 5 { 
                                Some(parts[4].to_string()).filter(|s| s != "N/A") 
                            } else { 
                                None 
                            };
                            
                            // Store in cache
                            cache.insert(
                                parts[0].to_string(),
                                (country.clone(), org.clone(), censys_country.clone(), censys_org.clone()),
                            );
                            initial_cache.insert(
                                parts[0].to_string(),
                                (country, org, censys_country, censys_org),
                            );
                        } else {
                            warn!("Skipping malformed or invalid cache line: {line}");
                        }
                    }
                    Err(e) => {
                        warn!("Failed to read cache line: {e}");
                    }
                }
            }
        }
        Err(e) => {
            warn!("Could not open cache file: {e}");
        }
    }
    
    (cache, initial_cache)
}

/// Process IP lookups with concurrency control
///
/// # Arguments
/// * `ip_vec` - Vector of (IP, count) pairs
/// * `cache` - Cache of previously looked up IPs
/// * `initial_cache` - Initial state of the cache to detect new entries
/// * `client` - HTTP client
/// * `config` - API configuration
///
/// # Returns
/// A tuple containing:
/// * Results vector of (IP, count, lookup result)
/// * New cache lines for saving to file
async fn process_ip_lookups(
    ip_vec: Vec<(String, usize)>,
    cache: &HashMap<String, (Option<String>, Option<String>, Option<String>, Option<String>)>,
    initial_cache: &HashMap<String, (Option<String>, Option<String>, Option<String>, Option<String>)>,
    client: &Client,
    config: &ApiConfig
) -> (
    Vec<(String, usize, Result<IpInfo, Box<dyn std::error::Error + Send + Sync>>)>,
    Vec<String>
) {
    // Define the constant for maximum concurrent requests
    const MAX_CONCURRENT: usize = 10;
    
    let mut futures: FuturesUnordered<IpInfoFuture> = FuturesUnordered::new();
    let pb = ProgressBar::new(ip_vec.len() as u64);
    pb.set_style(
        ProgressStyle::with_template("[{bar:40.cyan/blue}] {pos}/{len} IPs looked up").unwrap(),
    );

    // Initialize result collections
    let mut results = Vec::new();
    let mut new_cache_lines = Vec::new();
    let mut current_batch = 0;
    
    for (ip, count) in ip_vec.clone() {
        let ip_str = ip.clone();
        let client = client.clone();
        if let Some((country, org, censys_country, censys_org)) = cache.get(&ip_str) {
            let info = IpInfo {
                country: country.clone(),
                org: org.clone(),
                censys_country: censys_country.clone(),
                censys_org: censys_org.clone(),
            };
            futures.push(Box::pin(async move { (ip_str, count, Ok(info)) }));
        } else {
            let config_clone = config.clone();
            futures.push(Box::pin(async move {
                let res = lookup_ip_info(&ip_str, &client, &config_clone).await;
                (ip_str, count, res)
            }));
        }
        
        current_batch += 1;
        // Process in batches to control concurrency
        if current_batch >= MAX_CONCURRENT {
            process_completed_futures(&mut futures, &mut results, initial_cache, &mut new_cache_lines, &pb).await;
            current_batch = 0;
        }
    }
    
    // Process remaining futures
    while let Some((ip, count, result)) = futures.next().await {
        pb.inc(1);
        if let Ok(ref info) = result {
            // Only add to cache if not present in initial cache
            if !initial_cache.contains_key(&ip) {
                add_to_cache_lines(&ip, info, &mut new_cache_lines);
            }
        }
        results.push((ip, count, result));
    }
    pb.finish_and_clear();
    
    (results, new_cache_lines)
}

/// Process completed futures from the queue
///
/// Helper method for process_ip_lookups
async fn process_completed_futures(
    futures: &mut FuturesUnordered<IpInfoFuture>,
    results: &mut Vec<(String, usize, Result<IpInfo, Box<dyn std::error::Error + Send + Sync>>)>,
    initial_cache: &HashMap<String, (Option<String>, Option<String>, Option<String>, Option<String>)>,
    new_cache_lines: &mut Vec<String>,
    pb: &ProgressBar
) {
    // Define threshold for batch processing (half of MAX_CONCURRENT)
    const BATCH_THRESHOLD: usize = 5;
    
    // Wait for some futures to complete before adding more
    while futures.len() >= BATCH_THRESHOLD {
        if let Some((ip, count, result)) = futures.next().await {
            pb.inc(1);
            if let Ok(ref info) = result {
                if !initial_cache.contains_key(&ip) {
                    add_to_cache_lines(&ip, info, new_cache_lines);
                }
            }
            results.push((ip, count, result));
        }
    }
}

/// Add IP info to cache lines
fn add_to_cache_lines(ip: &str, info: &IpInfo, cache_lines: &mut Vec<String>) {
    let country = info.country.clone().unwrap_or_else(|| "N/A".to_string());
    let org = info.org.clone().unwrap_or_else(|| "N/A".to_string());
    let censys_country = info.censys_country.clone().unwrap_or_else(|| "N/A".to_string());
    let censys_org = info.censys_org.clone().unwrap_or_else(|| "N/A".to_string());
    cache_lines.push(format!("{ip}\t{country}\t{org}\t{censys_country}\t{censys_org}"));
}

/// Save new IP info to cache file
///
/// # Arguments
/// * `cache_path` - Path to the cache file
/// * `new_cache_lines` - Lines to append to the cache file
fn save_to_cache(cache_path: &str, new_cache_lines: Vec<String>) {
    // Append new cache lines to file
    if !new_cache_lines.is_empty() {
        use std::os::unix::fs::OpenOptionsExt;
        let mut file = OpenOptions::new()
            .create(true)
            .append(true)
            .mode(0o600)
            .open(cache_path)
            .expect("Failed to open cache file");
        let mut writer = BufWriter::new(&mut file);
        for line in new_cache_lines {
            if let Err(e) = writeln!(writer, "{line}") {
                warn!("Failed to write cache line: {e}");
            }
        }
    }
}

/// Print results in a formatted table
///
/// # Arguments
/// * `results` - Vector of (IP, count, lookup result) tuples
fn print_results(mut results: Vec<(String, usize, Result<IpInfo, Box<dyn std::error::Error + Send + Sync>>)>) {
    // Sort results by count descending before printing
    results.sort_by(|a, b| b.1.cmp(&a.1));
    for (ip, count, result) in results {
        // Format IP: compress IPv6, leave IPv4 as is
        let formatted_ip = format_ip_address(&ip);
        match result {
            Ok(info) => {
                println!(
                    "{formatted_ip} | {count} | {} | {} | {} | {}",
                    info.country.unwrap_or_else(|| "N/A".to_string()),
                    info.org.unwrap_or_else(|| "N/A".to_string()),
                    info.censys_country.unwrap_or_else(|| "N/A".to_string()),
                    info.censys_org.unwrap_or_else(|| "N/A".to_string())
                );
            }
            Err(e) => {
                println!("IP: {formatted_ip} | Count: {count} | Lookup failed: {e}");
            }
        }
    }
}

/// Format IP address for display
///
/// Compresses IPv6 addresses and keeps IPv4 as is
fn format_ip_address(ip: &str) -> String {
    if let Ok(addr) = ip.parse::<std::net::Ipv6Addr>() {
        // Use the standard compressed format for IPv6
        format!("[{addr}]")
    } else {
        ip.to_string()
    }
}

/// Struct for storing IP information from multiple API responses.
#[derive(Debug)]
struct IpInfo {
    country: Option<String>,
    org: Option<String>,
    censys_country: Option<String>,
    censys_org: Option<String>,
}

/// Response struct for deserializing IP information from the ipinfo.io API.
#[derive(Debug, serde::Deserialize)]
struct IpInfoResponse {
    country: Option<String>,
    org: Option<String>,
}

/// Looks up information for a given IP address using the ipinfo.io API.
///
/// Sends a GET request to the ipinfo.io API for the provided IP address and attempts to
/// deserialize the response into an `IpInfo` struct, which contains the country and
/// organization (owner) information if available.
///
/// # Arguments
/// * `ip` - The IP address to look up as a string slice.
/// * `client` - A reference to a configured `reqwest::Client` for HTTP requests.
/// * `config` - A reference to `ApiConfig` containing API credentials.
///
/// # Returns
/// * `Ok(IpInfo)` if the lookup and deserialization succeed.
/// * `Err(Box<dyn Error>)` if the HTTP request or deserialization fails.
async fn lookup_ip_info(ip: &str, client: &Client, config: &ApiConfig) -> Result<IpInfo, Box<dyn std::error::Error + Send + Sync>> {
    let url = format!("https://ipinfo.io/{ip}/json?token={}", config.ipinfo_token);
    let resp = client.get(&url).send().await?;
    if resp.status() == reqwest::StatusCode::TOO_MANY_REQUESTS {
        // Rate limit exceeded, return special IpInfo
        return Ok(IpInfo {
            country: Some("exceeded".to_string()),
            org: Some("exceeded".to_string()),
            censys_country: None,
            censys_org: None,
        });
    }
    let response = resp.json::<IpInfoResponse>().await?;
    
    // Get Censys data
    let censys_data = match get_censys_info(ip, &config.censys_org_id, &config.censys_api_secret).await {
        Ok((censys_org, censys_country)) => (Some(censys_org), Some(censys_country)),
        Err(e) => {
            log::debug!("Censys lookup error for IP {}: {}", ip, e);
            (None, None)
        }
    };
    
    Ok(IpInfo {
        country: response.country,
        org: response.org,
        censys_org: censys_data.0,
        censys_country: censys_data.1,
    })
}


/// Retrieves IP information from the Censys API
///
/// # Arguments
/// * `ip` - The IP address to look up as a string slice.
/// * `org_id` - The Censys organization ID.
/// * `api_secret` - The Censys API secret.
///
/// # Returns
/// * `Ok((org, country))` if the lookup succeeds.
/// * `Err(reqwest::Error)` if the HTTP request fails.
async fn get_censys_info(ip: &str, org_id: &str, api_secret: &str) -> Result<(String, String), Box<dyn std::error::Error>> {
    // Check if credentials are provided
    if org_id.is_empty() || api_secret.is_empty() {
        return Ok(("N/A".to_string(), "N/A".to_string()));
    }
    
    let client = reqwest::Client::new();
    let base = "https://api.platform.censys.io/v3/global/asset/host/";
    let url = format!("{base}{ip}?organization_id={org_id}");

    // Set the headers
    let accept_header = "application/vnd.censys.api.v3.host.v1+json";
    let bearer_token = format!("Bearer {}", api_secret);

    // Send GET request
    let response = client
        .get(url)
        .header(ACCEPT, accept_header)
        .header(AUTHORIZATION, bearer_token)
        .send()
        .await?;

    // Get the response body as text
    let body = response.text().await?;
    
    // Extract host details
    return match extract_host_details(&body) {
        Ok((owner, country)) => Ok((owner, country)),
        Err(e) => {
            log::debug!("Error extracting Censys host details: {e}");
            Ok(("N/A".to_string(), "N/A".to_string()))
        }
    };
}

// Extract owner organization name and geographic country from host info JSON
fn extract_host_details(json_str: &str) -> Result<(String, String), String> {
    // Parse the JSON string
    let v: Value = from_str(json_str).map_err(|e| format!("Error parsing JSON: {e}"))?;

    // Extract organization name from whois.organization.name
    let owner = v["result"]["resource"]["whois"]["organization"]["name"]
        .as_str()
        .ok_or_else(|| "Organization name not found in JSON".to_string())?
        .to_string();

    // Extract country from location.country
    let country = v["result"]["resource"]["location"]["country"]
        .as_str()
        .ok_or_else(|| "Country not found in JSON".to_string())?
        .to_string();

    Ok((owner, country))
}

/// Main entry point for the faillog application.
///
/// Orchestrates the process of:
/// - Parsing the ban log file to extract and count unique IP addresses.
/// - Printing the number of unique IPs found.
/// - Looking up and displaying information (country, organization) for each IP,
///   sorted by the number of occurrences in descending order.
///
/// # Panics
/// Panics if the log file cannot be opened or the HTTP client cannot be built.
#[tokio::main]
async fn main() {
    dotenvy::from_filename(".env").ok();
    env_logger::init();
    
    let ipinfo_token = match env::var("IPINFO_TOKEN") {
        Ok(token) => token,
        Err(_) => {
            log::error!("IPINFO_TOKEN environment variable not found");
            exit(1);
        }
    };
    let censys_org_id = match env::var("CENSYS_ORG_ID") {
        Ok(id) => id,
        Err(_) => {
            log::error!("CENSYS_ORG_ID environment variable not found");
            exit(1);
        }
    };
    let censys_api_secret = match env::var("CENSYS_API_SECRET") {
        Ok(secret) => secret,
        Err(_) => {
            log::error!("CENSYS_API_SECRET environment variable not found");
            exit(1);
        }
    };
    
    
    let ip_counts = parse_log_file("data/ban_log.txt");
    println!("Found {} unique IPs", ip_counts.len());
    println!("IP | Count | IpInfo Country | IpInfo Org | Censys Country | Censys Org");
    
    let client = Client::builder()
        .build()
        .expect("Failed to build reqwest client");
    
    // Create config struct with all API credentials
    let api_config = ApiConfig {
        ipinfo_token,
        censys_org_id,
        censys_api_secret,
    };
    
    print_ip_info_sorted(ip_counts, &client, &api_config).await;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_is_valid_ip() {
        assert!(is_valid_ip("192.168.1.1"));
        assert!(is_valid_ip("2001:db8::1"));
        assert!(!is_valid_ip("not.an.ip"));
        assert!(!is_valid_ip("999.999.999.999"));
    }

    #[test]
    fn test_parse_log_file_counts_ips() {
        let log = "2025-09-23 12:00:01,123 fail2ban.actions [1234]: NOTICE  [sshd] Ban 192.0.2.1\n2025-09-23 12:01:02,456 fail2ban.actions [1234]: NOTICE  [sshd] Ban 2001:db8::1\n2025-09-23 12:02:03,789 fail2ban.actions [1234]: NOTICE  [sshd] Ban 192.0.2.1\n";
        use std::fs::File;
        use std::io::Write;
        let path = "test_ban_log.txt";
        let mut file = File::create(path).unwrap();
        file.write_all(log.as_bytes()).unwrap();
        let counts = parse_log_file(path);
        std::fs::remove_file(path).unwrap();
        assert_eq!(counts.get("192.0.2.1"), Some(&2));
        assert_eq!(counts.get("2001:db8::1"), Some(&1));
    }
}