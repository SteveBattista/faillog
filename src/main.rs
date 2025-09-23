/// Type alias for the future used in IP info lookups.
type IpInfoFuture = futures::future::BoxFuture<'static, (String, usize, Result<IpInfo, reqwest::Error>)>;
// ...existing code...
/// Validates an IP address string (IPv4 or IPv6).
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

use std::collections::HashMap;
use std::fs::OpenOptions;
use std::io::{Write, BufWriter};
use futures::stream::{FuturesUnordered, StreamExt};
use reqwest::Client;
use std::env;
use indicatif::{ProgressBar, ProgressStyle};
use std::fs::File;
use std::io::{BufRead, BufReader};

use regex::Regex;

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
    let ip_counts = parse_log_file("data/ban_log.txt");
    println!("Found {} unique IPs", ip_counts.len());
    let token = env::var("IPINFO_TOKEN").expect("IPINFO_TOKEN environment variable not set");
    let client = Client::builder()
        .default_headers({
            let mut headers = reqwest::header::HeaderMap::new();
            headers.insert(
                reqwest::header::AUTHORIZATION,
                reqwest::header::HeaderValue::from_str(&format!("Bearer {token}")).expect("Invalid token format"),
            );
            headers
        })
        .build()
        .expect("Failed to build reqwest client");
    print_ip_info_sorted(ip_counts, &client).await;
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
            eprintln!("Error: Failed to open log file: {e}");
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
///
/// # Side Effects
/// Writes new IP info results to a cache file (`ipinfo_cache.tsv`).
async fn print_ip_info_sorted(ip_counts: HashMap<String, usize>, client: &Client) {
    let mut ip_vec: Vec<_> = ip_counts.into_iter().collect();
    ip_vec.sort_by(|a, b| b.1.cmp(&a.1));

    // Load cache from file
    let cache_path = "ipinfo_cache.tsv";
    let mut cache: HashMap<String, (Option<String>, Option<String>)> = HashMap::new();
    let mut initial_cache: HashMap<String, (Option<String>, Option<String>)> = HashMap::new();
    match File::open(cache_path) {
        Ok(cache_file) => {
            let reader = BufReader::new(cache_file);
            for line in reader.lines() {
                match line {
                    Ok(line) => {
                        let parts: Vec<_> = line.splitn(3, '\t').collect();
                        if parts.len() == 3 && is_valid_ip(parts[0]) {
                            cache.insert(parts[0].to_string(), (Some(parts[1].to_string()).filter(|s| s != "N/A"), Some(parts[2].to_string()).filter(|s| s != "N/A")));
                            initial_cache.insert(parts[0].to_string(), (Some(parts[1].to_string()).filter(|s| s != "N/A"), Some(parts[2].to_string()).filter(|s| s != "N/A")));
                        } else {
                            eprintln!("Warning: Skipping malformed or invalid cache line: {line}");
                        }
                    }
                    Err(e) => {
                        eprintln!("Warning: Failed to read cache line: {e}");
                    }
                }
            }
        }
        Err(e) => {
            eprintln!("Warning: Could not open cache file: {e}");
        }
    }

    let mut futures: FuturesUnordered<IpInfoFuture> = FuturesUnordered::new();
    let pb = ProgressBar::new(ip_vec.len() as u64);
    pb.set_style(ProgressStyle::with_template("[{bar:40.cyan/blue}] {pos}/{len} IPs looked up").unwrap());

    for (ip, count) in ip_vec.clone() {
        let ip_str = ip.clone();
        let client = client.clone();
        if let Some((country, org)) = cache.get(&ip_str) {
            let info = IpInfo {
                country: country.clone(),
                org: org.clone(),
            };
            futures.push(Box::pin(async move { (ip_str, count, Ok(info)) }));
        } else {
            futures.push(Box::pin(async move {
                let res = lookup_ip_info(&ip_str, &client).await;
                (ip_str, count, res)
            }));
        }
    }

    let mut results = Vec::new();
    let mut new_cache_lines = Vec::new();
    while let Some((ip, count, result)) = futures.next().await {
        pb.inc(1);
        if let Ok(ref info) = result {
            // Only add to cache if not present in initial cache
            if !initial_cache.contains_key(&ip) {
                let country = info.country.clone().unwrap_or_else(|| "N/A".to_string());
                let org = info.org.clone().unwrap_or_else(|| "N/A".to_string());
                new_cache_lines.push(format!("{ip}\t{country}\t{org}"));
            }
        }
        results.push((ip, count, result));
    }
    pb.finish_and_clear();

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
                eprintln!("Warning: Failed to write cache line: {e}");
            }
        }
    }



    // Sort results by count descending before printing
    results.sort_by(|a, b| b.1.cmp(&a.1));
    for (ip, count, result) in results {
        // Format IP: compress IPv6, leave IPv4 as is
        let formatted_ip = if let Ok(addr) = ip.parse::<std::net::Ipv6Addr>() {
            // Use the standard compressed format for IPv6
            format!("[{}]", addr)
        } else {
            ip.clone()
        };
        match result {
            Ok(info) => {
                println!(
                    "IP: {formatted_ip} | Count: {count} | Country: {} | Org: {}",
                    info.country.unwrap_or_else(|| "N/A".to_string()),
                    info.org.unwrap_or_else(|| "N/A".to_string())
                );
            }
            Err(e) => {
                println!("IP: {formatted_ip} | Count: {count} | Lookup failed: {e}");
            }
        }
    }
}

/// Struct for deserializing IP information from the ipinfo.io API response.
#[derive(Debug, serde::Deserialize)]
struct IpInfo {
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
///
/// # Returns
/// * `Ok(IpInfo)` if the lookup and deserialization succeed.
/// * `Err(reqwest::Error)` if the HTTP request or deserialization fails.
async fn lookup_ip_info(ip: &str, client: &Client) -> Result<IpInfo, reqwest::Error> {
    let url = format!("https://ipinfo.io/{ip}/json");
    let resp = client.get(&url).send().await?;
    if resp.status() == reqwest::StatusCode::TOO_MANY_REQUESTS {
        // Rate limit exceeded, return special IpInfo
        return Ok(IpInfo {
            country: Some("exceeded".to_string()),
            org: Some("exceeded".to_string()),
        });
    }
    let info = resp.json::<IpInfo>().await?;
    Ok(info)
}
