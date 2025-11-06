#![forbid(unsafe_code)]

use futures::stream::{FuturesUnordered, StreamExt};
use indicatif::{ProgressBar, ProgressStyle};
use reqwest::Client;
use std::collections::{HashSet, HashMap};
use std::env;
use std::fs::{File, OpenOptions};
use std::io::{BufRead, BufReader, BufWriter, Write};
use serde_json;

use log::{warn, error};
use std::process::exit;

/// Struct for storing ASN information from IPInfo API
#[derive(Debug, Clone)]
struct AsnInfo {
    asn: u32,
    name: Option<String>,
    country: Option<String>,
    domain: Option<String>,
    country_breakdown: Vec<CountryBreakdown>,
}

/// Configuration struct to hold API credentials
#[derive(Debug, Clone)]
struct ApiConfig {
    ipinfo_token: String,
}

/// Response struct for deserializing ASN information from the ipinfo.io API
#[derive(Debug, serde::Deserialize)]
struct IPInfoAsnResponse {
    #[serde(rename = "asn")]
    asn_number: Option<String>,
    name: Option<String>,
    domain: Option<String>,
    country: Option<String>,
    #[serde(rename = "country_codes")]
    country_codes: Option<serde_json::Value>,
    prefixes: Option<Vec<IPInfoPrefix>>,
}

/// Prefix information from IPInfo ASN response
#[derive(Debug, serde::Deserialize)]
struct IPInfoPrefix {
    netblock: String,
    id: Option<String>,
    name: Option<String>,
    country: Option<String>,
}

/// Country breakdown with percentage
#[derive(Debug, Clone)]
struct CountryBreakdown {
    country: String,
    percentage: f32,
    netblock_count: usize,
}

/// Parses the ASN list file and extracts unique ASN numbers.
///
/// Reads the specified ASN list file line by line and extracts ASN numbers.
///
/// # Arguments
/// * `file_path` - Path to the ASN list file to parse.
///
/// # Returns
/// A `Vec<u32>` containing unique ASN numbers.
fn parse_asn_file(file_path: &str) -> Vec<u32> {
    let file = match File::open(file_path) {
        Ok(f) => f,
        Err(e) => {
            error!("Failed to open ASN file: {e}");
            return Vec::new();
        }
    };
    let reader = BufReader::new(file);
    let mut asns = HashSet::new();
    
    for line in reader.lines().map_while(Result::ok) {
        let line = line.trim();
        if !line.is_empty() && !line.starts_with('#') {
            if let Ok(asn) = line.parse::<u32>() {
                asns.insert(asn);
            } else {
                warn!("Invalid ASN number: {}", line);
            }
        }
    }
    
    asns.into_iter().collect()
}

/// Calculate country breakdown from IPInfo prefixes
fn calculate_country_breakdown(prefixes: &Option<Vec<IPInfoPrefix>>) -> Vec<CountryBreakdown> {
    let mut country_counts = HashMap::new();
    let mut total_prefixes = 0;
    
    if let Some(prefix_list) = prefixes {
        for prefix in prefix_list {
            total_prefixes += 1;
            let country = prefix.country.as_deref().unwrap_or("Unknown").to_string();
            *country_counts.entry(country).or_insert(0) += 1;
        }
    }
    
    if total_prefixes == 0 {
        return vec![];
    }
    
    let mut breakdown: Vec<CountryBreakdown> = country_counts
        .into_iter()
        .map(|(country, count)| CountryBreakdown {
            country,
            percentage: (count as f32 / total_prefixes as f32) * 100.0,
            netblock_count: count,
        })
        .collect();
    
    // Sort by percentage descending
    breakdown.sort_by(|a, b| b.percentage.partial_cmp(&a.percentage).unwrap());
    
    breakdown
}

/// Load IPInfo ASN cache from file
///
/// # Arguments
/// * `cache_path` - Path to the cache file
///
/// # Returns
/// HashMap containing cached ASN data (ASN -> (name, country, domain, country_breakdown))
fn load_ipinfo_asn_cache(cache_path: &str) -> HashMap<u32, (Option<String>, Option<String>, Option<String>, Vec<CountryBreakdown>)> {
    let mut cache = HashMap::new();
    
    match File::open(cache_path) {
        Ok(cache_file) => {
            let reader = BufReader::new(cache_file);
            for line in reader.lines() {
                if let Ok(line) = line {
                    let parts: Vec<_> = line.splitn(5, '\t').collect();
                    if parts.len() >= 4 {
                        if let Ok(asn) = parts[0].parse::<u32>() {
                            let name = if parts[1] == "N/A" || parts[1].is_empty() { 
                                None 
                            } else { 
                                Some(parts[1].to_string()) 
                            };
                            let country = if parts[2] == "N/A" || parts[2].is_empty() { 
                                None 
                            } else { 
                                Some(parts[2].to_string()) 
                            };
                            let domain = if parts[3] == "N/A" || parts[3].is_empty() { 
                                None 
                            } else { 
                                Some(parts[3].to_string()) 
                            };
                            
                            // Parse country breakdown if available (parts[4])
                            let country_breakdown = if parts.len() >= 5 && parts[4] != "N/A" && !parts[4].is_empty() {
                                parse_country_breakdown_from_cache(parts[4])
                            } else {
                                vec![]
                            };
                            
                            cache.insert(asn, (name, country, domain, country_breakdown));
                        } else {
                            warn!("Invalid ASN in cache line: {}", line);
                        }
                    } else {
                        warn!("Malformed cache line: {}", line);
                    }
                }
            }
        }
        Err(e) => {
            warn!("Could not open IPInfo ASN cache file: {}", e);
        }
    }
    
    cache
}

/// Parse country breakdown from cache string format
fn parse_country_breakdown_from_cache(breakdown_str: &str) -> Vec<CountryBreakdown> {
    breakdown_str
        .split(';')
        .filter_map(|entry| {
            let parts: Vec<&str> = entry.split(':').collect();
            if parts.len() == 3 {
                if let (Ok(percentage), Ok(count)) = (parts[1].parse::<f32>(), parts[2].parse::<usize>()) {
                    Some(CountryBreakdown {
                        country: parts[0].to_string(),
                        percentage,
                        netblock_count: count,
                    })
                } else {
                    None
                }
            } else {
                None
            }
        })
        .collect()
}

/// Format country breakdown for cache storage
fn format_country_breakdown_for_cache(breakdown: &[CountryBreakdown]) -> String {
    if breakdown.is_empty() {
        "N/A".to_string()
    } else {
        breakdown
            .iter()
            .map(|cb| format!("{}:{:.1}:{}", cb.country, cb.percentage, cb.netblock_count))
            .collect::<Vec<_>>()
            .join(";")
    }
}

/// Save IPInfo ASN data to cache
///
/// # Arguments
/// * `cache_path` - Path to the cache file
/// * `asn` - The ASN number
/// * `name` - ASN name
/// * `country` - ASN country
/// * `domain` - ASN domain
/// * `country_breakdown` - Country breakdown data
fn save_to_ipinfo_asn_cache(
    cache_path: &str, 
    asn: u32, 
    name: &Option<String>, 
    country: &Option<String>, 
    domain: &Option<String>,
    country_breakdown: &[CountryBreakdown]
) {
    let name_str = name.as_deref().unwrap_or("N/A");
    let country_str = country.as_deref().unwrap_or("N/A");
    let domain_str = domain.as_deref().unwrap_or("N/A");
    let breakdown_str = format_country_breakdown_for_cache(country_breakdown);
    
    let cache_line = format!("{}\t{}\t{}\t{}\t{}", asn, name_str, country_str, domain_str, breakdown_str);
    
    match OpenOptions::new().create(true).append(true).open(cache_path) {
        Ok(mut file) => {
            let mut writer = BufWriter::new(&mut file);
            if let Err(e) = writeln!(writer, "{}", cache_line) {
                warn!("Failed to write to IPInfo ASN cache: {}", e);
            }
        }
        Err(e) => {
            warn!("Failed to open IPInfo ASN cache file for writing: {}", e);
        }
    }
}

/// Looks up ASN information using the IPInfo API with caching
///
/// # Arguments
/// * `asn` - The ASN number to look up
/// * `client` - HTTP client
/// * `token` - IPInfo API token
/// * `cache` - Cache of previously looked up ASNs
/// * `cache_path` - Path to the cache file for saving new results
///
/// # Returns
/// Result containing IPInfo data or error
async fn lookup_ipinfo_asn_with_cache(
    asn: u32,
    client: &Client,
    token: &str,
    cache: &HashMap<u32, (Option<String>, Option<String>, Option<String>, Vec<CountryBreakdown>)>,
    cache_path: &str,
) -> Result<(Option<String>, Option<String>, Option<String>, Vec<CountryBreakdown>), Box<dyn std::error::Error + Send + Sync>> {
    // Check cache first
    if let Some((name, country, domain, breakdown)) = cache.get(&asn) {
        return Ok((name.clone(), country.clone(), domain.clone(), breakdown.clone()));
    }
    
    // Not in cache, make API call
    let url = format!("https://ipinfo.io/AS{}/json?token={}", asn, token);
    
    let resp = client.get(&url).send().await?;
    
    //println!("DEBUG: ASN {} - Status: {}", asn, resp.status());
    
    if resp.status() == reqwest::StatusCode::TOO_MANY_REQUESTS {
        println!("DEBUG: Rate limited for ASN {}", asn);
        return Ok((Some("Rate Limited".to_string()), None, None, vec![]));
    }
    
    if resp.status() == reqwest::StatusCode::UNAUTHORIZED {
        println!("DEBUG: Unauthorized - check your IPinfo token for ASN {}", asn);
        return Ok((Some("Unauthorized".to_string()), None, None, vec![]));
    }
    
    if resp.status() == reqwest::StatusCode::NOT_FOUND {
        println!("DEBUG: ASN {} not found", asn);
        let result = (None, None, None, vec![]);
        // Save to cache
        save_to_ipinfo_asn_cache(cache_path, asn, &result.0, &result.1, &result.2, &result.3);
        return Ok(result);
    }
    
    if !resp.status().is_success() {
        println!("DEBUG: HTTP error {} for ASN {}", resp.status(), asn);
        let result = (None, None, None, vec![]);
        save_to_ipinfo_asn_cache(cache_path, asn, &result.0, &result.1, &result.2, &result.3);
        return Ok(result);
    }
    
    let response_text = resp.text().await?;
   // println!("DEBUG: Response for ASN {}: {}", asn, response_text);
    
    let response: IPInfoAsnResponse = serde_json::from_str(&response_text)?;
    let country_breakdown = calculate_country_breakdown(&response.prefixes);
    let result = (response.name, response.country, response.domain, country_breakdown);
    
    // Save to cache
    save_to_ipinfo_asn_cache(cache_path, asn, &result.0, &result.1, &result.2, &result.3);
    
    Ok(result)
}

/// Looks up ASN information from IPInfo API
///
/// # Arguments
/// * `asn` - The ASN number to look up
/// * `client` - HTTP client
/// * `config` - API configuration
/// * `ipinfo_cache` - Cache of IPInfo ASN data
/// * `cache_path` - Path to the IPInfo cache file
///
/// # Returns
/// AsnInfo struct with data from IPInfo API
async fn lookup_asn_info(
    asn: u32,
    client: &Client,
    config: &ApiConfig,
    ipinfo_cache: &HashMap<u32, (Option<String>, Option<String>, Option<String>, Vec<CountryBreakdown>)>,
    cache_path: &str,
) -> AsnInfo {
    // Lookup IPInfo data
    let (name, country, domain, country_breakdown) = match lookup_ipinfo_asn_with_cache(asn, client, &config.ipinfo_token, ipinfo_cache, cache_path).await {
        Ok(data) => data,
        Err(e) => {
            warn!("IPInfo lookup failed for ASN {}: {}", asn, e);
            (None, None, None, vec![])
        }
    };

    AsnInfo {
        asn,
        name,
        country,
        domain,
        country_breakdown,
    }
}

/// Process ASN lookups with concurrency control
async fn process_asn_lookups(asns: Vec<u32>, config: &ApiConfig) {
    const MAX_CONCURRENT: usize = 10;
    const CACHE_PATH: &str = "ipinfo_asn_cache.tsv";
    
    // Load IPInfo ASN cache
    let ipinfo_cache = load_ipinfo_asn_cache(CACHE_PATH);
    println!("Loaded {} cached IPInfo ASN entries", ipinfo_cache.len());
    
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(30))
        .build()
        .unwrap();
    
    let pb = ProgressBar::new(asns.len() as u64);
    pb.set_style(
        ProgressStyle::with_template("[{bar:40.cyan/blue}] {pos}/{len} ASNs processed")
            .unwrap()
    );
    
    let mut futures: FuturesUnordered<_> = FuturesUnordered::new();
    let mut results = Vec::new();
    
    // Print table header
    println!("ASN\t|\tName\t|\tCountry\t|\tDomain\t|\tCountry Breakdown");
    println!("---\t|\t----\t|\t-------\t|\t------\t|\t-----------------");
    
    for asn in asns {
        let client_clone = client.clone();
        let config_clone = config.clone();
        let ipinfo_cache_clone = ipinfo_cache.clone();
        
        futures.push(Box::pin(async move {
            lookup_asn_info(asn, &client_clone, &config_clone, &ipinfo_cache_clone, CACHE_PATH).await
        }));
        
        // Process results in batches to control concurrency
        if futures.len() >= MAX_CONCURRENT {
            while let Some(result) = futures.next().await {
                pb.inc(1);
                print_asn_result(&result);
                results.push(result);
            }
        }
        
        // Small delay to be respectful to APIs
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    }
    
    // Process remaining futures
    while let Some(result) = futures.next().await {
        pb.inc(1);
        print_asn_result(&result);
        results.push(result);
    }
    
    // Completely clear and erase the progress bar
    pb.finish_and_clear();
    // Clear the entire line and move cursor to beginning
    print!("\r\x1b[2K");
    std::io::stdout().flush().unwrap();
    
    // Print summary
    println!("\nSummary:");
    println!("Total ASNs processed: {}", results.len());
    let ipinfo_found = results.iter().filter(|r| r.name.is_some()).count();
    println!("IPInfo results found: {}", ipinfo_found);
}

/// Print a single ASN result in table format
fn print_asn_result(info: &AsnInfo) {
    let name = info.name.as_deref().unwrap_or("N/A");
    let country = info.country.as_deref().unwrap_or("N/A");
    let domain = info.domain.as_deref().unwrap_or("N/A");
    
    // Format country breakdown
    let country_breakdown_str = if info.country_breakdown.is_empty() {
        "N/A".to_string()
    } else {
        info.country_breakdown
            .iter()
            .map(|cb| format!("{}:{:.1}%", cb.country, cb.percentage))
            .collect::<Vec<_>>()
            .join(", ")
    };
    
    println!(
        "{}\t|\t{}\t|\t{}\t|\t{}\t|\t{}",
        info.asn,
        name,
        country,
        domain,
        country_breakdown_str
    );
}

/// Main entry point for the ASN lookup application.
#[tokio::main]
async fn main() {
    dotenvy::from_filename(".env").ok();
    env_logger::init();
    
    // Load API credentials from environment
    let ipinfo_token = match env::var("IPINFO_TOKEN") {
        Ok(token) => token,
        Err(_) => {
            error!("IPINFO_TOKEN environment variable not found");
            exit(1);
        }
    };
    
    let config = ApiConfig {
        ipinfo_token,
    };
    
    // Parse ASN list file
    let asns = parse_asn_file("data/asnlist.txt");
    println!("Found {} unique ASNs", asns.len());
    
    if asns.is_empty() {
        error!("No valid ASN numbers found in data/asnlist.txt");
        exit(1);
    }
    
    // Process ASN lookups
    process_asn_lookups(asns, &config).await;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_asn_file() {
        // Create a test ASN file
        use std::fs::File;
        use std::io::Write;
        
        let test_content = "174\n278\n# This is a comment\n1221\n\n1267\ninvalid\n";
        let path = "test_asnlist.txt";
        
        let mut file = File::create(path).unwrap();
        file.write_all(test_content.as_bytes()).unwrap();
        
        let asns = parse_asn_file(path);
        std::fs::remove_file(path).unwrap();
        
        assert_eq!(asns.len(), 4);
        assert!(asns.contains(&174));
        assert!(asns.contains(&278));
        assert!(asns.contains(&1221));
        assert!(asns.contains(&1267));
    }
}