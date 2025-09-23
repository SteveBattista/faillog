# faillog

A Rust tool to parse fail2ban log files, extract unique IP addresses, and look up their owner and country using the ipinfo.io API.

## Features
- Parses a log file (e.g., `data/ban_log.txt`) for banned IP addresses
- Counts occurrences of each unique IP
- Looks up country and organization for each IP using ipinfo.io
- Caches lookup results in `ipinfo_cache.tsv` to avoid redundant API calls
- Progress bar for lookup operations
- Handles API rate limits gracefully

## Usage

1. **Build the project:**
   ```sh
   cargo build --release
   ```

2. **Run the tool:**
   ```sh
   cargo run --release
   ```
   The tool will parse `data/ban_log.txt` and print results to the console.

3. **API Token:**
   The tool uses an ipinfo.io API token (already set in the code). If you need to change it, update the token in `main.rs`.

## Dependencies
- [tokio](https://crates.io/crates/tokio)
- [reqwest](https://crates.io/crates/reqwest)
- [serde](https://crates.io/crates/serde)
- [regex](https://crates.io/crates/regex)
- [indicatif](https://crates.io/crates/indicatif)
- [futures](https://crates.io/crates/futures)

## Notes
- The cache file `ipinfo_cache.tsv` is automatically updated with new lookups.
- The file `ipinfo_cache.tsv` is excluded from spell checking.
- The tool is designed for Linux and should work on any platform supported by Rust and the dependencies.

## License
MIT
