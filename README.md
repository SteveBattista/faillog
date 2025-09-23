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

1. **Set up your API token:**

   - Copy `.env.example` to `.env` and add your [ipinfo.io](https://ipinfo.io/) API token:

     ```sh
     cp .env.example .env
     # Then edit .env and set your IPINFO_TOKEN
     ```

2. **Build the project:**

   ```bash
   cargo build --release
   ```

3. **Run the tool:**

   ```bash
   cargo run --release
   ```

   The tool will parse `data/ban_log.txt` and print results to the console.

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

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.
