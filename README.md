# faillog

## Example Log Files

Sample log lines are provided in [`samples/ban_log.txt`](samples/ban_log.txt) for testing and demonstration purposes. You can use this file to quickly try out faillog:

```sh
cp samples/ban_log.txt data/ban_log.txt
cargo run --release
```

This will parse the example log and print IP info to the console.

## Quick Start

```sh
git clone https://github.com/yourusername/faillog.git
cd faillog
cp .env.example .env
# Edit .env and set your IPINFO_TOKEN
cargo run --release
```

This will parse `data/ban_log.txt` and print IP info to the console. See below for more details.

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

### More Usage Examples

- **Parse a custom log file:**

   Edit `src/lib.rs` and change the path in `parse_log_file("data/ban_log.txt")` to your log file.

- **IPv6 support:**

   The tool automatically detects and formats IPv6 addresses. Example output:

   ```text
   IP: [2001:db8::1] | Count: 2 | Country: US | Org: ExampleOrg
   IP: 192.0.2.1 | Count: 5 | Country: US | Org: ExampleOrg
   ```

- **Clear the cache:**

   To force fresh lookups, delete the cache file:

   ```sh
   rm ipinfo_cache.tsv
   ```

## Troubleshooting

- **No output or missing results?**
  - Make sure your log file path is correct and contains valid IP addresses.
  - Check that your `IPINFO_TOKEN` is set in the `.env` file.

- **API errors or rate limits?**
  - If you see `exceeded` in the output, you have hit the ipinfo.io rate limit. Wait and try again later.
  - Consider upgrading your ipinfo.io plan for higher limits.

- **Cache not updating?**
  - Ensure the tool has write permissions to `ipinfo_cache.tsv`.
  - Delete the cache file to reset.

- **Build or dependency errors?**
  - Run `cargo clean` then `cargo build`.
  - Make sure you are using a recent stable version of Rust (`rustup update`).

- **Still stuck?**
  - Open an issue on GitHub with your error message and environment details.

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

## API Documentation

Full API docs are generated with:

```sh
cargo doc --open
```

Or view them online (if published): [faillog API Docs](https://docs.rs/faillog)
