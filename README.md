My Project is based on Portscanner in cybersecurity.
  
`port_scanner.py` is a **multi-threaded TCP port scanner CLI tool** with optional JSON reporting and logging.

## What it does

- Takes a target host (DNS or IP), resolves it to IPv4.
- Scans either:
  - one port (`--port`), or
  - a range (`--start` to `--end`).
- Uses multiple threads (`--threads`) to speed up scanning.
- Classifies each port as `OPEN`, `CLOSED`, `TIMEOUT`, or `ERROR`.
- Prints live scan results, logs to `port_scan.log`, and can export a JSON summary (`--output`).

## Main flow

1. `main()` parses CLI args.
2. `resolve_host()` converts hostname to IPv4 using `socket.gethostbyname`.
3. Determines single-port vs range scan.
4. `validate_ports()` ensures range is valid (1–65535 and start <= end).
5. `scan_host()` performs threaded scan and aggregates results.
6. If `--output` is provided, `save_results_json()` writes a structured report.
7. Handles:
   - invalid input (`ValueError`)
   - Ctrl+C (`KeyboardInterrupt`)
   - unexpected exceptions

## Key functions explained

- `resolve_host(host)`  
  Resolves DNS/IP to an IPv4 string; raises a friendly `ValueError` if resolution fails.

- `check_port(host, port, timeout)`  
  Creates a TCP socket and calls `connect_ex((host, port))`:
  - `0` => `OPEN`
  - nonzero => `CLOSED`
  - socket timeout => `TIMEOUT`
  - any other exception => `ERROR`

- `worker(...)`  
  Repeatedly pulls ports from a `Queue`, scans them, prints/logs each result, and safely appends to shared `results` using a `threading.Lock`.

- `scan_host(...)`  
  - Builds a queue of ports.
  - Starts up to `min(max_threads, number_of_ports)` daemon worker threads.
  - Joins all threads (waits for completion).
  - Prints and logs final summary counts.
  - Returns the `results` dictionary.

- `save_results_json(...)`  
  Writes target info, scan settings, full categorized port lists (sorted), and count summary to JSON.

## CLI arguments

- positional: `host`
- optional:
  - `--timeout` (default `1.0`)
  - `--threads` (default `100`)
  - `--port` (single port)
  - `--start` (default `1`)
  - `--end` (default `1024`)
  - `--output` (JSON output file path)

## Example usage

- Scan default range:
  - `python port_scanner.py scanme.nmap.org`
- Scan one port:
  - `python port_scanner.py localhost --port 22`
- Scan custom range with tuning + JSON output:
  - `python port_scanner.py Local Host --start 20 --end 200 --threads 50 --timeout 0.5 --output results.json`

If you want, I can also walk through one sample run and show how each argument changes behavior.
