## Detailed Walkthrough

`port_scanner.py` is a command-line TCP scanner that combines:

- **host resolution**
- **threaded port probing**
- **result categorization**
- **console + file logging**
- **optional JSON reporting**

The file is organized cleanly into small functions, each with one responsibility.

---

## 1) Imports and Logging Setup

At the top, it imports standard libraries:

- `argparse`: parse CLI arguments
- `json`: write structured report
- `logging`: save scan activity to log file
- `socket`: actual network probing
- `threading`: concurrent workers
- `datetime`: timestamps
- `Queue`/`Empty`: thread-safe port task distribution

The `logging.basicConfig(...)` call sets:

- log file: `port_scan.log`
- level: `INFO`
- format: `timestamp - message`

So every scan event gets persisted, not just printed.

---

## 2) Host Resolution (`resolve_host`)

`resolve_host(host)` converts a host string (like `google.com`) into an IPv4 address using `socket.gethostbyname`.

- If successful: returns something like `"142.250.183.14"`
- If DNS resolution fails (`socket.gaierror`): raises a user-friendly `ValueError`

Why this is good:
- It fails early before launching threads.
- Keeps network scanning logic focused on already-resolved host addresses.

---

## 3) Single Port Check (`check_port`)

`check_port(host, port, timeout)` is the core probe operation.

Inside:
1. Creates a TCP socket (`AF_INET`, `SOCK_STREAM`)
2. Sets timeout (`sock.settimeout(timeout)`)
3. Calls `connect_ex((host, port))`

`connect_ex` behavior:
- returns `0` when TCP handshake succeeds -> port is **OPEN**
- nonzero return -> treated as **CLOSED**
- timeout exception -> **TIMEOUT**
- any other exception -> **ERROR**

Important nuance:
- This is a **TCP connect scan**, not a SYN/raw-packet scan.
- It checks if a full connect can be established, which is simple and portable.

---

## 4) Worker Thread Function (`worker`)

Each thread runs `worker(host, timeout, port_queue, results, lock)`.

Loop behavior:
- Try `port_queue.get_nowait()`
- If queue empty (`Empty`): break loop and thread exits
- Else:
  - scan port with `check_port`
  - print immediate status (`[OPEN] 1.2.3.4:22`)
  - write log entry
  - append port to `results[status]` inside a lock
  - mark task done (`port_queue.task_done()`)

Why lock is needed:
- Multiple threads may append to shared lists simultaneously.
- `lock` avoids race conditions/corrupt updates.

---

## 5) Scan Orchestration (`scan_host`)

This function coordinates the full scan:

1. Prints scan header (target, range, start time)
2. Logs “START” with host and range
3. Creates a `Queue` and enqueues every port in range
4. Initializes result buckets:
   - `"OPEN"`, `"CLOSED"`, `"TIMEOUT"`, `"ERROR"`
5. Chooses thread count:
   - `min(max_threads, total_ports)`  
   So it won’t launch more threads than needed.
6. Starts daemon threads running `worker(...)`
7. Joins all threads (wait until all complete)
8. Prints completion summary:
   - list of open ports (sorted)
   - counts for closed/timeout/error
9. Logs “END” summary counts
10. Returns `results`

Design strength:
- Efficient producer/consumer model via queue.
- Thread count capping prevents unnecessary thread overhead.

---

## 6) CLI Interface (`parse_args`)

The script supports:

- required positional:
  - `host`
- optional:
  - `--timeout` (float, default `1.0`)
  - `--threads` (int, default `100`)
  - `--port` (single port)
  - `--start` (default `1`)
  - `--end` (default `1024`)
  - `--output` (JSON filepath)

Behavior rule:
- If `--port` is provided, it overrides range and scans only that one port.
- Else it uses `--start` / `--end`.

---

## 7) Port Validation (`validate_ports`)

`validate_ports(start_port, end_port)` enforces:

- both ports in `1..65535`
- `start_port <= end_port`

On invalid values it raises `ValueError`, which `main()` catches and prints cleanly.

---

## 8) JSON Report Writer (`save_results_json`)

If user passes `--output`, this function writes a structured report containing:

- target input (`target`)
- resolved IP (`resolved_host`)
- range object
- timeout and thread settings
- timestamp
- full sorted result lists for each status
- summary counts

It writes with UTF-8 and pretty formatting (`indent=2`), then logs and prints save confirmation.

---

## 9) Program Entry + Error Handling (`main`)

`main()` workflow:

1. parse args
2. resolve host
3. decide scan mode (single port vs range)
4. validate ports
5. run scan
6. optionally write JSON

Exception handling:
- `ValueError`: user input/domain validation problems (friendly print)
- `KeyboardInterrupt`: graceful cancellation message
- generic `Exception`: fallback unexpected error message

Finally guarded with:

- `if __name__ == "__main__": main()`

so script runs only when executed directly.

---

## 10) Concurrency and Performance Notes

- It is **I/O-bound** (network waits), so threading helps significantly.
- Higher `--threads` can speed scans but also:
  - increase local resource use
  - trigger remote rate limits/firewalls
  - produce more timeouts under congestion
- Timeouts directly impact duration:
  - larger timeout = fewer false negatives, slower scan
  - smaller timeout = faster scan, more possible misses

Approx intuition:
- total time tends toward `(slowest outstanding ports / threads)` dynamics, not simple linear.

---

## 11) Practical Limitations / Behavior Characteristics

- IPv4 only (`gethostbyname`, `AF_INET`)
- TCP only (no UDP scanning)
- Does not attempt service/banner detection
- “CLOSED” here includes many non-open connect outcomes (not differentiated by exact errno)
- Prints every scanned port, which can be noisy on large ranges

---

## 12) Example End-to-End Usage

- Default scan:
  - `python port_scanner.py scanme.nmap.org`
- Single port:
  - `python port_scanner.py localhost --port 22`
- Tuned range + report:
  - `python port_scanner.py "Local Host" --start 20 --end 200 --threads 50 --timeout 0.5 --output results.json`

---

If you want, I can next give a **line-by-line explanation** of `scan_host` and `worker` together (that’s the most important part for interview/demo understanding).
