import argparse
import json
import logging
import socket
import threading
from datetime import datetime
from queue import Empty, Queue


logging.basicConfig(
    filename="port_scan.log",
    level=logging.INFO,
    format="%(asctime)s - %(message)s",
)


def resolve_host(host: str) -> str:
    """Resolve host to IPv4 address before scanning."""
    try:
        return socket.gethostbyname(host)
    except socket.gaierror as exc:
        raise ValueError(f"Hostname '{host}' could not be resolved") from exc


def check_port(host: str, port: int, timeout: float) -> str:
    """Return OPEN, CLOSED, TIMEOUT, or ERROR for the given port."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(timeout)
            result = sock.connect_ex((host, port))
            if result == 0:
                return "OPEN"
            return "CLOSED"
    except socket.timeout:
        return "TIMEOUT"
    except Exception:
        return "ERROR"


def worker(host: str, timeout: float, port_queue: Queue, results: dict, lock: threading.Lock) -> None:
    while True:
        try:
            port = port_queue.get_nowait()
        except Empty:
            break

        status = check_port(host, port, timeout)
        print(f"[{status}] {host}:{port}")
        logging.info("%s: %s:%s", status, host, port)

        with lock:
            results[status].append(port)

        port_queue.task_done()


def scan_host(host: str, start_port: int, end_port: int, timeout: float, max_threads: int) -> dict:
    print(f"\n[*] Scanning host: {host}")
    print(f"[*] Port range: {start_port}-{end_port}")
    print(f"[*] Started at: {datetime.now()}\n")
    logging.info("START scan host=%s range=%s-%s", host, start_port, end_port)

    port_queue = Queue()
    for port in range(start_port, end_port + 1):
        port_queue.put(port)

    results = {"OPEN": [], "CLOSED": [], "TIMEOUT": [], "ERROR": []}
    lock = threading.Lock()
    threads = []

    thread_count = min(max_threads, end_port - start_port + 1)
    for _ in range(thread_count):
        thread = threading.Thread(
            target=worker,
            args=(host, timeout, port_queue, results, lock),
            daemon=True,
        )
        thread.start()
        threads.append(thread)

    for thread in threads:
        thread.join()

    print(f"\n[*] Scan completed at: {datetime.now()}")
    print(f"[*] OPEN ports: {sorted(results['OPEN']) if results['OPEN'] else 'None'}")
    print(f"[*] CLOSED ports: {len(results['CLOSED'])}")
    print(f"[*] TIMEOUT ports: {len(results['TIMEOUT'])}")
    print(f"[*] ERROR ports: {len(results['ERROR'])}")
    logging.info(
        "END scan open=%s closed=%s timeout=%s error=%s",
        len(results["OPEN"]),
        len(results["CLOSED"]),
        len(results["TIMEOUT"]),
        len(results["ERROR"]),
    )
    return results


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Threaded TCP port scanner")
    parser.add_argument("host", help="Target host (IP or DNS name)")
    parser.add_argument("--timeout", type=float, default=1.0, help="Socket timeout in seconds (default: 1.0)")
    parser.add_argument("--threads", type=int, default=100, help="Maximum worker threads (default: 100)")
    parser.add_argument("--port", type=int, help="Scan a single port")
    parser.add_argument("--start", type=int, default=1, help="Start of port range (default: 1)")
    parser.add_argument("--end", type=int, default=1024, help="End of port range (default: 1024)")
    parser.add_argument("--output", type=str, help="Optional JSON report output path (example: results.json)")
    return parser.parse_args()


def validate_ports(start_port: int, end_port: int) -> None:
    if not (1 <= start_port <= 65535 and 1 <= end_port <= 65535):
        raise ValueError("Ports must be in range 1-65535")
    if start_port > end_port:
        raise ValueError("Start port cannot be greater than end port")


def save_results_json(
    output_path: str,
    target: str,
    host: str,
    start_port: int,
    end_port: int,
    timeout: float,
    threads: int,
    results: dict,
) -> None:
    payload = {
        "target": target,
        "resolved_host": host,
        "port_range": {"start": start_port, "end": end_port},
        "timeout_seconds": timeout,
        "threads": threads,
        "timestamp": datetime.now().isoformat(),
        "results": {
            "OPEN": sorted(results["OPEN"]),
            "CLOSED": sorted(results["CLOSED"]),
            "TIMEOUT": sorted(results["TIMEOUT"]),
            "ERROR": sorted(results["ERROR"]),
        },
        "summary": {
            "open_count": len(results["OPEN"]),
            "closed_count": len(results["CLOSED"]),
            "timeout_count": len(results["TIMEOUT"]),
            "error_count": len(results["ERROR"]),
        },
    }

    with open(output_path, "w", encoding="utf-8") as file:
        json.dump(payload, file, indent=2)

    print(f"[*] JSON report saved: {output_path}")
    logging.info("JSON report saved: %s", output_path)


def main() -> None:
    args = parse_args()

    try:
        resolved_host = resolve_host(args.host)

        if args.port is not None:
            start_port = end_port = args.port
        else:
            start_port, end_port = args.start, args.end

        validate_ports(start_port, end_port)
        results = scan_host(resolved_host, start_port, end_port, args.timeout, args.threads)
        if args.output:
            save_results_json(
                output_path=args.output,
                target=args.host,
                host=resolved_host,
                start_port=start_port,
                end_port=end_port,
                timeout=args.timeout,
                threads=args.threads,
                results=results,
            )
    except ValueError as err:
        print(f"[!] {err}")
    except KeyboardInterrupt:
        print("\n[!] Scan interrupted by user")
    except Exception as err:
        print(f"[!] Unexpected error: {err}")


if __name__ == "__main__":
    main()
