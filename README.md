# syntecxhub-internship

import socket
import sys
import threading
from datetime import datetime
import logging

logging.basicConfig(filename='port_scan.log', level=logging.INFO, format='%(asctime)s - %(message)s')

def scan_port(host, port, open_ports):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)
        result = sock.connect_ex((host, port))
        if result == 0:
            print(f"[+] Port {port} is OPEN")
            logging.info(f"OPEN: {host}:{port}")
            open_ports.append(port)
        else:
            print(f"[-] Port {port} is CLOSED or TIMEOUT")
        sock.close()
    except socket.gaierror:
        print(f"[!] Hostname {host} could not be resolved")
        sys.exit(1)
    except KeyboardInterrupt:
        print("\n[!] Scan interrupted by user")
        sys.exit(1)
    except Exception as e:
        print(f"[!] Error on port {port}: {e}")

def scan_host(host, start_port, end_port):
    print(f"\n[*] Scanning {host} from port {start_port} to {end_port}")
    print(f"[*] Started at {datetime.now()}\n")
    open_ports = []
    threads = []
    
    for port in range(start_port, end_port + 1):
        thread = threading.Thread(target=scan_port, args=(host, port, open_ports))
        threads.append(thread)
        thread.start()
    
    for thread in threads:
        thread.join()
    
    print(f"\n[*] Scan completed at {datetime.now()}")
    print(f"[*] Open ports found: {sorted(open_ports) if open_ports else 'None'}")
    return open_ports

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python port_scanner.py <host> [start_port] [end_port]")
        print("Example: python port_scanner.py scanme.nmap.org")
        print("Example: python port_scanner.py 192.168.1.1 20 100")
        sys.exit(1)
    
    host = sys.argv[1]
    start_port = int(sys.argv[2]) if len(sys.argv) > 2 else 1
    end_port = int(sys.argv[3]) if len(sys.argv) > 3 else 1024
    
    scan_host(host, start_port, end_port)
