#!/usr/bin/env python3

import argparse
import socket
import sys
import re
from concurrent.futures import ThreadPoolExecutor, as_completed

# ===== ANSI Colors =====
GREEN = "\033[92m"
BLUE = "\033[94m"
YELLOW = "\033[93m"
RED = "\033[91m"
RESET = "\033[0m"

KNOWN_SERVICES = {
    21: "FTP",
    22: "SSH",
    23: "TELNET",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    110: "POP3",
    143: "IMAP",
    443: "HTTPS",
    3306: "MySQL",
    3389: "RDP",
    8080: "HTTP-ALT",
    8443: "HTTPS-ALT"
}

def extract_version(banner):
    patterns = [
        r"Apache\/([\d\.]+)",
        r"nginx\/([\d\.]+)",
        r"OpenSSH[_\-]?([\d\.p]+)"
    ]
    for pattern in patterns:
        match = re.search(pattern, banner)
        if match:
            return match.group(0)
    return None

def detect_service(ip, port, timeout=1):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        result = sock.connect_ex((ip, port))
        if result != 0:
            sock.close()
            return None

        service = KNOWN_SERVICES.get(port)
        banner = ""

        try:
            sock.sendall(b"HEAD / HTTP/1.0\r\n\r\n")
            banner = sock.recv(2048).decode(errors="ignore")
        except:
            try:
                banner = sock.recv(2048).decode(errors="ignore")
            except:
                pass

        sock.close()

        if "HTTP" in banner:
            service = "HTTP"
        elif "SSH" in banner:
            service = "SSH"
        elif "FTP" in banner:
            service = "FTP"

        if not service:
            return None

        version = extract_version(banner)
        return (port, service, version)

    except:
        return None

def scan_range(ip, start_port, end_port, threads=200):
    print(f"{YELLOW}[+] Target:{RESET} {ip}")
    print(f"{YELLOW}[+] Scanning:{RESET} {start_port} - {end_port}")
    print("-" * 50)

    results = []

    with ThreadPoolExecutor(max_workers=threads) as executor:
        futures = {
            executor.submit(detect_service, ip, port): port
            for port in range(start_port, end_port + 1)
        }

        for future in as_completed(futures):
            result = future.result()
            if result:
                port, service, version = result
                line = f"{GREEN}[OPEN]{RESET} {port}  --->  {BLUE}{service}{RESET}"
                if version:
                    line += f"  {YELLOW}({version}){RESET}"
                print(line)
                results.append(result)

    print("-" * 50)
    print(f"{GREEN}[+] Done. Found:{RESET} {len(results)} services")

def show_help():
    print("""
IPScan Pro - Advanced Port Scanner

Options:
  -p <port>     Check single port
  -a <number>   Scan ports 1 to number
  -au           Auto scan (1 - 10000)
  -u <ip/url>   Target IP

Examples:
  python3 ipscan.py -au -u 49.228.131.69
  python3 ipscan.py -p 22 -u 49.228.131.69
""")

def main():
    if len(sys.argv) == 1:
        show_help()
        sys.exit(0)

    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument("-p", type=int)
    parser.add_argument("-a", type=int)
    parser.add_argument("-au", action="store_true")
    parser.add_argument("-u", type=str)

    args = parser.parse_args()

    if not args.u:
        print(f"{RED}[-] Please specify target with -u{RESET}")
        sys.exit(1)

    target = args.u

    if args.p:
        scan_range(target, args.p, args.p)
    elif args.a:
        scan_range(target, 1, args.a)
    elif args.au:
        scan_range(target, 1, 10000)
    else:
        show_help()

if __name__ == "__main__":
    main()
