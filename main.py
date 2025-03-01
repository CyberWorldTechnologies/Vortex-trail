import requests
import socket
import argparse
import signal
import threading
import time
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
from tqdm import tqdm
from pyfiglet import figlet_format
from colorama import Fore, Style, init

# Initialize colorama
init()

# Global event to handle CTRL+C
stop_event = threading.Event()

def signal_handler(sig, frame):
    if not stop_event.is_set():
        print("\n[!] Scan interrupted by user. Stopping all threads...\n")
        stop_event.set()
        time.sleep(0.5)
        sys.exit(0)

signal.signal(signal.SIGINT, signal_handler)

def display_banner():
    print(Fore.RED + figlet_format("vorteX", font="slant") + Style.RESET_ALL)
    print(f"{Fore.MAGENTA}[✔] vorteX - The Ultimate Recon Tool{Style.RESET_ALL}\n")

# Service name map for known ports
SERVICE_NAMES = {
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    110: "POP3",
    443: "HTTPS",
    3306: "MySQL",
    3389: "RDP"
}

def get_service_name(port):
    return SERVICE_NAMES.get(port, "Unknown")

def grab_banner(sock):
    try:
        sock.send(b"HEAD / HTTP/1.1\r\n\r\n")
        return sock.recv(1024).decode().strip() or "No Banner"
    except:
        return "No Banner"

# Subdomain Enumeration
def check_subdomain(subdomain, progress_bar, output_file):
    if stop_event.is_set():
        return
    try:
        ip = socket.gethostbyname(subdomain)
        result = f"[✔] Found: {subdomain} -> {ip}"
        tqdm.write(f"{Fore.GREEN}{result}{Style.RESET_ALL}")
        if output_file:
            with open(output_file, "a") as f:
                f.write(result + "\n")
    except:
        pass
    finally:
        progress_bar.update(1)

def enumerate_subdomains(domain, wordlist, max_threads, output_file):
    display_banner()
    print(f"{Fore.CYAN}[*] Enumerating subdomains for {domain} using {wordlist} with {max_threads} threads...\n{Style.RESET_ALL}")

    with open(wordlist, "r") as file:
        subdomains = [line.strip() for line in file if line.strip() and not line.startswith("#")]

    with tqdm(total=len(subdomains), desc="Scanning", bar_format="{l_bar}{bar} {n_fmt}/{total_fmt} [{elapsed}]", ncols=80) as progress_bar:
        with ThreadPoolExecutor(max_workers=max_threads) as executor:
            futures = {executor.submit(check_subdomain, f"{sub}.{domain}", progress_bar, output_file) for sub in subdomains}
            for _ in as_completed(futures):
                if stop_event.is_set():
                    break

# Directory Fuzzing
def check_directory(url, progress_bar, output_file):
    if stop_event.is_set():
        return
    try:
        response = requests.get(url, timeout=5, allow_redirects=False)
        if response.status_code in [200, 301, 302, 403]:
            result = f"[✔] Found: {url} ({response.status_code})"
            tqdm.write(f"{Fore.GREEN}{result}{Style.RESET_ALL}")
            if output_file:
                with open(output_file, "a") as f:
                    f.write(result + "\n")
    except:
        pass
    finally:
        progress_bar.update(1)

def directory_fuzzing(base_url, wordlist, max_threads, output_file):
    display_banner()
    print(f"{Fore.CYAN}[*] Starting directory fuzzing on {base_url} using {wordlist} with {max_threads} threads...\n{Style.RESET_ALL}")

    with open(wordlist, "r") as file:
        directories = [line.strip() for line in file if line.strip() and not line.startswith("#")]

    with tqdm(total=len(directories), desc="Fuzzing", bar_format="{l_bar}{bar} {n_fmt}/{total_fmt} [{elapsed}]", ncols=80) as progress_bar:
        with ThreadPoolExecutor(max_workers=max_threads) as executor:
            futures = {executor.submit(check_directory, f"{base_url}/{dir}", progress_bar, output_file) for dir in directories}
            for _ in as_completed(futures):
                if stop_event.is_set():
                    break

# Advanced Port Scan with Service & Banner Detection
def scan_port(target, port, protocol, progress_bar, output_file):
    if stop_event.is_set():
        return
    try:
        sock_type = socket.SOCK_STREAM if protocol == "tcp" else socket.SOCK_DGRAM
        with socket.socket(socket.AF_INET, sock_type) as sock:
            sock.settimeout(1)
            result = sock.connect_ex((target, port))

            if result == 0:
                service_name = get_service_name(port)
                banner = grab_banner(sock) if protocol == "tcp" else "N/A"

                result_str = f"[✔] {protocol.upper()} Port {port} OPEN - Service: {service_name}, Banner: {banner}"
                tqdm.write(f"{Fore.GREEN}{result_str}{Style.RESET_ALL}")

                if output_file:
                    with open(output_file, "a") as f:
                        f.write(result_str + "\n")
    except:
        pass
    finally:
        progress_bar.update(1)

def advanced_port_scan(target, ports, max_threads, output_file, scan_udp):
    display_banner()
    print(f"{Fore.CYAN}[*] Starting advanced port scan on {target} with {max_threads} threads...\n{Style.RESET_ALL}")

    protocol = "udp" if scan_udp else "tcp"

    if ports:
        if '-' in ports:
            start, end = map(int, ports.split('-'))
            port_list = range(start, end + 1)
        else:
            port_list = [int(p.strip()) for p in ports.split(",")]
    else:
        port_list = range(1, 65536)

    with tqdm(total=len(port_list), desc=f"{protocol.upper()} Scan", bar_format="{l_bar}{bar} {n_fmt}/{total_fmt} [{elapsed}]", ncols=80) as progress_bar:
        with ThreadPoolExecutor(max_workers=max_threads) as executor:
            futures = {executor.submit(scan_port, target, port, protocol, progress_bar, output_file) for port in port_list}
            for _ in as_completed(futures):
                if stop_event.is_set():
                    break

# CLI Argument Parsing
if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="vorteX - Advanced Recon & Fuzzing Tool")
    parser.add_argument("-d", "--domain", help="Target domain for subdomain enumeration (e.g., example.com)")
    parser.add_argument("-w", "--wordlist", help="Path to wordlist (for subdomains or directories)")
    parser.add_argument("-T", "--threads", type=int, default=10, help="Number of threads (default: 10)")
    parser.add_argument("-o", "--output", help="Save results to a file")
    parser.add_argument("-url", "--target", help="Target URL for directory fuzzing")
    parser.add_argument("-fuzz", "--fuzzing", action="store_true", help="Enable directory fuzzing")
    parser.add_argument("-pscan", "--portscan", action="store_true", help="Enable port scanning")
    parser.add_argument("-pt", "--porttarget", help="Target IP or domain for port scanning")
    parser.add_argument("-p", "--ports", help="Comma-separated list of ports or range (e.g., 22,80,443 or 1-50)")
    parser.add_argument("--udp", action="store_true", help="Enable UDP scan (default is TCP)")

    args = parser.parse_args()

    if args.domain and args.wordlist:
        enumerate_subdomains(args.domain, args.wordlist, args.threads, args.output)
    elif args.target and args.fuzzing and args.wordlist:
        directory_fuzzing(args.target, args.wordlist, args.threads, args.output)
    elif args.portscan and args.porttarget:
        advanced_port_scan(args.porttarget, args.ports, args.threads, args.output, args.udp)
    else:
        print(f"{Fore.RED}[!] Invalid argument combination.{Style.RESET_ALL}")
