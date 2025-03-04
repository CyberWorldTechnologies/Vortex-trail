import requests
import socket
import argparse
import signal
import threading
import time
import sys
import nmap  # Python-nmap library
from concurrent.futures import ThreadPoolExecutor, as_completed
from tqdm import tqdm
from pyfiglet import figlet_format
from colorama import Fore, Style, init

# Initialize colorama for cross-platform color support
init()

# Global event to handle stopping threads immediately
stop_event = threading.Event()

def signal_handler(sig, frame):
    if not stop_event.is_set():
        print("\n[!] Scan interrupted by user. Stopping all threads immediately...\n")
        stop_event.set()
        time.sleep(0.5)
        sys.exit(0)

signal.signal(signal.SIGINT, signal_handler)

def display_banner():
    print(Fore.RED + figlet_format("vorteX", font="slant") + Style.RESET_ALL)
    print(f"{Fore.MAGENTA}[✔] vorteX - The Ultimate Recon Tool{Style.RESET_ALL}\n")

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

# Nmap-based Port Scanning with Service, OS Detection, and NSE
def run_nmap_scan(target, ports, output_file, scantype=None, nse_script=None):
    display_banner()

    scan_type_str = scantype if scantype else ""  # Handle None case
    arguments = scan_type_str.strip()

    if nse_script:
        arguments += f" --script={nse_script}"

    print(f"{Fore.CYAN}[*] Starting Nmap scan on {target} using '{arguments}'...\n{Style.RESET_ALL}")

    nm = nmap.PortScanner()

    ports_string = ports if ports else "1-65535"

    try:
        nm.scan(hosts=target, ports=ports_string, arguments=arguments)

        for host in nm.all_hosts():
            tqdm.write(f"{Fore.CYAN}[+] Host: {host} ({nm[host].hostname()}){Style.RESET_ALL}")
            tqdm.write(f"{Fore.CYAN}[+] State: {nm[host].state()}{Style.RESET_ALL}")

            if 'osmatch' in nm[host]:
                for osmatch in nm[host]['osmatch']:
                    tqdm.write(f"{Fore.YELLOW}[+] OS Match: {osmatch['name']} (Accuracy: {osmatch['accuracy']}%) {Style.RESET_ALL}")

            for proto in nm[host].all_protocols():
                tqdm.write(f"{Fore.CYAN}[+] Protocol: {proto}{Style.RESET_ALL}")
                for port in nm[host][proto]:
                    port_info = nm[host][proto][port]
                    result = f"[✔] Port {port}/{proto} - State: {port_info['state']} - Service: {port_info.get('name', 'unknown')}"
                    tqdm.write(f"{Fore.GREEN}{result}{Style.RESET_ALL}")
                    if output_file:
                        with open(output_file, "a") as f:
                            f.write(result + "\n")

    except nmap.PortScannerError as e:
        tqdm.write(f"{Fore.RED}[!] Nmap scan failed: {e}{Style.RESET_ALL}")
    except Exception as e:
        tqdm.write(f"{Fore.RED}[!] Unexpected error: {e}{Style.RESET_ALL}")


# CLI Argument Parsing
if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="vorteX - Advanced Recon & Fuzzing Tool")
    parser.add_argument("-d", "--domain", help="Target domain for subdomain enumeration (e.g., example.com)")
    parser.add_argument("-w", "--wordlist", help="Path to wordlist (for subdomains or directories)")
    parser.add_argument("-T", "--threads", type=int, default=10, help="Number of threads (default: 10)")
    parser.add_argument("-o", "--output", help="Save results to a file")

    # Directory Fuzzing
    parser.add_argument("-url", "--target", help="Target URL for directory fuzzing")
    parser.add_argument("-fuzz", "--fuzzing", action="store_true", help="Enable directory fuzzing")

    # Port Scanning
    parser.add_argument("-pscan", "--portscan", action="store_true", help="Enable port scanning using Nmap")
    parser.add_argument("-pt", "--porttarget", help="Target IP or domain for port scanning")
    parser.add_argument("-p", "--ports", help="Comma-separated list of ports or range (e.g., 22,80,443 or 1-50)")
    parser.add_argument("--scantype", help="Nmap scan types (e.g., '-sS -sV -O')")
    parser.add_argument("--nse", help="NSE script or category (e.g., 'http-title' or 'vuln')")

    args = parser.parse_args()

    if args.domain and args.wordlist:
        enumerate_subdomains(args.domain, args.wordlist, args.threads, args.output)

    elif args.target and args.fuzzing and args.wordlist:
        directory_fuzzing(args.target, args.wordlist, args.threads, args.output)

    elif args.portscan and args.porttarget:
        if args.nse:
            run_nmap_scan(args.porttarget, args.ports, args.output, args.scantype, args.nse)
        elif args.scantype:
            run_nmap_scan(args.porttarget, args.ports, args.output, args.scantype)
        else:
            print(f"{Fore.RED}[!] Missing scan type or NSE script for port scanning.{Style.RESET_ALL}")

    else:
        print(f"{Fore.RED}[!] Invalid argument combination. Use -h for help.{Style.RESET_ALL}")
