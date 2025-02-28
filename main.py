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

# Initialize colorama for cross-platform color support
init()

# Global event to handle stopping threads immediately
stop_event = threading.Event()

# Handle CTRL+C gracefully
def signal_handler(sig, frame):
    if not stop_event.is_set():  # Avoid multiple trigger messages
        print("\n[!] Scan interrupted by user. Stopping all threads immediately...\n")
        stop_event.set()  # Set stop flag for running threads
        time.sleep(0.5)  # Allow threads to exit gracefully
        sys.exit(0)  # Exit cleanly

# Attach signal handler
signal.signal(signal.SIGINT, signal_handler)

# Function to display ASCII banner
def display_banner():
    print(Fore.RED + figlet_format("vorteX", font="slant") + Style.RESET_ALL)
    print(f"{Fore.MAGENTA}[✔] vorteX - The Ultimate Recon Tool{Style.RESET_ALL}\n")

# Function to check if a subdomain is live
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
    except (socket.gaierror, OSError):
        pass  # Skip invalid subdomains
    finally:
        if not stop_event.is_set():
            progress_bar.update(1)

# Function to check if a directory exists
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
    except (requests.ConnectionError, requests.Timeout):
        pass  # Skip failed requests
    finally:
        if not stop_event.is_set():
            progress_bar.update(1)

# Subdomain Enumeration
def enumerate_subdomains(domain, wordlist, max_threads, output_file):
    display_banner()
    print(f"{Fore.CYAN}[*] Enumerating subdomains for {domain} using {wordlist} with {max_threads} threads...\n{Style.RESET_ALL}")

    try:
        with open(wordlist, "r") as file:
            subdomains = [line.strip() for line in file if line.strip() and not line.startswith("#")]

        with tqdm(total=len(subdomains), desc="Scanning", bar_format="{l_bar}{bar} {n_fmt}/{total_fmt} [{elapsed}]", ncols=80) as progress_bar:
            with ThreadPoolExecutor(max_workers=max_threads) as executor:
                futures = {executor.submit(check_subdomain, f"{sub}.{domain}", progress_bar, output_file) for sub in subdomains}
                for future in as_completed(futures):
                    if stop_event.is_set():
                        break

    except KeyboardInterrupt:
        print("\n[!] Scan interrupted by user. Cleaning up and exiting...\n")
        stop_event.set()
        sys.exit(0)

# Directory Fuzzing
def directory_fuzzing(base_url, wordlist, max_threads, output_file):
    display_banner()
    print(f"{Fore.CYAN}[*] Starting directory fuzzing on {base_url} using {wordlist} with {max_threads} threads...\n{Style.RESET_ALL}")

    try:
        with open(wordlist, "r") as file:
            directories = [line.strip() for line in file if line.strip() and not line.startswith("#")]

        with tqdm(total=len(directories), desc="Fuzzing", bar_format="{l_bar}{bar} {n_fmt}/{total_fmt} [{elapsed}]", ncols=80) as progress_bar:
            with ThreadPoolExecutor(max_workers=max_threads) as executor:
                futures = {executor.submit(check_directory, f"{base_url}/{dir}", progress_bar, output_file) for dir in directories}
                for future in as_completed(futures):
                    if stop_event.is_set():
                        break

    except KeyboardInterrupt:
        print("\n[!] Scan interrupted by user. Cleaning up and exiting...\n")
        stop_event.set()
        sys.exit(0)

# CLI Argument Parsing
if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="vorteX - Advanced Recon & Fuzzing Tool")
    parser.add_argument("-d", "--domain", help="Target domain for subdomain enumeration (e.g., example.com)")
    parser.add_argument("-w", "--wordlist", required=True, help="Path to wordlist (for subdomains or directories)")
    parser.add_argument("-T", "--threads", type=int, default=10, help="Number of threads (default: 10)")
    parser.add_argument("-o", "--output", help="Save results to a file")
    parser.add_argument("-url", "--target", help="Target URL for directory fuzzing")
    parser.add_argument("-fuzz", "--fuzzing", action="store_true", help="Enable directory fuzzing")

    args = parser.parse_args()

    if args.domain:
        enumerate_subdomains(args.domain, args.wordlist, args.threads, args.output)
    elif args.target and args.fuzzing:
        directory_fuzzing(args.target, args.wordlist, args.threads, args.output)
    else:
        print(f"{Fore.RED}[!] You must specify either -d (Subdomain Enum) or -url -fuzz (Directory Fuzzing){Style.RESET_ALL}")
