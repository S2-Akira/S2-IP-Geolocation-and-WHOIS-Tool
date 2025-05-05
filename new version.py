import whois
import socket
import re
import urllib.request
from bs4 import BeautifulSoup
import json

# ANSI color codes
RED = '\033[91m'
GREEN = '\033[92m'
YELLOW = '\033[93m'
BLUE = '\033[94m'
MAGENTA = '\033[95m'
CYAN = '\033[96m'
RESET = '\033[0m'
BOLD = '\033[1m'

def colored_print(text, color=RESET, bold=False):
    style = ""
    if color:
        style += color
    if bold:
        style += BOLD
    print(f"{style}{text}{RESET}")

def s2_header(text):
    colored_print(f"[{BOLD}S2{RESET}] {text}", color=GREEN, bold=True)

def is_valid_ip(ip_address):
    pattern = r"^(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])$"
    return re.match(pattern, ip_address) is not None

def geolocate_ip(ip_address):
    s2_header(f"Geolocation for {ip_address}")
    try:
        url = f"https://ipinfo.io/{ip_address}/json"
        response = urllib.request.urlopen(url)
        data = json.load(response)

        colored_print(f"  [+] City: {data.get('city')}", color=YELLOW)
        colored_print(f"  [+] Country: {data.get('country')}", color=YELLOW)
        colored_print(f"  [+] Region: {data.get('region')}", color=YELLOW)
        colored_print(f"  [+] Latitude: {data.get('loc').split(',')[0] if data.get('loc') else None}", color=YELLOW)
        colored_print(f"  [+] Longitude: {data.get('loc').split(',')[1] if data.get('loc') else None}", color=YELLOW)
        return data
    except Exception as e:
        colored_print(f"[-] Geolocation error: {e}", color=RED)
        return None

def get_whois_info(domain):
    s2_header(f"WHOIS Information for {domain}")
    try:
        w = whois.whois(domain)
        whois_text = str(w)
        colored_print(f"[+] WHOIS Info: {whois_text}", color=CYAN)

        ips_found = re.findall(r'(?:\d{1,3}\.){3}\d{1,3}', whois_text)
        unique_ips = list(set(ips_found))
        if unique_ips:
            colored_print(f"[+] Found {len(unique_ips)} IP(s) in WHOIS. Attempting geolocation...", color=YELLOW)
            for ip in unique_ips:
                colored_print(f"\n[IP] {ip}", color=MAGENTA, bold=True)
                geolocate_ip(ip)
        else:
            colored_print("[*] No IP addresses found in WHOIS.", color=YELLOW)

        return whois_text
    except Exception as e:
        colored_print(f"[-] WHOIS error: {e}", color=RED)
        return None

def get_domain_history(domain):
    s2_header(f"Domain History for {domain}")
    url = f"https://web.archive.org/web/*/{domain}"
    colored_print(f"[+] Wayback Machine: {url}", color=CYAN)
    return url

def get_dns_history(domain):
    s2_header(f"DNS History for {domain}")
    dns_url = f"https://securitytrails.com/domain/{domain}/dns"
    colored_print(f"[+] View DNS history: {dns_url}", color=CYAN)

    try:
        ip_address = socket.gethostbyname(domain)
        colored_print(f"[+] Current A record IP: {ip_address}", color=BLUE)
        geolocate_ip(ip_address)
    except socket.gaierror:
        colored_print("[-] Could not resolve current A record.", color=RED)

    return dns_url

def banner():
    return f"""
{CYAN}{BOLD}
  _________________   .____    ________  _________     ________________________ __________ 
 /   _____/\\_____  \\  |    |   \\_____  \\ \\_   ___ \\   /  _  \\__    ___/\\_____  \\\\______   \\
 \\_____  \\  /  ____/  |    |    /   |   \\/    \\  \\/  /  /_\\  \\|    |    /   |   \\|       _/
 /        \\/       \\  |    |___/    |    \\     \\____/    |    \\    |   /    |    \\    |   \\
/_______  /\\_______ \\ |_______ \\_______  /\\______  /\\____|__  /____|   \\_______  /____|_  /
        \\/         \\/         \\/       \\/        \\/         \\/                 \\/       \\/
{RESET}
"""

def main():
    print(banner())
    s2_header("S2 - IP & Domain Info Toolkit")

    while True:
        colored_print("\n[+] Menu:", color=MAGENTA, bold=True)
        colored_print("  1. 🔍 Geolocate IP Address", color=CYAN)
        colored_print("  2. 🌐 Get Domain WHOIS + History", color=CYAN)
        colored_print("  3. 📜 View DNS History", color=CYAN)
        colored_print("  4. ❌ Exit", color=CYAN)

        choice = input(f"{GREEN}Enter your choice (1-4): {RESET}").strip()

        if choice == '1':
            target = input(f"{GREEN}Enter IP address: {RESET}").strip()
            if not is_valid_ip(target):
                colored_print("[-] Invalid IP format.", color=RED)
                continue
            geolocate_ip(target)

        elif choice == '2':
            domain = input(f"{GREEN}Enter domain name: {RESET}").strip()
            if not domain:
                colored_print("[-] Please enter a domain.", color=RED)
                continue

            try:
                ip_address = socket.gethostbyname(domain)
                colored_print(f"[+] Resolved {domain} to {ip_address}", color=BLUE)
                geolocate_ip(ip_address)
            except socket.gaierror:
                colored_print("[-] Could not resolve domain.", color=RED)

            get_whois_info(domain)
            get_domain_history(domain)
            get_dns_history(domain)

        elif choice == '3':
            domain = input(f"{GREEN}Enter domain name: {RESET}").strip()
            if not domain:
                colored_print("[-] Please enter a domain.", color=RED)
                continue
            get_dns_history(domain)

        elif choice == '4':
            colored_print("\n[+] Exiting S2 Toolkit. Goodbye!", color=MAGENTA, bold=True)
            break

        else:
            colored_print("[-] Invalid choice. Please select 1-4.", color=RED)

if __name__ == "__main__":
    main()
