import whois
import socket
import re  # Import the regular expression module
import urllib.request  # Import for fetching website content
from bs4 import BeautifulSoup # Import for parsing
import json # Import for json

# ANSI escape codes for colored output
RED = '\033[91m'
GREEN = '\033[92m'
YELLOW = '\033[93m'
BLUE = '\033[94m'
MAGENTA = '\033[95m'
CYAN = '\033[96m'
RESET = '\033[0m'
BOLD = '\033[1m'

def colored_print(text, color=RESET, bold=False):
    """
    Prints text to the console with optional color and bold formatting.

    Args:
        text (str): The text to print.
        color (str, optional): The color of the text. Defaults to RESET.
    """
    style = ""
    if color:
        style += color
    if bold:
        style += BOLD
    print(f"{style}{text}{RESET}")

def s2_header(text):
    """Prints a header with the S2 tag."""
    colored_print(f"[{BOLD}S2{RESET}] {text}", color=GREEN, bold=True)

def is_valid_ip(ip_address):
    """
    Checks if a given string is a valid IPv4 address using regular expression.

    Args:
        ip_address (str): The string to check.

    Returns:
        bool: True if the string is a valid IPv4 address, False otherwise.
    """
    pattern = r"^(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])$"
    return re.match(pattern, ip_address) is not None

def get_whois_info(domain):
    """
    Retrieves WHOIS information for a given domain.

    Args:
        domain (str): The domain name to query.

    Returns:
        str: The WHOIS information, or None on error.
    """
    s2_header(f"WHOIS Information for {domain}")
    try:
        w = whois.whois(domain)
        colored_print(f"[+] WHOIS Info: {w}", color=CYAN)
        return str(w)
    except Exception as e:
        colored_print(f"[-] Error getting WHOIS info for {domain}: {e}", color=RED)
        return None

def geolocate_ip(ip_address):
    """
    Geolocates an IP address using the ipinfo.io API.

    Args:
        ip_address (str): The IP address to geolocate.

    Returns:
        dict: A dictionary containing geolocation information, or None on error.
    """
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
        return {
            'city': data.get('city'),
            'country': data.get('country'),
            'region': data.get('region'),
            'latitude': data.get('loc').split(',')[0] if data.get('loc') else None,
            'longitude': data.get('loc').split(',')[1] if data.get('loc') else None,
        }
    except urllib.error.URLError as e:
        colored_print(f"[-] Error fetching geolocation data: {e}", color=RED)
        return None
    except json.JSONDecodeError as e:
        colored_print(f"[-] Error decoding JSON response: {e}", color=RED)
        return None
    except Exception as e:
        colored_print(f"[-] Error during IP geolocation: {e}", color=RED)
        return None

def get_domain_history(domain):
    """
    Retrieves the domain history using the Wayback Machine.

    Args:
        domain (str): The domain name to query.

    Returns:
        str: The URL of the Wayback Machine archive, or None on error.
    """
    s2_header(f"Domain History for {domain}")
    wayback_url = f"https://web.archive.org/web/*/{domain}"
    colored_print(f"[+] Wayback Machine URL: {wayback_url}", color=CYAN)
    return wayback_url

def main():
    """
    Main function to provide a menu and handle user input.
    """
    s2_header("S2 - IP/Domain Information Tool")

    while True:
        colored_print("\n[+] Options:", color=MAGENTA, bold=True)
        colored_print("  1. Geolocate IP Address", color=CYAN)
        colored_print("  2. Get Domain History", color=CYAN)
        colored_print("  3. Exit", color=CYAN)

        choice = input(f"{GREEN}Enter your choice (1, 2, or 3): {RESET}")
        choice = choice.strip()

        if choice == '1':
            target = input(f"{GREEN}Enter IP address: {RESET}")
            target = target.strip()
            if not target:
                colored_print("[-] Error: Please enter a valid IP address.", color=RED)
                continue
            if not is_valid_ip(target):
                colored_print("[-] Error: Invalid IP address format.", color=RED)
                continue
            ip_address = target
            geolocation = geolocate_ip(ip_address)
            if geolocation:
                colored_print("[+] Geolocation Information:", color=MAGENTA, bold=True)
                colored_print(f"  [+] City: {geolocation['city']}", color=CYAN)
                colored_print(f"  [+] Country: {geolocation['country']}", color=CYAN)
                colored_print(f"  [+] Region: {geolocation['region']}", color=CYAN)
                colored_print(f"  [+] Latitude: {geolocation['latitude']}", color=CYAN)
                colored_print(f"  [+] Longitude: {geolocation['longitude']}", color=CYAN)
            else:
                colored_print("[-] Geolocation information not available.", color=MAGENTA)

        elif choice == '2':
            domain = input(f"{GREEN}Enter domain name: {RESET}")
            domain = domain.strip()
            if not domain:
                colored_print("[-] Error: Please enter a valid domain name.", color=RED)
                continue
            try:
                ip_address = socket.gethostbyname(domain)
                colored_print(f"[+] Resolved {domain} to {ip_address}", color=BLUE)
                geolocation = geolocate_ip(ip_address)  # Geolocate using the IP
                if geolocation:
                    colored_print("[+] Geolocation Information:", color=MAGENTA, bold=True)
                    colored_print(f"  [+] City: {geolocation['city']}", color=CYAN)
                    colored_print(f"  [+] Country: {geolocation['country']}", color=CYAN)
                    colored_print(f"  [+] Region: {geolocation['region']}", color=CYAN)
                    colored_print(f"  [+] Latitude: {geolocation['latitude']}", color=CYAN)
                    colored_print(f"  [+] Longitude: {geolocation['longitude']}", color=CYAN)
                else:
                    colored_print("[-] Geolocation information not available.", color=MAGENTA)

            except socket.gaierror:
                colored_print(f"[-] Error: Could not resolve domain {domain}.  Please enter a valid domain name.", color=RED)
                continue
            whois_info = get_whois_info(domain)
            if whois_info:
                colored_print("\n[+] WHOIS Information:", color=MAGENTA, bold=True)
                colored_print(whois_info, color=CYAN)
            else:
                colored_print("[-] WHOIS information not available.", color=MAGENTA)

            get_domain_history(domain)

        elif choice == '3':
            colored_print("[+] Exiting S2. Goodbye!", color=MAGENTA)
            break

        else:
            colored_print("[-] Error: Invalid choice. Please enter 1, 2, or 3.", color=RED)

if __name__ == "__main__":
    main()
