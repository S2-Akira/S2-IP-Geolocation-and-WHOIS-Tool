# S2 - IP/Domain Information Tool

## Description

S2 is a Python-based command-line tool designed to help you gather information about IP addresses and domain names. It provides the following functionalities:

* **IP Address Geolocation:** Retrieves the geographical location of an IP address (city, country, region, latitude, and longitude) using the ipinfo.io API.
* **Domain History:** Provides a link to the domain's history on the Wayback Machine, allowing you to see how the website has changed over time.
* **WHOIS Lookup:** Retrieves WHOIS information for a domain.

## Features

* Interactive menu-driven interface.
* Uses the ipinfo.io API for IP geolocation (no local database required).
* Uses the Wayback Machine for domain history.
* Uses the `whois` library for WHOIS information.
* Clear, color-coded output in the terminal.
* Error handling for invalid input and API errors.

## Prerequisites

* Python 3.x
* `whois` library:  You can install it using pip:
    ```bash
    pip install whois
    ```

## Usage

1.  **Save the script:** Save the Python code (provided as `menu_ip_whois_tool_python`) to a file named `s2.py`.
2.  **Open a terminal:** Open your command-line interface (terminal) and navigate to the directory where you saved `s2.py`.
3.  **Run the script:** Execute the script by typing the following command and pressing Enter:
    ```bash
    python3 s2.py
    ```
4.  **Follow the menu:** The script will display a menu with the following options:
    * **1. Geolocate IP Address:** Enter an IP address to see its geographical location.
    * **2. Get Domain History:** Enter a domain name to get a link to its history on the Wayback Machine and WHOIS information.
    * **3. Exit:** Close the application.
5.  **Enter your choice:** Type the number of your choice (1, 2, or 3) and press Enter.  The script will then prompt you for the required input (IP address or domain name) and display the results.
6.  **Repeat or exit:** After the results are displayed, the menu will reappear, allowing you to perform another lookup or exit the script.

## Disclaimer

This tool is intended for informational and educational purposes only.  Please use it responsibly and ethically
