import argparse  # For parsing command-line arguments
import socket  # For network operations such as port scanning and banner grabbing
import json  # For handling JSON data (input/output)
import requests  # For making HTTP requests (used for CVE lookup)
import logging  # For suppressing Scapy warnings
from scapy.all import ICMP, IP, sr1  # For sending/receiving ICMP packets (ping sweep)
from concurrent.futures import ThreadPoolExecutor, as_completed  # For multi-threaded operations
import time  # For handling time-related functions (e.g., sleep)
import paramiko  # For handling SSH connections (used for default credential checking)
from ftplib import FTP  # For handling FTP connections (used for default credential checking)
import warnings  # For suppressing cryptography warnings
from cryptography.utils import CryptographyDeprecationWarning  # Used to identify cryptography-related warnings
import re  # For handling regular expressions (e.g., cleaning banners)
import threading  # For running background tasks like continuous CVE checks

# Suppress unnecessary warnings and logs
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
warnings.filterwarnings("ignore", category=CryptographyDeprecationWarning)

def continuous_cve_update(service_name, update_interval=3600):
    """
    Continuously checks for new CVEs for a given service at regular intervals (default: 1 hour).
    This function runs in a background thread and performs the CVE lookup periodically.
    
    Parameters:
    - service_name: The name of the service (e.g., 'apache', 'nginx')
    - update_interval: The time interval (in seconds) between each CVE check (default is 3600 seconds)
    """
    while True:
        print(f"Checking for new CVEs for {service_name}...")
        cves = fetch_cves_with_retry(service_name)  # Fetch CVEs with retry mechanism
        if cves:
            print(f"Found {len(cves)} new CVEs for {service_name}!")
            for cve in cves:
                cve_id = cve['cve']['CVE_data_meta']['ID']
                description = cve['cve']['description']['description_data'][0]['value']
                print(f"New CVE-{cve_id}: {description}")
        else:
            print(f"No new CVEs found for {service_name}.")
        
        # Sleep for the update interval before checking again
        time.sleep(update_interval)

# Example usage:
# Start a background thread to continuously check for new CVEs for apache every hour (3600 seconds)
t = threading.Thread(target=continuous_cve_update, args=("apache", 3600), daemon=True)
t.start()

# Clean unnecessary HTML tags or long banners
def clean_banner(banner):
    """
    Cleans and truncates banners by removing HTML tags and truncating long text.
    
    Parameters:
    - banner: The raw banner text to be cleaned
    
    Returns:
    - Cleaned and truncated banner text (up to 100 characters)
    """
    banner = re.sub('<.*?>', '', banner)  # Remove HTML tags using regular expression
    if len(banner) > 100:
        return banner[:100] + '...'  # Truncate banners longer than 100 characters
    return banner.strip() if banner else "No banner"

# Network Discovery using ICMP Ping Sweep
def ping_sweep(network):
    """
    Performs an ICMP ping sweep on the specified network to identify active hosts.
    
    Parameters:
    - network: The network in CIDR format (e.g., '192.168.1.0/24')
    
    Returns:
    - List of active hosts with their IP addresses and OS guesses
    """
    print(f"\nPerforming ICMP ping sweep on network: {network}")
    ip_range = network.split('.')[:-1]  # Extract the first 3 octets of the network
    ip_base = '.'.join(ip_range)  # Form the base IP (e.g., '192.168.1')
    active_hosts = []  # List to store active hosts

    def ping(host_ip):
        """
        Sends an ICMP echo request to the specified host and returns the host's OS guess based on TTL.
        
        Parameters:
        - host_ip: The target host's IP address
        
        Returns:
        - Dictionary with the host's IP and guessed OS, or None if the host is not responsive
        """
        packet = IP(dst=host_ip) / ICMP()  # Create ICMP echo request packet
        response = sr1(packet, timeout=1, verbose=0)  # Send the packet and wait for the reply
        if response and response[ICMP].type == 0:  # Check if we received an ICMP echo reply
            ttl = response.ttl
            os_guess = ttl_os_fingerprint(ttl)  # Guess OS based on TTL
            return {'ip': host_ip, 'os': os_guess}
        return None

    # Perform concurrent ping using a thread pool
    with ThreadPoolExecutor(max_workers=50) as executor:
        futures = {executor.submit(ping, f"{ip_base}.{i}"): f"{ip_base}.{i}" for i in range(1, 255)}
        for future in as_completed(futures):
            result = future.result()
            if result:
                active_hosts.append(result)

    return active_hosts

# Port Scanning
def port_scan(host, ports):
    """
    Scans specified ports on the given host and returns a list of open ports.
    
    Parameters:
    - host: The target host's IP address
    - ports: List of ports to scan
    
    Returns:
    - List of open ports on the host
    """
    open_ports = []
    print(f"Scanning ports on host: {host}")

    def scan_port(port):
        """
        Attempts to connect to the specified port on the host to check if it's open.
        
        Parameters:
        - port: The port number to scan
        
        Returns:
        - Port number if open, otherwise None
        """
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(1)  # Set timeout for the connection
            result = sock.connect_ex((host, port))  # Attempt to connect
            return port if result == 0 else None

    # Perform concurrent port scanning using a thread pool
    with ThreadPoolExecutor(max_workers=50) as executor:
        futures = [executor.submit(scan_port, port) for port in ports]
        open_ports = [future.result() for future in as_completed(futures) if future.result() is not None]

    return open_ports

# Banner Grabbing
def banner_grab(host, port):
    """
    Grabs the banner from a service running on the specified host and port.
    
    Parameters:
    - host: The target host's IP address
    - port: The port number to connect to
    
    Returns:
    - The banner text (or a truncated version) if available, otherwise "No banner"
    """
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.connect((host, port))  # Connect to the host on the specified port
            sock.settimeout(2)  # Set a timeout for the connection
            sock.sendall(b"GET / HTTP/1.1\r\nHost: " + host.encode() + b"\r\n\r\n")  # Send an HTTP request
            response = sock.recv(4096).decode(errors="ignore")  # Receive and decode the response
            banner = response.split('\r\n')[0]  # Extract the banner (first line of response)
            return banner[:100] if banner else "No banner"  # Truncate banner to 100 characters if necessary
    except socket.error:
        return "No banner"

# Retry mechanism for CVE API
def fetch_cves_with_retry(service_name, retries=3, delay=5):
    """
    Fetches CVEs for a service from the NVD CVE API, with retry mechanism in case of failures.
    
    Parameters:
    - service_name: The name of the service (e.g., 'apache', 'nginx')
    - retries: Number of retries before giving up (default: 3)
    - delay: Delay between retries (default: 5 seconds)
    
    Returns:
    - List of CVE items if found, otherwise an empty list
    """
    cve_url = 'https://services.nvd.nist.gov/rest/json/cves/2.0'
    params = {'keyword': service_name, 'resultsPerPage': 5, 'startIndex': 0}  # API parameters
    attempt = 0
    while attempt < retries:
        try:
            response = requests.get(cve_url, params=params, timeout=10)  # Send HTTP GET request
            if response.status_code == 200:
                return response.json().get('result', {}).get('CVE_Items', [])  # Parse CVE items from response
            else:
                print(f"Error fetching CVEs: HTTP {response.status_code}")
        except requests.RequestException as e:
            print(f"Error fetching CVE vulnerabilities: {e}")
        attempt += 1
        print(f"Retrying in {delay} seconds...")
        time.sleep(delay)  # Wait before retrying
    return []

# CVE Lookup based on parsed banner with retry mechanism
def check_cve_vulnerabilities(banner):
    """
    Checks the banner for known services and looks up related CVEs.
    
    Parameters:
    - banner: The service banner from the scanned host
    
    Returns:
    - List of vulnerabilities (CVE ID and description) if found
    """
    vulnerabilities = []
    service_names = {
        "apache": "apache",
        "nginx": "nginx",
        "ssh": "openssh",
        "mysql": "mysql",
        "postgresql": "postgresql",
        "ftp": "ftp",
        "iis": "microsoft-iis",
        "samba": "samba",
        "tomcat": "tomcat",
        "openvpn": "openvpn"
    }

    # Detect services based on keywords in the banner
    detected_services = [service for name, service in service_names.items() if name in banner.lower()]
    for service in detected_services:
        cves = fetch_cves_with_retry(service)  # Fetch CVEs for the detected service
        for cve in cves:
            cve_id = cve['cve']['CVE_data_meta']['ID']
            description = cve['cve']['description']['description_data'][0]['value']
            vulnerabilities.append({'id': cve_id, 'description': description})
    return vulnerabilities

# OS Fingerprinting based on banners
def os_fingerprint(banner):
    """
    Determines the OS based on keywords in the banner.
    
    Parameters:
    - banner: The banner text from the scanned host
    
    Returns:
    - Guessed OS based on patterns in the banner
    """
    banner = banner.lower()  # Convert banner to lowercase for easier comparison
    os_patterns = {
        "linux": ["ubuntu", "debian", "centos", "linux", "kernel"],
        "windows": ["microsoft-iis", "windows nt", "win32"],
        "mac": ["mac os x", "darwin"],
        "bsd": ["freebsd", "openbsd", "netbsd"],
        "solaris": ["sunos", "solaris"],
        "android": ["android"]
    }
    
    # Check banner for patterns matching known operating systems
    for os, patterns in os_patterns.items():
        if any(pattern in banner for pattern in patterns):
            return os.capitalize()  # Return the detected OS
    
    return "Unknown OS"  # Return "Unknown" if no pattern matches

# Perform TTL-based OS fingerprinting during ICMP ping sweep
def ttl_os_fingerprint(ttl_value):
    """
    Guesses the OS based on the TTL value of the ICMP response.
    
    Parameters:
    - ttl_value: The TTL value from the ICMP response
    
    Returns:
    - Guessed OS based on TTL value
    """
    if ttl_value <= 64:
        return "Linux/Unix-based OS"  # TTL values <= 64 typically indicate Linux/Unix
    elif ttl_value <= 128:
        return "Windows-based OS"  # TTL values <= 128 typically indicate Windows
    elif ttl_value > 128:
        return "Cisco/Network device"  # TTL values > 128 often indicate network devices like Cisco routers
    else:
        return "Unknown OS"

# Export results to JSON
def export_results(data, filename):
    """
    Exports the scan results to a JSON file.
    
    Parameters:
    - data: The scan result data to be exported
    - filename: The name of the output JSON file
    """
    with open(filename, 'w') as f:
        json.dump(data, f, indent=4)  # Write the data to a file with indentation for readability
    print(f"Results saved to {filename}")

# Print scan results neatly
def print_results(results):
    """
    Prints the scan results in a structured format.
    
    Parameters:
    - results: List of scan results to be printed
    """
    print("\nScan Results:")
    for result in results:
        print(f"\nHost: {result['ip']}")
        print(f"    OS: {result['os']}")
        if result['services']:
            print(f"    Services:")
            for service in result['services']:
                print(f"        Port: {service['port']}")
                print(f"        Banner: {service['banner']}")
                if service['vulnerabilities']:
                    for vuln in service['vulnerabilities']:
                        print(f"        Vulnerability: CVE-{vuln['id']}")
                        print(f"            Description: {vuln['description']}")
                else:
                    print(f"        Vulnerabilities: None")
        else:
            print(f"    No open ports found.")

# Common default credentials for different services
DEFAULT_CREDENTIALS = {
    'ssh': [('root', 'toor'), ('admin', 'admin')],
    'ftp': [('anonymous', 'anonymous'), ('admin', 'password')],
}

# Check for default credentials on SSH service
def check_ssh_default_credentials(host, port=22):
    """
    Attempts to log in to the SSH service using common default credentials.
    
    Parameters:
    - host: The target host's IP address
    - port: The SSH port (default is 22)
    
    Returns:
    - Message indicating whether default credentials were found or not
    """
    for username, password in DEFAULT_CREDENTIALS['ssh']:
        try:
            client = paramiko.SSHClient()
            client.set_missing_host_key_policy(paramiko.AutoAddPolicy())  # Automatically accept host keys
            client.connect(host, port=port, username=username, password=password, timeout=3)  # Attempt SSH login
            client.close()  # Close the connection if successful
            return f"Default credentials for SSH found: {username}/{password}"
        except (paramiko.AuthenticationException, paramiko.SSHException, socket.error):
            continue
    return "No default SSH credentials found."

# Check for default credentials on FTP service
def check_ftp_default_credentials(host, port=21):
    """
    Attempts to log in to the FTP service using common default credentials.
    
    Parameters:
    - host: The target host's IP address
    - port: The FTP port (default is 21)
    
    Returns:
    - Message indicating whether default credentials were found or not
    """
    for username, password in DEFAULT_CREDENTIALS['ftp']:
        try:
            ftp = FTP()
            ftp.connect(host, port, timeout=3)  # Attempt FTP connection
            ftp.login(username, password)  # Attempt FTP login
            ftp.quit()  # Close the connection if successful
            return f"Default credentials for FTP found: {username}/{password}"
        except Exception:
            continue
    return "No default FTP credentials found."

# Parse Arguments
def parse_arguments():
    """
    Parses command-line arguments for network scanning, port scanning, and output options.
    
    Returns:
    - Parsed arguments
    """
    parser = argparse.ArgumentParser(description="Network scanner with service detection, CVE lookup, and default credential detection.")
    parser.add_argument("-n", "--network", help="Network to scan in CIDR format (e.g., 192.168.1.0/24)", required=True)
    parser.add_argument("-p", "--ports", help="Comma-separated list of ports to scan (e.g., 21,22,80,443)", default="21,22,80,443")
    parser.add_argument("-o", "--output", help="Output file to save scan results (JSON format)", default="scan_results.json")
    args = parser.parse_args()
    return args

# Main function
def main():
    """
    Main function to perform network scanning, service detection, CVE lookup, and default credential checks.
    The results are printed and optionally exported to a JSON file.
    """
    args = parse_arguments()  # Parse command-line arguments
    network = args.network
    ports = list(map(int, args.ports.split(',')))  # Convert ports to a list of integers
    output_file = args.output

    # Perform ping sweep to identify active hosts
    active_hosts = ping_sweep(network)

    # Port scan and service detection on active hosts
    results = []
    for host in active_hosts:
        open_ports = port_scan(host['ip'], ports)  # Scan open ports on each active host
        services = []
        for port in open_ports:
            banner = clean_banner(banner_grab(host['ip'], port))  # Grab and clean service banner
            vulnerabilities = check_cve_vulnerabilities(banner)  # Check for CVEs based on the banner
            service_info = {'port': port, 'banner': banner, 'vulnerabilities': vulnerabilities}
            if port == 22:
                service_info['default_creds'] = check_ssh_default_credentials(host['ip'])  # Check for default SSH credentials
            elif port == 21:
                service_info['default_creds'] = check_ftp_default_credentials(host['ip'])  # Check for default FTP credentials
            services.append(service_info)

        # Store the results for each host
        results.append({'ip': host['ip'], 'os': host['os'], 'services': services})

    # Print and export the results
    print_results(results)
    export_results(results, output_file)

if __name__ == "__main__":
    main()  # Run the main function when the script is executed
