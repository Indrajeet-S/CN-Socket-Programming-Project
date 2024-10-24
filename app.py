#!/usr/bin/env python 
# coding: utf-8

from flask import Flask, render_template, request # Web application
import socket # DNS lookup
import time # For pinging       
import requests # For geolocation
from scapy.all import ARP, Ether, srp, sr1, IP, ICMP # For network scanning

# Initialize Flask app
app = Flask(__name__)

# Function to perform a network scan with a limit of 10 devices
def network_scanner(network):
    arp = ARP(pdst=network)
    ether = Ether(dst="ff:ff:ff:ff:ff:ff")
    packet = ether / arp
    result = srp(packet, timeout=3, verbose=0)[0]

    devices = []
    for sent, received in result[:10]:  # Limit to first 10 results
        devices.append({'ip': received.psrc, 'mac': received.hwsrc})
    
    return devices

# Function to ping a given IP address or domain
def ping_utility(target):
    start_time = time.time()  # Record the start time
    packet = IP(dst=target)/ICMP()
    response = sr1(packet, timeout=2, verbose=0)
    end_time = time.time()  # Record the end time
    if response is None:
        return f"{target} is unreachable."
    else:
        round_trip_time = (end_time - start_time) * 1000  # Convert to milliseconds
        return f"{target} is reachable. Round-trip time: {round_trip_time:.2f} ms"

# Function to perform DNS lookup
def dns_lookup(domain):
    try:
        ip = socket.gethostbyname(domain)
        return f"The IP address for {domain} is {ip}."
    except socket.error:
        return f"Failed to resolve domain: {domain}"

# Function to get geolocation of an IP address
def get_ip_geolocation(ip):
    try:
        response = requests.get(f"https://ipinfo.io/{ip}/json")
        data = response.json()
        return {
            'city': data.get('city', 'N/A'),
            'region': data.get('region', 'N/A'),
            'country': data.get('country', 'N/A'),
            'coordinates': data.get('loc', 'N/A')
        }
    except requests.RequestException:
        return None

# Flask routes
@app.route('/')
def index():
    return render_template('index.html')

@app.route('/scan', methods=['POST'])
def scan_network():
    network = request.form['network']
    devices = network_scanner(network)
    return render_template('results.html', devices=devices, scan=True)

@app.route('/ping', methods=['POST'])
def ping_host():
    target = request.form['target']
    result = ping_utility(target)
    return render_template('results.html', result=result, ping=True)

@app.route('/dns', methods=['POST'])
def dns_lookup_tool():
    domain = request.form['domain']
    result = dns_lookup(domain)
    
    # Perform the IP geolocation lookup using the resolved IP address
    resolved_ip = socket.gethostbyname(domain)
    geo_data = get_ip_geolocation(resolved_ip)  # Fetch geolocation for the IP
    
    return render_template('results.html', result=result, geo_data=geo_data, dns=True)


# Run the app
if __name__ == "__main__":
    app.run(debug=True)
