import subprocess
import json
import mysql.connector
from datetime import datetime
import xml.etree.ElementTree as ET
import os

# -----------------------------
# Database connection
# -----------------------------
try:
    db = mysql.connector.connect(
        host="192.168.10.3",
        user="scanner",
        password="scanner",
        database="netdb"
    )
    cursor = db.cursor()

except Exception as DBCNX:
    print(f"Cannot connect to database server error:\n{DBCNX}")
    exit()

# -----------------------------
# Create scan entry
# -----------------------------
cursor.execute("INSERT INTO scans () VALUES ()")
scan_id = cursor.lastrowid
db.commit()

print(f"Created scan #{scan_id}")

# -----------------------------
# Network detection
# -----------------------------
target = subprocess.run(
    "ip route | awk '/kernel/ {print $1}' | head -n 1",
    shell=True,
    capture_output=True,
    text=True
).stdout.strip()

print(f"Scanning network {target}")

# -----------------------------
# Run Nmap (XML output)
# -----------------------------
xml_file = f"/tmp/scan_{scan_id}.xml"

args = ["-sS", "-sV", "-Pn", "-O", "-oX", xml_file, "10.0.3.0/24"]

try:
    subprocess.run(["sudo", "/usr/local/bin/nmap-helper.sh"] + args, check=True)
except Exception as excpt:
    print(f"Scan failed. Error = {excpt}")
    exit()

print("Scan completed, parsing results...")

# -----------------------------
# Parse XML
# -----------------------------
tree = ET.parse(xml_file)
root = tree.getroot()

results = []
numberOfHosts = 0

# -----------------------------
# Host loop
# -----------------------------
for host in root.findall("host"):
    numberOfHosts += 1

    status = host.find("status").attrib["state"]

    ip = "unknown"
    hostname = "unknown"
    mac = "unknown"
    os_name = "unknown"

    # IP
    for addr in host.findall("address"):
        if addr.attrib["addrtype"] == "ipv4":
            ip = addr.attrib["addr"]
        elif addr.attrib["addrtype"] == "mac":
            mac = addr.attrib["addr"]

    # Hostname
    hostnames = host.find("hostnames")
    if hostnames is not None and len(hostnames):
        hostname = hostnames[0].attrib.get("name", "unknown") or "unknown"

    # OS detection
    os_elem = host.find("os")
    if os_elem is not None:
        osmatch = os_elem.find("osmatch")
        if osmatch is not None:
            os_name = osmatch.attrib.get("name", "unknown")

    print(f"""
-------------------- Machine {numberOfHosts} --------------------
Hostname : {hostname}
IP       : {ip}
MAC      : {mac}
OS       : {os_name}
Status   : {status}
""")

    host_data = {
        "ip": ip,
        "hostname": hostname,
        "mac": mac,
        "os": os_name,
        "nbPorts": 0,
        "ports": []
    }

    # -----------------------------
    # Ports
    # -----------------------------
    ports = host.find("ports")
    nb_ports = 0

    if ports is not None:
        print("----- Scanning Ports -----")

        for port in ports.findall("port"):
            nb_ports += 1

            port_id = port.attrib["portid"]
            service = port.find("service")

            service_name = service.attrib.get("name", "unknown") if service is not None else "unknown"
            product = service.attrib.get("product", "unknown") if service is not None else "unknown"
            version = service.attrib.get("version", "unknown") if service is not None else "unknown"

            host_data["ports"].append({
                "port": port_id,
                "service": service_name,
                "product": product,
                "version": version
            })

            print(f"""
Port    : {port_id}
Service : {service_name}
Product : {product}
Version : {version}
""")

    host_data["nbPorts"] = nb_ports

    # -----------------------------
    # Save host to DB
    # -----------------------------
    cursor.execute("""
        INSERT INTO hosts
        (scan_id, ip, hostname, os, nb_ports)
        VALUES (%s, %s, %s, %s, %s)
    """, (scan_id, ip, hostname, os_name, nb_ports))

    host_id = cursor.lastrowid

    # -----------------------------
    # Save ports to DB
    # -----------------------------
    for p in host_data["ports"]:
        cursor.execute("""
            INSERT INTO ports
            (host_id, port, service, product, version)
            VALUES (%s, %s, %s, %s, %s)
        """, (
            host_id,
            p["port"],
            p["service"],
            p["product"],
            p["version"]
        ))

    db.commit()

    results.append(host_data)

# -----------------------------
# Save JSON file
# -----------------------------
current_datetime = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")

os.makedirs("/mnt/scans_backup", exist_ok=True)

filename = f"./scans_backup/scan_{current_datetime}.json"

with open(filename, "w") as json_file:
    json.dump(results, json_file, indent=4)
    
subprocess.run([
    "sudo",
    "-u",
    "scanner",
    "cp",
    filename,
    "/mnt/scans_backup/"
    ], check=True)
print(f"Results saved to {filename}")

# -----------------------------
# Cleanup
# -----------------------------
cursor.close()
db.close()

print(f"Scan #{scan_id} saved successfully.")
