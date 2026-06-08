import nmap
import subprocess
import json
import mysql.connector
from datetime import datetime

# -----------------------------
# Database connection
# -----------------------------

db = mysql.connector.connect(
    host="192.168.10.3",
    user="scanner",
    password="scanner",
    database="netdb"
)

cursor = db.cursor()

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

scanner = nmap.PortScanner()

target = subprocess.run(
    "ip route | awk '/kernel/ {print $1}' | cut -d' ' -f1",
    shell=True,
    capture_output=True,
    text=True
).stdout.strip()

print(f"Scanning network {target}")

args = "-sS -sV -Pn -O"

try:
    scanner.scan(hosts=target, arguments=args)
except Exception as excpt:
    print(f"Scan failed. Error = {excpt}")
    exit()

print(f"Our attempt to scan {target} shows this result")

numberOfHosts = 0
results = []

# -----------------------------
# Host loop
# -----------------------------

for host in scanner.all_hosts():

    numberOfHosts += 1

    hostnames = scanner[host].get("hostnames", [])

    hostname = (
        hostnames[0].get("name")
        if hostnames and "name" in hostnames[0]
        else "unknown"
    )

    if hostname == "":
        hostname = "unknown"

    os_matches = scanner[host].get("osmatch", [])

    if os_matches:
        detected_os = os_matches[0]["name"]
    else:
        detected_os = "unknown"

    mac_address = scanner[host].get(
        "addresses", {}
    ).get(
        "mac",
        "unknown"
    )

    print(f"""
-------------------- Machine {numberOfHosts} --------------------
Hostname : {hostname}
IP       : {host}
MAC      : {mac_address}
OS       : {detected_os}
Status   : {scanner[host]['status']['state']}
""")

    host_data = {
        "ip": host,
        "hostname": hostname,
        "mac": mac_address,
        "os": detected_os,
        "nbPorts": 0,
        "ports": []
    }

    nb_ports = 0

    # -----------------------------
    # Ports
    # -----------------------------

    if "tcp" in scanner[host]:

        print("----- Scanning Ports -----")

        for port in scanner[host]["tcp"]:

            port_info = scanner[host]["tcp"][port]

            nb_ports += 1

            service = port_info.get("name", "unknown")
            product = port_info.get("product", "unknown")
            version = port_info.get("version", "unknown")

            host_data["ports"].append({
                "port": port,
                "service": service,
                "product": product,
                "version": version
            })

            print(f"""
Port    : {port}
Service : {service}
Product : {product}
Version : {version}
""")

    host_data["nbPorts"] = nb_ports

    # -----------------------------
    # Save host to DB
    # -----------------------------

    cursor.execute(
        """
        INSERT INTO hosts
        (scan_id, ip, hostname, os, nb_ports)
        VALUES (%s, %s, %s, %s, %s)
        """,
        (
            scan_id,
            host,
            hostname,
            detected_os,
            nb_ports
        )
    )

    host_id = cursor.lastrowid

    # -----------------------------
    # Save ports to DB
    # -----------------------------

    for p in host_data["ports"]:

        cursor.execute(
            """
            INSERT INTO ports
            (host_id, port, service, product, version)
            VALUES (%s, %s, %s, %s, %s)
            """,
            (
                host_id,
                p["port"],
                p["service"],
                p["product"],
                p["version"]
            )
        )

    db.commit()

    results.append(host_data)

# -----------------------------
# Save JSON file
# -----------------------------

current_datetime = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
filename = f"./scans_backup/scan_results_{current_datetime}.json"

with open(filename, "w") as json_file:
    json.dump(results, json_file, indent=4)

print("Results saved to scan_results.json")

print("Results saved to scan_results.json")

# -----------------------------
# Cleanup
# -----------------------------

cursor.close()
db.close()

print(f"Scan #{scan_id} saved successfully.")
