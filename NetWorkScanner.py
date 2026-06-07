import nmap
import subprocess
import json
scanner= nmap.PortScanner()
target=subprocess.run("ip route | awk '/kernel/ {print $1}' | cut -d' ' -f1", shell=True,capture_output=True,text=True).stdout.strip()
print(f"scanning the network {target}")


args="-sS -sV -Pn -O"
 
try:
    scanner.scan(hosts=target, arguments=args)
except Exception as excpt:
    print(f"Scan failed. Error = {excpt}")
    exit()

print(f"Our attempt to scan {target} shows this result")

numberOfHosts = 0
results = []

for host in scanner.all_hosts():

    numberOfHosts += 1

    hostnames = scanner[host].get('hostnames', [])
    hostname = (
        hostnames[0].get('name')
        if hostnames and 'name' in hostnames[0]
        else "unknown"
    )

    if hostname == "":
        hostname = "unknown"

    os_matches = scanner[host].get("osmatch", [])

    if os_matches:
        detected_os = os_matches[0]["name"]
    else:
        detected_os = "unknown"

    mac_address = scanner[host].get("addresses", {}).get("mac", "unknown")

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

        print(f"Total open ports: {nb_ports}\n")

    host_data["nbPorts"] = nb_ports

    results.append(host_data)

with open("scan_results.json", "w") as json_file:
    json.dump(results, json_file, indent=4)

print("Results saved to scan_results.json")  
