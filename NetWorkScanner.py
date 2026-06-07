import nmap
import subprocess

scanner= nmap.PortScanner()
target=subprocess.run("ip route | awk '/kernel/ {print $1}' | cut -d' ' -f1", shell=True,capture_output=True,text=True).stdout.strip()
print(f"scanning the network {target}")

args="-sS -sV -Pn -O"
try:
    scanner.scan(hosts=target,arguments=args)
except Exception as excpt:
    print(f"scan failed error= {excpt}")
    
print(f"our attemt to scan {target} shows this result")
numberOfHosts=0
for host in scanner.all_hosts():
    numberOfHosts+=1
    hostnames = scanner[host].get('hostnames', [])
    hostname = (
        hostnames[0].get('name')
        if hostnames and 'name' in hostnames[0]
        else "Unknown")
    if(hostname==""):
        hostname="unknown"
    osM=scanner[host].get("osmatch",[])

    if osM :
        ROs=osM[0]['name']
    else:
        ROs="unknown"
    print(f" \n \n -------------------- machine number : {numberOfHosts} ---------------------- \n host_name:{hostname}  \n ip:{host} \n OperatingSys:{ROs}  \n status:{scanner[host]['status']['state']} \n  ")
    print("-----scanning ports-------")
    nb_ports=0
    if "tcp" in scanner[host]:
        for port in scanner[host]["tcp"]:
            portinfos=scanner[host]["tcp"][port]
            nb_ports+=1
            service=portinfos["name"]
            portnumber=port
            soft=portinfos.get("product","unknown")
            version=portinfos.get("version","unknown")
            print(f" port number: {portnumber} \n service:{service} \n product:{soft} \n version:{version} ")
    print(f"total ports number:{nb_ports} \n \n ")

    
