import scapy.all as scapy
from concurrent.futures import ThreadPoolExecutor

def scan_port(target_ip, port):
   
    packet = scapy.IP(dst=target_ip)/scapy.TCP(dport=port, flags="S")
    response = scapy.sr1(packet, timeout=1, verbose=0)
    if response:
        if response.haslayer(scapy.TCP) and response.getlayer(scapy.TCP).flags == 0x12:
            return port, "Open"
        elif response.haslayer(scapy.ICMP) and response.getlayer(scapy.ICMP).type == 3 and response.getlayer(scapy.ICMP).code in [1, 2, 3, 9, 10, 13]:
            return port, "Filtered"
    return port, "Closed"

def stealthy_port_scan(target_ip):
    
    ports = range(1, 65536)
    with ThreadPoolExecutor(max_workers=100) as executor:
        results = list(executor.map(scan_port, [target_ip]*len(ports), ports))
    return dict(results)

if __name__ == "__main__":
    target_ip = "192.168.0.1"  # Replace with the target IP address
    results = stealthy_port_scan(target_ip)
    open_ports = {port: status for port, status in results.items() if status == "Open"}
    print("Open Ports:")
    for port, status in open_ports.items():
        print(f"Port {port}: {status}")