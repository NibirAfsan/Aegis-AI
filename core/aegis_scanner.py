import nmap

def scan_my_battlefield():
    # Note: host.docker.internal is the 'bridge' to your Docker victims
    target = "host.docker.internal"
    scanner = nmap.PortScanner()
    
    print(f"[*] Aegis-AI is searching for victims on {target}...")
    
    # We scan ports 8081, 8082, 8083 (our Docker targets)
    scanner.scan(target, '8081-8083', '-Pn')
    
    for host in scanner.all_hosts():
        print(f"\n[+] Target Found: {host}")
        for proto in scanner[host].all_protocols():
            ports = scanner[host][proto].keys()
            for port in ports:
                state = scanner[host][proto][port]['state']
                print(f"    - Port {port}: {state}")

if __name__ == "__main__":
    scan_my_battlefield()