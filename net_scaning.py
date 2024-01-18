import nmap

target_ip = '192.168.10.1'

scanner = nmap.PortScanner()

# Perform a vulnerability scan on the target system
scanner.scan(target_ip, arguments='-sV --script vulners')

# Iterate over the hosts found in the scan
for host in scanner.all_hosts():
    print(f"Host: {host}")

    # Iterate over the scanned ports for each host
    for port in scanner[host].all_tcp():
        port_info = scanner[host]['tcp'][port]
        if port_info['state'] == 'open':
            print(f"Open TCP port: {port}")
        # Check if the port has any vulnerabilities detected
        if 'script' in port_info and 'vulners' in port_info['script']:
            vulnerabilities = port_info['script']['vulners']
            print("Vulnerabilities found:")
            print(f"  - {vulnerabilities}")