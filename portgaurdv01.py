import subprocess

def scan_ports():
    print("Scanning open ports...\n")
    result = subprocess.check_output("netstat -ano", shell=True, text=True)
    lines = result.splitlines()

    ports = set()

    for line in lines:
        if "LISTENING" in line:
            parts = line.split()
            local = parts[1]
            if ":" in local:
                port = local.split(":")[-1]
                if port.isdigit():
                    ports.add(port)

    ports = sorted(list(ports))
    print("Open Ports:")
    for i, p in enumerate(ports):
        print(f"{i+1}. Port {p}")

    return ports

def block_port(port):
    print(f"Blocking port {port}...")
    cmd = f'netsh advfirewall firewall add rule name="PortGuard Block {port}" dir=in action=block protocol=TCP localport={port}'
    subprocess.call(cmd, shell=True)
    print(f"Port {port} blocked.\n")

# MAIN
ports = scan_ports()

choice = input("\nEnter port numbers to block (comma separated): ")

selected = choice.split(",")

for c in selected:
    c = c.strip()
    if c.isdigit():
        block_port(c)
    else:
        print(f"Invalid: {c}")
