import socket
import traceroute


def scan_ports(target, ports):
    open_ports = []
    for port in ports:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(0.5)
        try:
            sock.connect((target, port))
            open_ports.append((port, "open"))
            sock.close()
        except socket.timeout:
            pass
    return open_ports


def run():
    ip = input("enter ip: ")
    start, end = map(int, input("enter port range (split by comma): ").split(","))
    ports = range(start, end)
    print(f"Scanning {traceroute.resolve_hostname(ip)} ({ip})")
    open_ports = scan_ports(ip, ports)
    for port, state in open_ports:
        print(f"{port} | {state} | {socket.getservbyport(port)}")

