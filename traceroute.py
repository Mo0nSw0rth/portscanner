import threading
import time
import socket

from scapy.layers.inet import IP, ICMP
from scapy.sendrecv import sr1


def resolve_hostname(ip, timeout=0.5):
    def resolve():
        try:
            hostname, _, _ = socket.gethostbyaddr(ip)
            resolved_hostnames[ip] = hostname
        except socket.herror:
            resolved_hostnames[ip] = ip

    resolved_hostnames = {}
    thread = threading.Thread(target=resolve)
    thread.start()
    thread.join(timeout)

    return resolved_hostnames.get(ip, ip)

def trace(hops):
    ip = input("enter ip: ")
    for ttl in range(1, hops + 1):
        packet = IP(dst=ip, ttl=ttl) / ICMP()

        start_time = time.time()
        reply = sr1(packet, verbose=False, timeout=1)
        end_time = time.time()

        if reply is None:
            print(f"{ttl}: *")
        elif reply.type == 11:
            host = resolve_hostname(reply.src, timeout=0.5)
            print(f"{ttl}: {host} - {(end_time - start_time) * 1000:.2f} ms")
        elif reply.type == 0:
            host = resolve_hostname(reply.src, timeout=0.5)
            print(f"{ttl}: {host} - {(end_time - start_time) * 1000:.2f} ms")
            break
        else:
            host = resolve_hostname(reply.src, timeout=0.5)
            print(f"{ttl}: {host} - {(end_time - start_time) * 1000:.2f} ms")
