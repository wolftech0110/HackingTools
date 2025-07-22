#!/usr/bin/env python3

import sys
import argparse
import subprocess
import threading
from queue import Queue
import socket

def get_hostname(ip):
    try:
        hostname = socket.gethostbyaddr(ip)[0]
        return hostname
    except (socket.herror, socket.gaierror):
        return None

def ping_host(host, alive_hosts, resolve_hostnames):
    try:
        result = subprocess.run(['ping', '-c', '1', '-W', '1', host], 
                              capture_output=True, text=True, timeout=3)
        if result.returncode == 0:
            host_info = {"ip": host}
            if resolve_hostnames:
                hostname = get_hostname(host)
                host_info["hostname"] = hostname
                if hostname:
                    print(f"{host} ({hostname}) is alive")
                else:
                    print(f"{host} is alive")
            else:
                print(f"{host} is alive")
            alive_hosts.append(host_info)
    except (subprocess.TimeoutExpired, subprocess.SubprocessError):
        pass

def worker(host_queue, alive_hosts, resolve_hostnames):
    while not host_queue.empty():
        host = host_queue.get()
        ping_host(host, alive_hosts, resolve_hostnames)
        host_queue.task_done()

def validate_network(network_base):
    try:
        parts = network_base.split('.')
        if len(parts) != 3:
            return False
        for part in parts:
            if not (0 <= int(part) <= 255):
                return False
        return True
    except ValueError:
        return False

parser = argparse.ArgumentParser(
    description="Multi-threaded ping sweep for network discovery",
    formatter_class=argparse.RawDescriptionHelpFormatter,
    epilog="""
Examples:
  python3 pingsweep.py 192.168.1
  python3 pingsweep.py 10.0.0 -t 50
  python3 pingsweep.py 172.16.1 --threads 25 --start 10 --end 100
  python3 pingsweep.py 192.168.1 --resolve
    """
)

parser.add_argument("network", help="Network base (e.g., 192.168.1)")
parser.add_argument("-t", "--threads", type=int, default=20,
                   help="Number of threads to use (default: 20)")
parser.add_argument("-s", "--start", type=int, default=1,
                   help="Starting host number (default: 1)")
parser.add_argument("-e", "--end", type=int, default=254,
                   help="Ending host number (default: 254)")
parser.add_argument("-r", "--resolve", action="store_true",
                   help="Resolve hostnames for alive hosts")

args = parser.parse_args()

if not validate_network(args.network):
    print("Error: Invalid network format. Use format like '192.168.1'")
    sys.exit(1)

if not (1 <= args.start <= 254) or not (1 <= args.end <= 254):
    print("Error: Host range must be between 1 and 254")
    sys.exit(1)

if args.start > args.end:
    print("Error: Start host must be less than or equal to end host")
    sys.exit(1)

print(f"Ping sweeping network: {args.network}.{args.start}-{args.end}")
print(f"Using {args.threads} threads")
print("-" * 50)

alive_hosts = []
host_queue = Queue()

for host_num in range(args.start, args.end + 1):
    host = f"{args.network}.{host_num}"
    host_queue.put(host)

try:
    threads = []
    
    for i in range(args.threads):
        t = threading.Thread(target=worker, args=(host_queue, alive_hosts, args.resolve))
        t.daemon = True
        t.start()
        threads.append(t)
    
    host_queue.join()
    
    print("-" * 50)
    print(f"Ping sweep completed. Found {len(alive_hosts)} alive hosts:")
    for host_info in sorted(alive_hosts, key=lambda x: int(x["ip"].split('.')[-1])):
        if args.resolve and host_info.get("hostname"):
            print(f"{host_info['ip']} ({host_info['hostname']})")
        else:
            print(host_info["ip"])
    
except KeyboardInterrupt:
    print('\nExiting...')
    sys.exit(1)
except Exception as e:
    print(f"Error: {e}")
    sys.exit(1)