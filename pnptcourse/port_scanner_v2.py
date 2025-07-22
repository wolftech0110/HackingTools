#!/usr/bin/env python3

import sys
import argparse
from datetime import datetime as dt
import socket
import threading
from queue import Queue

def scan_port(target, port, open_ports):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        socket.setdefaulttimeout(1)
        result = s.connect_ex((target, port))
        if result == 0:
            open_ports.append(port)
            print("port {} is open".format(port))
        s.close()
    except:
        pass

def worker(target, port_queue, open_ports):
    while not port_queue.empty():
        port = port_queue.get()
        scan_port(target, port, open_ports)
        port_queue.task_done()

parser = argparse.ArgumentParser(
    description="Multi-threaded port scanner for network reconnaissance",
    formatter_class=argparse.RawDescriptionHelpFormatter,
    epilog="""
Examples:
  python3 port_scanner_v2.py 192.168.1.1
  python3 port_scanner_v2.py example.com -t 50
  python3 port_scanner_v2.py 10.0.0.1 --threads 25
    """
)

parser.add_argument("target", help="Target IP address or hostname to scan")
parser.add_argument("-t", "--threads", type=int, default=15, 
                   help="Number of threads to use (default: 15)")

args = parser.parse_args()

try:
    target = socket.gethostbyname(args.target)
except socket.gaierror:
    print("Error: Hostname '{}' couldn't be resolved".format(args.target))
    sys.exit(1)

print("Scanning target: " + target)
print("Using {} threads".format(args.threads))
print("Time started: " + str(dt.now()))
print('-' * 50)

open_ports = []
port_queue = Queue()

for port in range(1, 65536):
    port_queue.put(port)

try:
    threads = []
    thread_count = args.threads
    
    for i in range(thread_count):
        t = threading.Thread(target=worker, args=(target, port_queue, open_ports))
        t.daemon = True
        t.start()
        threads.append(t)
    
    port_queue.join()
    
    print('-' * 50)
    print("Scan completed at: " + str(dt.now()))
    print("Open ports: {}".format(sorted(open_ports)))
    
except KeyboardInterrupt:
    print('\nExiting...')
    sys.exit()
except socket.gaierror:
    print("Hostname couldn't be resolved")
    sys.exit()
except socket.error:
    print("Couldn't connect to server")
    sys.exit(1)