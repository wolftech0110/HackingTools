#!/usr/bin/env python3
"""
AOC Day 1 - IC2KP Protocol Traffic Analyzer

A modular tool for analyzing encrypted IC2KP protocol traffic from network captures.
Decrypts and analyzes command & control communications for cybersecurity research.

Originally based on the HTB challenge (https://app.hackthebox.com/challenges/295).
Refactored for better maintainability and educational purposes.

Author: KaliMaxx_
Dependencies: pyshark, Crypto, termcolor, colorama
"""

import argparse
import math
import subprocess
import hashlib
from dataclasses import dataclass
from Crypto.Cipher import AES
from termcolor import colored
from colorama import init
import pyshark


# Constants
MASTER = "master"
SLAVE = "slave"


class ProtocolError(Exception):
    """Raised when protocol parsing fails"""
    pass


class HandshakeError(Exception):
    """Raised during handshake authentication failures"""
    pass


class ImplementationError(Exception):
    """Raised for implementation-specific errors"""
    pass


# === UTILITY FUNCTIONS ===

def blob(string: str) -> bytes:
    """Converts HEX string to bytes"""
    array = list(string)
    pairs = zip(array[0::2], array[1::2])
    hexes = map(lambda p: str().join(p), pairs)
    return bytes.fromhex(" ".join(hexes))


def hexdigest(data) -> str:
    """Converts bytes/int to hex string"""
    if isinstance(data, int):
        return str(hex(data))[2:].rjust(2, "0")
    elif isinstance(data, bytes):
        return "".join(map(hexdigest, data))
    raise TypeError("Data must be bytes or int")


def sha1(data: bytes) -> bytes:
    """SHA1 hash function"""
    return hashlib.sha1(data).digest()


def truncate_to_128(sha1_hash: bytes):
    """Truncates SHA1 (160 bit) to AES 128 bit key"""
    return sha1_hash[:16]


# === PRINTING/LOGGING FUNCTIONS ===

try:
    init()
except ImportError:
    def colored(message: str, color: str = str()) -> str:
        return message


def pprint(label: str, color: str, *objects, **kwargs) -> None:
    """Pretty print with colored labels"""
    separator = kwargs.get("sep", " ")
    end = kwargs.get("end", "\n")
    
    head = colored(label, color)
    body = separator.join(map(str, objects))
    print(f"{head} {body}", end=end)


def info(*args, **kwargs):
    pprint("[info]", "light_blue", *args, **kwargs)


def warning(*args, **kwargs):
    pprint("[warning]", "light_yellow", *args, **kwargs)


def success(*args, **kwargs):
    pprint("[ ok ]", "light_green", *args, **kwargs)


def error(*args, **kwargs):
    pprint("[error]", "light_red", *args, **kwargs)


# === PACKET FILTERING ===

class PacketsFilter:
    """Filters packets by connection participants"""
    
    def __init__(self, packet):
        self.master_address = str(packet.ip.src)
        self.slave_address = str(packet.ip.dst)
        self.master_port = int(packet.tcp.srcport)
        self.slave_port = int(packet.tcp.dstport)
        
        self._comparable_master = {self.master_address, str(self.master_port)}
        self._comparable_slave = {self.slave_address, str(self.slave_port)}
    
    def __call__(self, packet, sender: str = None) -> bool:
        """Check if packet belongs to this connection"""
        if sender == MASTER:
            return {str(packet.ip.src), str(packet.tcp.srcport)} == self._comparable_master
        elif sender == SLAVE:
            return {str(packet.ip.src), str(packet.tcp.srcport)} == self._comparable_slave
        return True  # No sender filter
    
    def identify_sender(self, packet) -> str:
        """Identify packet sender"""
        for sender in (MASTER, SLAVE):
            if self(packet, sender):
                return sender
        raise ImplementationError("Cannot identify packet sender")


# === DECRYPTION CONTEXT ===

@dataclass
class Context:
    """Maintains decryption state and packet processing context"""
    aes_1: AES
    aes_2: AES
    capture: pyshark.FileCapture
    current_packet: int
    packets_filter: PacketsFilter
    verbose: int
    
    def __post_init__(self):
        self._decrypted = []
        self._last_sender = None
    
    def __del__(self):
        try:
            self.capture.close()
        except Exception:
            if self.verbose > 0:
                warning("Failed to gracefully close capture")
    
    @property
    def tcp_packet(self):
        try:
            return self.capture[self.current_packet]
        except KeyError:
            return None
    
    def advance(self, sender: str = None):
        """Move to next valid packet"""
        try:
            while True:
                self.current_packet += 1
                packet = self.capture[self.current_packet]
                
                if not hasattr(packet, "tcp") or not hasattr(packet.tcp, "len"):
                    continue
                    
                if int(packet.tcp.len) == 0:
                    continue
                    
                if not self.packets_filter(packet, sender):
                    continue
                    
                if self.verbose > 1:
                    info(f"Advanced to packet {self.current_packet}")
                return packet
        except KeyError:
            return None
    
    def get_data(self, sender: str = None):
        """Get decrypted data from next packet"""
        if len(self._decrypted) == 0:
            packet = self.advance(sender)
            if packet is None:
                return None
                
            liable = sender or self.packets_filter.identify_sender(packet)
            self._last_sender = sender
            
            decrypted = decrypt(self, get_packet_data(packet), sender=liable)
            if self._last_sender is None:
                self._decrypted.extend([(liable, dat) for dat in decrypted])
            else:
                self._decrypted.extend(list(decrypted))
        
        return self._decrypted.pop(0)


# === PACKET DATA EXTRACTION ===

def get_packet_data(packet) -> bytes:
    """Extract raw data from packet"""
    return blob(packet.DATA.data)


# === DECRYPTION FUNCTIONS ===

def get_aes_context(context, sender: str):
    """Get appropriate AES context for sender"""
    if sender == SLAVE:
        return context.aes_1
    elif sender == MASTER:
        return context.aes_2
    else:
        raise ValueError(f"Unknown sender '{sender}'")


def decrypt(context, data: bytes, sender: str):
    """Decrypt IC2KP packet data"""
    aes_ctx = get_aes_context(context, sender)
    
    # Decrypt header
    header = aes_ctx.decrypt(data[:16])
    content_size = int.from_bytes(header[:2], "big")
    
    if content_size < 0 or content_size > 4096:
        raise ProtocolError(f"Invalid packet size: {content_size}")
    
    # Extract content
    buffer = header[2:]  # Initial 14 bytes
    
    if content_size <= 14:
        packet_size = 16  # Header only
        buffer = buffer[:content_size]
    else:
        # Multi-block packet
        packet_size = math.ceil((2 + content_size) / 16) * 16
        remain_data = data[16:packet_size]
        buffer = buffer + aes_ctx.decrypt(remain_data)[:content_size - 14]
    
    hmac = data[packet_size:packet_size + 20]
    
    if len(hmac) != 20:
        raise ProtocolError(f"Invalid HMAC size: {len(hmac)}")
    
    if context.verbose > 1:
        info(f"Decrypted packet: size={content_size}, HMAC={hexdigest(hmac)}")
    
    yield buffer
    
    # Handle nested packets
    next_packet = data[packet_size + 20:]
    if len(next_packet) > 0:
        yield from decrypt(context, next_packet, sender)


# === PROTOCOL ANALYSIS ===

def find_initial_packet(capture):
    """Find the initial handshake packet (40 bytes)"""
    for index, packet in enumerate(capture):
        try:
            if (hasattr(packet, "tcp") and 
                hasattr(packet.tcp, "len") and 
                int(packet.tcp.len) == 40):
                return index
        except AttributeError:
            continue
    return -1


def step_1_handshake(capture, secret: str, **kwargs):
    """Step 1: Process initial handshake packet"""
    initial = kwargs.get("initial")
    verbose = kwargs.get("verbose", 0)
    
    if initial is None:
        initial = find_initial_packet(capture)
        if initial < 0:
            raise ValueError("Initial handshake packet not found")
        success(f"Found initial packet at index {initial}")
    
    packet = capture[initial]
    hashes = get_packet_data(packet)
    salt_1 = hashes[:20]
    salt_2 = hashes[20:]
    
    # Generate AES keys and IVs
    key_1 = truncate_to_128(sha1(secret.encode() + salt_2))
    key_2 = truncate_to_128(sha1(secret.encode() + salt_1))
    iv_1 = truncate_to_128(salt_2)
    iv_2 = truncate_to_128(salt_1)
    
    aes_1 = AES.new(key_1, AES.MODE_CBC, iv=iv_1)
    aes_2 = AES.new(key_2, AES.MODE_CBC, iv=iv_2)
    
    packet_filter = PacketsFilter(packet)
    
    if verbose > 0:
        info(f"Master: {packet_filter.master_address}:{packet_filter.master_port}")
        info(f"Slave: {packet_filter.slave_address}:{packet_filter.slave_port}")
        info(f"Encryption keys generated")
    
    return Context(
        aes_1=aes_1,
        aes_2=aes_2,
        capture=capture,
        current_packet=initial,
        packets_filter=packet_filter,
        verbose=verbose
    )


def step_2_authentication(context, signature: str, **kwargs):
    """Step 2: Process authentication challenge"""
    if isinstance(signature, str):
        signature = blob(signature)
    
    # Server challenge
    challenge_1 = context.get_data(MASTER)
    if challenge_1 != signature:
        raise HandshakeError("Server sent invalid magic signature")
    success("Server authenticated by client")
    
    # Client response
    challenge_2 = context.get_data(SLAVE)
    if challenge_1 != challenge_2:
        raise HandshakeError("Client sent invalid magic signature")
    success("Client authenticated by server")


# === COMMAND PROCESSING ===

def process_reverse_shell(context, verbose: int = 0, **kwargs):
    """Process reverse shell command traffic"""
    # Read initialization data
    term = context.get_data(sender=MASTER)
    argp = context.get_data(sender=MASTER)
    tbd = context.get_data(sender=MASTER)
    
    if verbose > 0:
        info(f"TERM environment: {term.decode()}")
        info(f"IOCTL argument: {hexdigest(argp)}")
    
    # Process shell I/O
    cout = ""
    cin = ""
    
    while True:
        try:
            pack = context.get_data()
            if pack is None:
                break
            sender, binary = pack
            text = binary.decode()
            
            if sender == SLAVE:
                cout += text
            else:
                cin += text
        except Exception:
            break
    
    # Display results
    if cin:
        print(colored("← " + cin.replace("\r", "\n← "), "dark_grey"))
    if cout:
        print("→ " + cout.replace("\n", "\n→ "))


# Command mapping
COMMANDS = {
    b"\x01": ("upload file", None),
    b"\x02": ("download file", None),
    b"\x03": ("reverse shell", process_reverse_shell),
}


def analyze_traffic(capture, secret: str, signature: str, **kwargs):
    """Main analysis function"""
    # Step 1: Process handshake
    context = step_1_handshake(capture, secret, **kwargs)
    
    try:
        # Step 2: Authentication
        step_2_authentication(context, signature, **kwargs)
    except Exception as e:
        warning(f"Authentication failed with secret '{secret}' and signature '{signature}'")
        raise
    
    # Process commands
    while True:
        command = context.get_data(sender=MASTER)
        if command is None:
            break
            
        if len(command) != 1 or command not in COMMANDS:
            raise ProtocolError(f"Unknown command: {hexdigest(command)}")
        
        display_name, handler = COMMANDS[command]
        info(f"Processing '{display_name}' command")
        
        if handler is None:
            raise NotImplementedError(f"Command '{display_name}' not implemented")
        
        handler(context, **kwargs)
    
    success("Analysis complete")


# === PCAP PREPROCESSING ===

def prefilter_capture(input_pcap, output_pcap):
    """Filter PCAP to include only TCP packets with data"""
    filter_expression = "tcp && tcp.len > 0"
    tshark_command = [
        "tshark", "-r", input_pcap, "-Y", filter_expression, "-w", output_pcap
    ]
    
    try:
        subprocess.run(tshark_command, check=True)
        info(f"Filtered capture saved to {output_pcap}")
    except subprocess.CalledProcessError as e:
        raise RuntimeError(f"Tshark filtering failed: {e}")


# === COMMAND LINE INTERFACE ===

def get_arguments():
    """Parse command line arguments"""
    help_text = """
Common Issues:
- Ensure the shared secret matches the IC2KP configuration
- Verify the magic signature is correct for your IC2KP version
- Check that the capture contains valid TCP traffic

Verbose Levels:
  -v:  Extra information and progress updates
  -vv: Detailed packet analysis and debugging info

Examples:
  python3 AOC_Day1.py -c capture.pcap -s MySecret123
  python3 AOC_Day1.py -c traffic.pcap -s S3cr3tP@ss -vv
  python3 AOC_Day1.py -c data.pcap -s password --signature abc123def456
    """
    
    parser = argparse.ArgumentParser(
        description=__doc__,
        epilog=help_text,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    
    parser.add_argument(
        "-c", "--capture",
        default="capture.pcap",
        help="Path to Wireshark capture file",
        metavar="FILE"
    )
    
    parser.add_argument(
        "-s", "--secret",
        default="S3cr3tP@ss",
        help="IC2KP session shared secret",
        metavar="SECRET"
    )
    
    parser.add_argument(
        "-i", "--initial",
        type=int,
        help="Specify initial packet index manually",
        metavar="INDEX"
    )
    
    parser.add_argument(
        "-v", "--verbose",
        action="count",
        default=0,
        help="Increase verbosity (use -vv for maximum detail)"
    )
    
    parser.add_argument(
        "--signature",
        default="5890ae86f1b91cf6298395711dde580d",
        help="IC2KP magic signature (hex)",
        metavar="HEX"
    )
    
    return parser.parse_args()


# === MAIN EXECUTION ===

def main():
    """Main execution function"""
    args = get_arguments()
    
    # Prefilter the capture
    filtered_capture = "filtered_capture.pcap"
    
    try:
        prefilter_capture(args.capture, filtered_capture)
        
        # Load filtered capture
        capture = pyshark.FileCapture(filtered_capture)
        
        # Analyze the traffic
        analyze_traffic(
            capture=capture,
            secret=args.secret,
            signature=args.signature,
            initial=args.initial,
            verbose=args.verbose
        )
        
    except Exception as e:
        error(str(e))
        if args.verbose > 0:
            raise
        return 1
    
    return 0


if __name__ == "__main__":
    exit(main())