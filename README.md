# HackingTools

Educational cybersecurity tools developed for defensive security research and authorized penetration testing. These tools are built for learning purposes and should only be used in authorized environments.

## Installation

### Prerequisites
```bash
# System tools for network analysis
sudo apt-get install tshark wireshark-common

# Install Python dependencies
pip install -r requirements.txt
```

### Quick Start
```bash
# Clone and setup
git clone <repository-url>
cd HackingTools
pip install -r requirements.txt

# Make scripts executable
chmod +x pnptcourse/pingsweep.sh
chmod +x BashScripting/example.sh
```

## Tools Overview

### Network Discovery & Scanning

#### `pnptcourse/pingsweep.py`
Multi-threaded ping sweep tool for network discovery
- **Features**: Threading support, hostname resolution, customizable host ranges
- **Usage**: `python3 pingsweep.py 192.168.1 --resolve --threads 30`
- **Options**: `-r/--resolve` for hostnames, `-t/--threads` for concurrency, `-s/--start` and `-e/--end` for host ranges

#### `pnptcourse/pingsweep.sh`
Original bash ping sweep script
- **Purpose**: Basic network host discovery using ping
- **Usage**: `./pingsweep.sh 192.168.1`

#### `pnptcourse/port_scanner.py`
Single-threaded port scanner
- **Purpose**: Sequential port scanning for learning TCP concepts
- **Usage**: `python3 port_scanner.py target_host`

#### `pnptcourse/port_scanner_v2.py`
Multi-threaded port scanner with enhanced features
- **Features**: Configurable threading, comprehensive CLI options, progress tracking
- **Usage**: `python3 port_scanner_v2.py target_host --threads 50`
- **Range**: Scans ports 1-65535 with customizable thread count

### Exploitation & Security Testing

#### `Python4Hackers/sshbruteforcing.py`
SSH brute force testing tool
- **Purpose**: Educational demonstration of SSH authentication attacks
- **Features**: Uses rockyou.txt wordlist, paramiko SSH library
- **Note**: For authorized testing only

#### `Python4Hackers/sha256-crack.py`
SHA256 hash cracking utility
- **Purpose**: Dictionary attack against SHA256 hashes
- **Usage**: `python3 sha256-crack.py <hash_value>`
- **Features**: Progress tracking, rockyou.txt wordlist support

#### `pnptcourse/bof.py`
Buffer overflow testing script
- **Purpose**: Educational tool for learning buffer overflow concepts
- **Source**: TCM Security PNPT course material

### Web Application Testing

#### `Python4Hackers/webform.py`
Web form interaction and testing tool
- **Purpose**: Automated web form submission and analysis
- **Features**: HTTP requests handling, form data processing

#### `Python4Hackers/BeautifulSoupDemo.py`
Web scraping demonstration
- **Purpose**: Educational web scraping using BeautifulSoup
- **Features**: HTML parsing, data extraction techniques

#### `Python4Hackers/sqlinjection.py`
SQL injection testing utility
- **Purpose**: Educational demonstration of SQL injection techniques
- **Note**: For authorized testing and learning only

### Serialization & Payloads

#### `Pickle/picklepayload.py`
Python pickle serialization demonstration
- **Purpose**: Educational tool showing pickle security risks
- **Features**: Payload generation, base64 encoding, system command execution

### Scripting & Automation

#### `BashScripting/example.sh`
Basic bash scripting examples
- **Purpose**: Educational shell scripting demonstrations

#### `AdventOfCyber/AOC_Day1.py`
IC2KP Protocol Traffic Analyzer - Modular network protocol analysis tool
- **Purpose**: Decrypt and analyze IC2KP command & control communications
- **Features**: AES-128-CBC decryption, handshake analysis, reverse shell processing
- **Usage**: `python3 AOC_Day1.py -c capture.pcap -s S3cr3tP@ss -vv`
- **Documentation**: See `AdventOfCyber/AOC_Day1_Documentation.md` for detailed usage guide

## Featured Tools

### 🔍 **Network Discovery Suite**
- **Multi-threaded ping sweep** with hostname resolution
- **Advanced port scanner** with configurable threading
- **Network reconnaissance** tools for authorized testing

### 🔐 **Protocol Analysis**
- **IC2KP Traffic Analyzer** - Decrypt command & control communications
- **AES-128-CBC decryption** with automatic key derivation
- **Network protocol reverse engineering** capabilities

### 🎯 **Security Testing Tools**
- **Hash cracking utilities** (SHA256 dictionary attacks)
- **SSH brute force testing** with wordlist support
- **Web application testing** tools and demonstrations

## Development Features

### Code Quality
- **Comprehensive error handling** with detailed logging
- **Modular architecture** for maintainability
- **Threading support** for performance optimization
- **Extensive documentation** and usage examples

### CLI Features
- **Rich command-line interfaces** with argparse
- **Verbose output modes** for debugging
- **Flexible parameter configuration**
- **Built-in help systems**

## Security Notice

⚠️ **IMPORTANT**: These tools are for educational and authorized security testing purposes only. Always ensure you have proper permission before running any security tools against systems you do not own.

### Authorized Use Cases
- Educational learning environments
- Authorized penetration testing
- Cybersecurity research with proper permissions
- Malware analysis in controlled environments

### Prohibited Uses
- Unauthorized network scanning or testing
- Attacking systems without explicit permission
- Commercial use without proper licensing
- Any illegal or unethical activities

## Learning Resources

These tools were developed as part of various cybersecurity courses including:
- **TCM Security PNPT** (Practical Network Penetration Tester) course
- **Python for Hackers** educational content  
- **TryHackMe Advent of Cyber** security challenges
- **TryHackMe Advent of Cyber** Learnning challenges
- **HackTheBox** challenge implementations

## Contributing

When extending or modifying tools:
1. Maintain modular architecture and error handling
2. Add comprehensive CLI help and documentation
3. Include verbose output for debugging
4. Follow secure coding practices
5. Update README.md and requirements.txt as needed

## Support

For questions, issues, or contributions:
- Review tool-specific documentation files
- Check individual script help output (`--help`)
- Refer to course materials for context
- Ensure proper authorization before testing
