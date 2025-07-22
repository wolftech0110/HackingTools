# AOC Day 1 - IC2KP Protocol Traffic Analyzer

## Overview

The IC2KP Protocol Traffic Analyzer is a cybersecurity research tool designed to decrypt and analyze command & control (C2) communications captured in network traffic. This tool is specifically designed for educational purposes and authorized security testing.

## Background

This tool was originally developed for the HackTheBox challenge (https://app.hackthebox.com/challenges/295) and has been refactored into a modular, maintainable codebase for educational purposes. It demonstrates advanced concepts in:

- Network protocol analysis
- Cryptographic operations (AES-128-CBC)
- Packet capture processing
- Command & control communication patterns

## Features

### Core Functionality
- **Traffic Decryption**: Decrypts IC2KP protocol communications using AES-128-CBC
- **Handshake Analysis**: Processes two-step authentication handshake
- **Command Processing**: Analyzes various C2 commands including reverse shell sessions
- **Packet Filtering**: Automatically filters and processes relevant network packets

### Technical Capabilities
- **Multi-step Protocol Analysis**: Handles complex protocol handshakes
- **Dynamic Key Generation**: Generates AES keys from shared secrets and salt values
- **Nested Packet Processing**: Handles TCP packets containing multiple IC2KP messages
- **Authentication Verification**: Validates magic signatures during handshake

## Installation

### Prerequisites
```bash
# Required system tools
sudo apt-get install tshark wireshark-common

# Python dependencies
pip install pyshark pycryptodome termcolor colorama
```

### Dependencies
- **pyshark**: Network packet analysis
- **pycryptodome**: AES encryption/decryption
- **termcolor**: Colored terminal output
- **colorama**: Cross-platform color support
- **tshark**: Command-line packet analyzer (part of Wireshark)

## Usage

### Basic Usage
```bash
python3 AOC_Day1.py -c capture.pcap -s MySecret123
```

### Advanced Usage
```bash
# With custom signature and maximum verbosity
python3 AOC_Day1.py -c traffic.pcap -s S3cr3tP@ss --signature abc123def456 -vv

# Specify initial packet manually
python3 AOC_Day1.py -c data.pcap -s password -i 42 -v
```

### Command Line Options

| Option | Description | Default |
|--------|-------------|---------|
| `-c, --capture` | Path to Wireshark capture file | `capture.pcap` |
| `-s, --secret` | IC2KP session shared secret | `S3cr3tP@ss` |
| `-i, --initial` | Manual initial packet index | Auto-detect |
| `-v, --verbose` | Verbosity level (-v or -vv) | Silent |
| `--signature` | IC2KP magic signature (hex) | `5890ae86...` |

### Verbosity Levels
- **No flags**: Basic output with results only
- **-v**: Extra information and progress updates
- **-vv**: Detailed packet analysis and debugging information

## Protocol Analysis

### IC2KP Protocol Structure

The IC2KP protocol uses a multi-layered approach:

```
+--------------+---------+--------------------+----------+
| Content size | Content | AES block padding  | HMAC     |
+--------------+---------+--------------------+----------+
| 2 bytes      | ← bytes | up to 15 bytes     | 20 bytes |
+--------------+---------+--------------------+----------+
| AES 128 (CBC)                               | Raw      |
+--------------+---------+--------------------+----------+
```

### Handshake Process

1. **Initial Packet**: Server sends 40-byte packet containing two SHA1 salt values
2. **Key Generation**: AES keys derived from `SHA1(secret + salt)`
3. **Authentication**: Bilateral challenge using magic signature verification

### Supported Commands

| Command | Code | Status | Description |
|---------|------|--------|-------------|
| Upload File | `0x01` | Not Implemented | File transfer to target |
| Download File | `0x02` | Not Implemented | File retrieval from target |
| Reverse Shell | `0x03` | ✅ Implemented | Interactive shell session |

## Code Architecture

### Class Structure

- **`Context`**: Maintains decryption state and packet processing context
- **`PacketsFilter`**: Filters packets by connection participants
- **Exception Classes**: Custom exceptions for protocol errors

### Key Functions

- **`step_1_handshake()`**: Processes initial handshake and key generation
- **`step_2_authentication()`**: Handles authentication challenge
- **`decrypt()`**: Core decryption engine for IC2KP packets
- **`process_reverse_shell()`**: Analyzes shell command traffic

### Modular Design

The refactored code separates concerns into logical modules:
- Utility functions (encoding, hashing, printing)
- Protocol analysis (handshake, authentication)
- Command processing (reverse shell, file transfers)
- Packet handling (filtering, decryption)

## Troubleshooting

### Common Issues

**Authentication Failures**
- Verify the shared secret matches the IC2KP configuration
- Check that the magic signature corresponds to your IC2KP version
- Ensure the capture contains the complete handshake sequence

**Packet Processing Errors**
- Confirm the capture file contains TCP traffic with data
- Try manual initial packet specification with `-i` flag
- Use `-vv` flag to debug packet processing issues

**Decryption Problems**
- Verify the capture is from a single IC2KP session
- Check for packet loss or corruption in the capture
- Ensure tshark/Wireshark is properly installed

### Debug Tips

1. **Use Verbose Output**: Start with `-vv` to see detailed processing information
2. **Check Packet Indices**: Manually specify initial packet if auto-detection fails
3. **Verify Dependencies**: Ensure all Python packages and system tools are installed
4. **Test with Known Samples**: Use provided sample captures to verify functionality

## Educational Context

This tool demonstrates several important cybersecurity concepts:

### Network Security
- Command & control communication patterns
- Encrypted C2 channel analysis
- Network protocol reverse engineering

### Cryptography
- AES-128-CBC implementation details
- Key derivation from shared secrets
- HMAC verification for message integrity

### Malware Analysis
- C2 traffic decryption techniques
- Protocol analysis methodologies
- Behavioral analysis of remote access tools

## Security Considerations

### Authorized Use Only
This tool is designed for:
- Educational purposes and learning
- Authorized penetration testing
- Malware analysis in controlled environments
- Cybersecurity research with proper permissions

### Prohibited Uses
- Analyzing traffic without authorization
- Attacking systems you don't own
- Violating privacy or legal regulations
- Commercial exploitation without permission

## Contributing

When modifying or extending this tool:

1. Maintain the modular architecture
2. Add comprehensive error handling
3. Include verbose output for debugging
4. Update documentation for new features
5. Follow secure coding practices

## License and Attribution

Original implementation by alexander-utkov for HTB challenge.
Refactored and documented by KaliMaxx_ for educational purposes.

This tool is provided for educational and authorized security testing only.