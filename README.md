# PortScanner (C++)

A simple and fast multithreaded TCP port scanner written in C++.  
Designed for penetration testing and network reconnaissance.

## Features

- Scans a range of ports on a target host.
- Detects open and closed TCP ports.
- Multithreaded for faster scanning.
- Optional banner grabbing (for open ports).
- Outputs results in simple text format.
- Works on IPv4 (IPv6 support can be added).

## Usage

```bash
./portscanner <target> <start_port> <end_port> [threads] [timeout_ms]

