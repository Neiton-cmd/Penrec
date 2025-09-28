# PortScanner (C++)

A simple and fast multithreaded TCP port scanner written in C++.  
Designed for penetration testing and network reconnaissance.

## Features

- Scans a range of ports on a target host.
- Detects open TCP ports.
- Multithreaded for faster scanning.
- Optional banner grabbing (for open ports).
- Outputs results in simple text format.
- Works on IPv4 (IPv6 support can be added).

## Downloading
Find in Releases latest version with sourse code: binary_file penrec

Click in penrec and download raw file
Give permissions to execute for file
```bash
chmod +x penrec # give perm
./penrec --help # work-check
```

## Usage

```bash
./penrec -t <target> -s <start_port> -e <end_port> -n <num_of_threads> -o <timeout>
```

For help instruction use
```bash
penrec --help
```

## Output example

```bash
[+] port:      21   open
[+] port:      3000   open
```

## Docker Lab

```bash
cd /lab # directory with docker-compose conf file
docker compose up # run a safe machine with open ports(FTP - 21,
# JuiceShop - 3000, TCP port - 4444
docker compose down # close docker lab
```

Tested on Kali Linux

New updates will be soon...
