# DeadCIDR

A high-performance, adaptive network scanner designed for scanning large IP ranges with intelligent timeout handling, congestion detection, and rate limiting. The scanner automatically adjusts its behavior based on network conditions and scan scope to optimize performance while maintaining network stability.

## Description

This Python-based network scanner is built for large-scale network discovery operations. It combines ICMP ping, HTTP, and HTTPS port scanning to detect live hosts across extensive IP ranges. The scanner features adaptive rate control, network health monitoring, and timeout-aware thresholds that automatically adjust based on scan scope and network conditions.

## Features

- **Multi-Scale Scanning**: Automatically detects scan scope (Small/Medium/Large/Massive) and adjusts parameters accordingly
- **Adaptive Rate Control**: Dynamically adjusts scanning rate based on network congestion detection
- **Multiple Detection Methods**: 
  - ICMP ping (with raw socket support via Scapy)
  - HTTP port scanning (port 80)
  - HTTPS port scanning (port 443)
- **Intelligent Timeout Handling**: Adjusts thresholds and rates based on user-specified timeout values
- **Network Health Monitoring**: Real-time congestion detection with automatic rate adjustment
- **Batch Processing**: Efficient handling of massive IP ranges with batched execution
- **Comprehensive Reporting**: Detailed reports showing reachable/unreachable networks with statistics
- **Progress Monitoring**: Real-time progress updates with ETA calculations
- **Conservative Mode**: Lower-impact scanning for sensitive environments

## Requirements

### Python Version
- Python 3.7 or higher

# For enhanced performance (optional)
pip install psutil

# For raw socket support (requires root/admin privileges)
pip install scapy

# Usage
## Basic Usage
Scan single IP or CIDR range:

    python3 ping_scanner.py 192.168.1.0/24

## Scan multiple targets:

    python3 ping_scanner.py 192.168.1.0/24 10.0.0.0/16 172.16.0.0/12

## Scan from file:

    python3 ping_scanner.py -f targets.txt

## Advanced Usage

Custom timeout (supports decimals):
    
    python3 ping_scanner.py 192.168.1.0/24 -t 2.5

Custom scan rate:

    python3 ping_scanner.py 192.168.1.0/24 -r 5000

Conservative mode for sensitive networks:

    python3 ping_scanner.py 192.168.1.0/24 --conservative

Large-scale scan with custom parameters:

    python3 ping_scanner.py 10.0.0.0/8 -t 3 -r 1000 --conservative

With raw socket support (requires root):

    sudo python3 ping_scanner.py 192.168.1.0/24

# Command Line Options

python3 ping_scanner.py [targets] [options]

Positional Arguments:
  targets              IP addresses or CIDR ranges to scan

Options:
  -t, --timeout FLOAT  Timeout in seconds (default: 1, supports decimals like 2.5)
  -r, --rate INT       Initial packets per second (default: 2000)
  -f, --file FILE      Read targets from file (one per line)
  --conservative       Conservative mode - use lower scan rates
  -h, --help          Show help message

# Configuration
Target File Format

Create a text file with one target per line:

192.168.1.0/24
10.0.0.0/16
172.16.1.100
203.0.113.0/24

# Scan Modes

The scanner automatically selects scan mode based on target count:

    Small: < 1,000 hosts
    Medium: 1,000 - 9,999 hosts
    Large: 10,000 - 49,999 hosts
    Massive: 50,000+ hosts

Timeout Recommendations

    Fast networks: 0.5 - 1.0 seconds
    Standard networks: 1.0 - 2.0 seconds
    Slow/WAN networks: 2.0 - 5.0 seconds
    Very slow networks: 5.0+ seconds


### Network Health Monitoring

The scanner provides detailed network health information:

    Response times: Average response time monitoring
    Packet loss: Real-time packet loss calculation
    Error rates: Connection error tracking
    Congestion detection: Automatic detection and rate adjustment
    Threshold adaptation: Dynamic threshold adjustment based on timeout settings

### Performance Notes
Scan Speed Estimates

    Small networks (< 1K hosts): 2-10 minutes
    Medium networks (1K-10K hosts): 10-60 minutes
    Large networks (10K-50K hosts): 1-6 hours
    Massive networks (50K+ hosts): 6+ hours

### Memory Usage

    Small scans: < 50 MB RAM
    Large scans: 100-500 MB RAM
    Massive scans: 500 MB - 2 GB RAM

### Network Impact

The scanner includes multiple safety features:
- Adaptive rate limiting
- Congestion detection
- Conservative mode option
- Timeout-aware thresholds
- Emergency stop capability
