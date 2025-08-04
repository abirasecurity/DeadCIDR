#!/usr/bin/env python3
"""
Large-Scale Network Scanner with Enhanced Timeout Handling
Automatically adjusts health monitoring based on timeout settings
"""

import asyncio
import ipaddress
import socket
import time
import sys
import argparse
import csv
import random
import threading
import os
from collections import defaultdict, deque
from statistics import mean
import subprocess
from enum import Enum

try:
    import psutil
    PSUTIL_AVAILABLE = True
except ImportError:
    PSUTIL_AVAILABLE = False

try:
    from scapy.all import *
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False

class ScanMode(Enum):
    SMALL = "small"
    MEDIUM = "medium"
    LARGE = "large"
    MASSIVE = "massive"

class NetworkHealthMonitor:
    """Updated Network Health Monitor with Timeout-Aware Thresholds"""
    def __init__(self, scan_mode, timeout, window_size=200):
        self.scan_mode = scan_mode
        self.timeout = timeout
        self.window_size = window_size
        self.response_times = deque(maxlen=window_size)
        self.packet_loss_window = deque(maxlen=window_size)
        self.error_count = 0
        self.total_packets = 0
        self.congestion_detected = False
        self.lock = threading.Lock()

        # Adjust thresholds based on timeout setting
        # Base multipliers for different scan modes
        if scan_mode == ScanMode.MASSIVE:
            base_response_multiplier = 10
            base_loss_rate = 0.50
            base_error_rate = 0.60
            self.min_sample_size = 1000
        elif scan_mode == ScanMode.LARGE:
            base_response_multiplier = 8
            base_loss_rate = 0.45
            base_error_rate = 0.55
            self.min_sample_size = 500
        elif scan_mode == ScanMode.MEDIUM:
            base_response_multiplier = 6
            base_loss_rate = 0.40
            base_error_rate = 0.50
            self.min_sample_size = 200
        else:  # SMALL
            base_response_multiplier = 5
            base_loss_rate = 0.35
            base_error_rate = 0.45
            self.min_sample_size = 100

        # Scale response time threshold based on actual timeout
        # If timeout is 3s, allow much longer response times
        self.max_response_time = max(timeout * base_response_multiplier, 15.0)
        self.max_packet_loss_rate = base_loss_rate
        self.max_error_rate = base_error_rate

        print(f"[*] Timeout-adjusted congestion thresholds for {scan_mode.value} scan:")
        print(f"    User timeout setting: {timeout}s")
        print(f"    Max response time: {self.max_response_time}s")
        print(f"    Max packet loss: {self.max_packet_loss_rate:.0%}")
        print(f"    Max error rate: {self.max_error_rate:.0%}")
        print(f"    Min samples before detection: {self.min_sample_size}")

        # Special handling for very long timeouts
        if timeout >= 3.0:
            print(f"    🕐 Long timeout detected - using very lenient thresholds")
            self.max_response_time *= 1.5  # Even more lenient
            self.max_packet_loss_rate = min(0.70, self.max_packet_loss_rate + 0.10)

    def record_response(self, response_time, success=True):
        with self.lock:
            self.total_packets += 1

            # Sample less aggressively to get better data
            sample_rate = 1.0
            if self.scan_mode == ScanMode.MASSIVE:
                sample_rate = 0.3
            elif self.scan_mode == ScanMode.LARGE:
                sample_rate = 0.5

            if random.random() < sample_rate:
                if success:
                    self.response_times.append(response_time)
                    self.packet_loss_window.append(0)
                else:
                    self.packet_loss_window.append(1)
                    self.error_count += 1

    def get_avg_response_time(self):
        with self.lock:
            if not self.response_times:
                return 0
            return mean(self.response_times)

    def get_packet_loss_rate(self):
        with self.lock:
            if not self.packet_loss_window:
                return 0
            return sum(self.packet_loss_window) / len(self.packet_loss_window)

    def is_network_congested(self):
        """Much less sensitive congestion detection with timeout awareness"""
        # Don't even check until we have enough samples
        if self.total_packets < self.min_sample_size:
            return False

        avg_response = self.get_avg_response_time()
        packet_loss = self.get_packet_loss_rate()
        error_rate = self.error_count / self.total_packets if self.total_packets > 0 else 0

        # Count severe indicators only
        severe_congestion_indicators = 0

        if avg_response > self.max_response_time:
            severe_congestion_indicators += 1
        if packet_loss > self.max_packet_loss_rate:
            severe_congestion_indicators += 1  
        if error_rate > self.max_error_rate:
            severe_congestion_indicators += 1

        # For large scans or long timeouts, require ALL 3 indicators
        if self.scan_mode in [ScanMode.LARGE, ScanMode.MASSIVE] or self.timeout >= 3.0:
            threshold = 3  # All indicators must be present
        else:
            threshold = 2  # Most indicators must be present

        was_congested = self.congestion_detected
        self.congestion_detected = severe_congestion_indicators >= threshold

        if self.congestion_detected and not was_congested:
            print(f"[!] SEVERE network congestion detected (indicators: {severe_congestion_indicators}/3)")
            print(f"    Response: {avg_response:.1f}s (>{self.max_response_time}s)")
            print(f"    Loss: {packet_loss:.1%} (>{self.max_packet_loss_rate:.0%})")
            print(f"    Errors: {error_rate:.1%} (>{self.max_error_rate:.0%})")
            print(f"    This indicates serious network infrastructure overload!")
        elif not self.congestion_detected and was_congested:
            print(f"[*] Network congestion cleared - resuming normal scan rate")

        return self.congestion_detected

    def get_network_health_summary(self):
        """Get detailed health info for troubleshooting"""
        return {
            'avg_response_time': self.get_avg_response_time(),
            'packet_loss_rate': self.get_packet_loss_rate(),
            'error_rate': self.error_count / self.total_packets if self.total_packets > 0 else 0,
            'total_packets': self.total_packets,
            'samples_collected': len(self.response_times),
            'congestion_detected': self.congestion_detected,
            'thresholds': {
                'max_response': self.max_response_time,
                'max_loss': self.max_packet_loss_rate,
                'max_errors': self.max_error_rate
            },
            'timeout_setting': self.timeout
        }

class AdaptiveRateController:
    """Updated Rate Controller with Timeout-Aware Rate Limits"""
    def __init__(self, scan_mode, timeout, initial_rate=1000):
        self.scan_mode = scan_mode
        self.timeout = timeout

        # Adjust rates based on timeout - longer timeouts need slower rates
        timeout_factor = min(timeout / 1.0, 3.0)  # Cap at 3x adjustment

        if scan_mode == ScanMode.MASSIVE:
            self.current_rate = min(initial_rate, int(8000 / timeout_factor))
            self.min_rate = max(50, int(200 / timeout_factor))
            self.max_rate = int(10000 / timeout_factor)
            self.adjustment_factor = 0.95
            self.recovery_factor = 1.02
        elif scan_mode == ScanMode.LARGE:
            self.current_rate = min(initial_rate, int(5000 / timeout_factor))
            self.min_rate = max(25, int(100 / timeout_factor))
            self.max_rate = int(7000 / timeout_factor)
            self.adjustment_factor = 0.9
            self.recovery_factor = 1.05
        else:
            self.current_rate = min(initial_rate, int(initial_rate / timeout_factor))
            self.min_rate = max(10, int(50 / timeout_factor))
            self.max_rate = int(initial_rate * 3 / timeout_factor)
            self.adjustment_factor = 0.85
            self.recovery_factor = 1.1

        self.last_adjustment_time = time.time()
        self.adjustment_cooldown = max(20, int(20 * timeout_factor))  # Longer cooldown for longer timeouts
        self.adjustment_count = 0

        print(f"[*] Timeout-adjusted rate limits:")
        print(f"    Initial rate: {self.current_rate:.0f} pps")
        print(f"    Rate range: {self.min_rate:.0f} - {self.max_rate:.0f} pps")
        print(f"    Adjustment cooldown: {self.adjustment_cooldown}s")

    def adjust_rate(self, network_congested):
        current_time = time.time()

        if current_time - self.last_adjustment_time < self.adjustment_cooldown:
            return self.current_rate

        if network_congested:
            if self.adjustment_count < 3:
                new_rate = max(self.current_rate * self.adjustment_factor, self.min_rate)
                if abs(new_rate - self.current_rate) > 50:  # Lower threshold for adjustment
                    print(f"[!] SEVERE congestion - reducing rate: {self.current_rate:.0f} -> {new_rate:.0f} pps")
                    print(f"    (Adjustment {self.adjustment_count + 1}/3)")
                    self.current_rate = new_rate
                    self.last_adjustment_time = current_time
                    self.adjustment_count += 1
            else:
                print(f"[*] Max rate reductions reached - maintaining {self.current_rate:.0f} pps")
        else:
            if self.current_rate < self.max_rate:
                new_rate = min(self.current_rate * self.recovery_factor, self.max_rate)
                if abs(new_rate - self.current_rate) > 50:
                    print(f"[*] Network stable - increasing rate: {self.current_rate:.0f} -> {new_rate:.0f} pps")
                    self.current_rate = new_rate
                    self.last_adjustment_time = current_time
                    if self.adjustment_count > 0:
                        self.adjustment_count -= 1

        return self.current_rate

class LargeScaleScanner:
    def __init__(self, initial_rate=1000, timeout=1, conservative_mode=False):
        self.timeout = timeout
        self.use_raw_sockets = SCAPY_AVAILABLE and os.geteuid() == 0

        self.scan_mode = None
        self.health_monitor = None
        self.rate_controller = None

        self.results = defaultdict(dict)
        self.results_lock = asyncio.Lock()

        self.scan_start_time = None
        self.packets_sent = 0
        self.responses_received = 0
        self.hosts_completed = 0
        self.total_hosts = 0

        self.emergency_stop = False
        self.target_ports = [80, 443]

        self.conservative_mode = conservative_mode
        self.initial_rate = initial_rate

        # Timeout validation and warnings
        if timeout >= 5.0:
            print(f"[!] WARNING: Very long timeout ({timeout}s) will significantly slow scan")
            print(f"[!] Consider using multiple shorter scans instead")
        elif timeout >= 3.0:
            print(f"[*] Long timeout ({timeout}s) - using conservative rates and thresholds")

    def analyze_scan_scope(self, targets):
        parsed_targets, cidr_ranges = self.parse_targets(targets)
        total_hosts = len(parsed_targets)

        if total_hosts < 1000:
            self.scan_mode = ScanMode.SMALL
        elif total_hosts < 10000:
            self.scan_mode = ScanMode.MEDIUM
        elif total_hosts < 50000:
            self.scan_mode = ScanMode.LARGE
        else:
            self.scan_mode = ScanMode.MASSIVE

        # Pass timeout to health monitor and rate controller
        self.health_monitor = NetworkHealthMonitor(self.scan_mode, self.timeout)

        if self.conservative_mode:
            rate = min(self.initial_rate, 500)
        else:
            rate = self.initial_rate

        self.rate_controller = AdaptiveRateController(self.scan_mode, self.timeout, rate)
        self.total_hosts = total_hosts

        print(f"\n[*] SCAN SCOPE ANALYSIS")
        print(f"    Total hosts: {total_hosts:,}")
        print(f"    Scan mode: {self.scan_mode.value.upper()}")
        print(f"    CIDR ranges: {len(cidr_ranges)}")
        print(f"    Timeout per host: {self.timeout}s")

        # Adjust time estimate based on timeout
        base_time_per_host = max(1.0 / self.rate_controller.current_rate, self.timeout * 0.3)
        estimated_time = total_hosts * base_time_per_host
        hours = int(estimated_time // 3600)
        minutes = int((estimated_time % 3600) // 60)
        print(f"    Estimated time: {hours}h {minutes}m at {self.rate_controller.current_rate:.0f} pps")

        if self.timeout >= 3.0:
            print(f"    📝 Note: Long timeout may extend actual scan time significantly")

        return parsed_targets, cidr_ranges

    def parse_targets(self, targets):
        parsed_targets = []
        cidr_ranges = []

        for target in targets:
            target = target.strip()
            if not target:
                continue

            try:
                network = ipaddress.ip_network(target, strict=False)
                if network.num_addresses > 1:
                    cidr_ranges.append(network)
                    if network.num_addresses > 65536:
                        print(f"[!] Very large network {network} - this will take significant time")
                    parsed_targets.extend(list(network.hosts()))
                else:
                    parsed_targets.append(network.network_address)
            except ipaddress.AddressValueError:
                print(f"[!] Invalid IP/CIDR format: {target}")

        return parsed_targets, cidr_ranges

    async def fast_scan_host(self, host, semaphore):
        async with semaphore:
            if self.emergency_stop:
                return False

            host_str = str(host)

            await asyncio.sleep(1.0 / self.rate_controller.current_rate)

            start_time = time.time()

            try:
                ping_task = asyncio.create_task(self.quick_ping(host_str))
                port_tasks = [asyncio.create_task(self.quick_port_scan(host_str, port)) 
                             for port in self.target_ports]

                # Use longer timeout for the overall operation
                operation_timeout = self.timeout * 2 + 1
                ping_result = await asyncio.wait_for(ping_task, timeout=operation_timeout)
                port_results = await asyncio.gather(*port_tasks, return_exceptions=True)

                http_result = port_results[0] if len(port_results) > 0 and not isinstance(port_results[0], Exception) else False
                https_result = port_results[1] if len(port_results) > 1 and not isinstance(port_results[1], Exception) else False
                is_alive = ping_result or http_result or https_result

                response_time = time.time() - start_time
                self.health_monitor.record_response(response_time, is_alive)

                if is_alive:
                    self.responses_received += 1

                async with self.results_lock:
                    self.results[host_str] = {
                        'ping': ping_result,
                        'http': http_result,
                        'https': https_result,
                        'alive': is_alive
                    }
                    self.hosts_completed += 1

                self.packets_sent += 1 + len(self.target_ports)
                return is_alive

            except Exception:
                async with self.results_lock:
                    self.results[host_str] = {
                        'ping': False,
                        'http': False,
                        'https': False,
                        'alive': False
                    }
                    self.hosts_completed += 1

                return False

    async def quick_ping(self, host):
        try:
            if self.use_raw_sockets:
                packet = IP(dst=host)/ICMP(type=8, code=0, id=random.randint(1, 65535))
                response = sr1(packet, timeout=self.timeout, verbose=0)
                return response is not None and response.haslayer(ICMP) and response[ICMP].type == 0
            else:
                return await self.subprocess_ping(host)
        except:
            return False

    async def quick_port_scan(self, host, port):
        try:
            if self.use_raw_sockets:
                packet = IP(dst=host)/TCP(sport=random.randint(1024, 65535), dport=port, flags="S")
                response = sr1(packet, timeout=self.timeout, verbose=0)
                return response is not None and response.haslayer(TCP) and response[TCP].flags == 18
            else:
                future = asyncio.open_connection(host, port)
                reader, writer = await asyncio.wait_for(future, timeout=self.timeout)
                writer.close()
                await writer.wait_closed()
                return True
        except:
            return False

    async def subprocess_ping(self, host):
        try:
            if sys.platform.startswith('win'):
                cmd = ['ping', '-n', '1', '-w', str(int(self.timeout * 1000)), host]
            else:
                cmd = ['ping', '-c', '1', '-W', str(int(self.timeout)), host]

            process = await asyncio.create_subprocess_exec(
                *cmd, stdout=asyncio.subprocess.DEVNULL, stderr=asyncio.subprocess.DEVNULL
            )
            await asyncio.wait_for(process.wait(), timeout=self.timeout + 1)
            return process.returncode == 0
        except:
            return False

    async def progress_monitor(self):
        """Enhanced Progress Monitor with Health Details"""
        last_completed = 0
        last_time = time.time()

        while not self.emergency_stop and self.hosts_completed < self.total_hosts:
            await asyncio.sleep(15)

            current_time = time.time()
            current_completed = self.hosts_completed

            elapsed_total = current_time - self.scan_start_time
            elapsed_recent = current_time - last_time

            overall_rate = current_completed / elapsed_total if elapsed_total > 0 else 0
            recent_rate = (current_completed - last_completed) / elapsed_recent if elapsed_recent > 0 else 0

            remaining = self.total_hosts - current_completed
            eta_seconds = remaining / recent_rate if recent_rate > 0 else 0
            eta_hours = int(eta_seconds // 3600)
            eta_minutes = int((eta_seconds % 3600) // 60)

            progress_pct = (current_completed / self.total_hosts * 100) if self.total_hosts > 0 else 0
            response_rate = (self.responses_received/self.packets_sent*100) if self.packets_sent > 0 else 0

            print(f"\n[*] PROGRESS UPDATE ({time.strftime('%H:%M:%S')})")
            print(f"    Completed: {current_completed:,}/{self.total_hosts:,} ({progress_pct:.1f}%)")
            print(f"    Rate: {overall_rate:.1f} overall, {recent_rate:.1f} recent (hosts/sec)")
            print(f"    ETA: {eta_hours}h {eta_minutes}m remaining")
            print(f"    Response rate: {response_rate:.1f}% | Live hosts found: {self.responses_received:,}")
            print(f"    Current scan rate: {self.rate_controller.current_rate:.0f} pps")
            print(f"    Timeout setting: {self.timeout}s")

            # Show network health details
            health = self.health_monitor.get_network_health_summary()
            if health['total_packets'] > 0:
                print(f"    Network health: {health['avg_response_time']:.2f}s avg response, "
                      f"{health['packet_loss_rate']:.1%} loss, {health['error_rate']:.1%} errors")
                print(f"    Health thresholds: {health['thresholds']['max_response']:.1f}s, "
                      f"{health['thresholds']['max_loss']:.0%}, {health['thresholds']['max_errors']:.0%}")

            if self.health_monitor.congestion_detected:
                print(f"    🚨 SEVERE network congestion detected - scan rate reduced")
            else:
                print(f"    ✅ Network conditions normal")

            last_completed = current_completed
            last_time = current_time

    async def health_monitor_task(self):
        while not self.emergency_stop:
            await asyncio.sleep(20)

            is_congested = self.health_monitor.is_network_congested()
            self.rate_controller.adjust_rate(is_congested)

    async def run_large_scale_scan(self, targets):
        parsed_targets, cidr_ranges = self.analyze_scan_scope(targets)

        if not parsed_targets:
            print("[!] No valid targets found")
            return

        print(f"\n[*] Starting {self.scan_mode.value} scale scan...")
        print(f"[*] Scan rate: {self.rate_controller.current_rate:.0f} pps")
        print(f"[*] Timeout: {self.timeout}s per host")
        print("-" * 80)

        self.scan_start_time = time.time()
        self.cidr_ranges = cidr_ranges

        # Adjust concurrency based on timeout
        timeout_factor = min(self.timeout / 1.0, 3.0)

        if self.scan_mode == ScanMode.MASSIVE:
            max_concurrent = min(2000, max(100, int(self.rate_controller.current_rate / (2 * timeout_factor))))
        elif self.scan_mode == ScanMode.LARGE:
            max_concurrent = min(1000, max(50, int(self.rate_controller.current_rate / (3 * timeout_factor))))
        else:
            max_concurrent = min(500, max(20, int(self.rate_controller.current_rate / (5 * timeout_factor))))

        semaphore = asyncio.Semaphore(max_concurrent)

        progress_task = asyncio.create_task(self.progress_monitor())
        health_task = asyncio.create_task(self.health_monitor_task())

        print(f"[*] Max concurrent connections: {max_concurrent}")

        if self.scan_mode == ScanMode.MASSIVE:
            await self.batch_scan(parsed_targets, semaphore, batch_size=5000)
        else:
            tasks = [asyncio.create_task(self.fast_scan_host(host, semaphore)) 
                    for host in parsed_targets]

            await asyncio.gather(*tasks, return_exceptions=True)

        progress_task.cancel()
        health_task.cancel()

        end_time = time.time()
        total_time = end_time - self.scan_start_time

        print(f"\n[*] SCAN COMPLETED!")
        print(f"    Total time: {total_time/3600:.1f} hours ({total_time:.1f} seconds)")
        print(f"    Hosts scanned: {self.hosts_completed:,}/{self.total_hosts:,}")
        print(f"    Average rate: {self.hosts_completed/total_time:.1f} hosts/sec")
        print(f"    Alive hosts: {self.responses_received:,}")
        print(f"    Timeout used: {self.timeout}s")

        self.generate_comprehensive_report()

    async def batch_scan(self, targets, semaphore, batch_size=5000):
        total_batches = (len(targets) + batch_size - 1) // batch_size

        for batch_num in range(total_batches):
            if self.emergency_stop:
                break

            start_idx = batch_num * batch_size
            end_idx = min(start_idx + batch_size, len(targets))
            batch_targets = targets[start_idx:end_idx]

            print(f"[*] Processing batch {batch_num + 1}/{total_batches} ({len(batch_targets)} hosts)")

            tasks = [asyncio.create_task(self.fast_scan_host(host, semaphore)) 
                    for host in batch_targets]

            await asyncio.gather(*tasks, return_exceptions=True)

            if batch_num < total_batches - 1:
                await asyncio.sleep(1)

    def generate_comprehensive_report(self):
        """Generate report with original reachable/unreachable format"""
        print(f"\n{'='*80}")
        print("COMPREHENSIVE NETWORK SCAN REPORT")
        print(f"{'='*80}")

        # Separate CIDR ranges into reachable and unreachable
        reachable_cidrs = []
        unreachable_cidrs = []

        for cidr in self.cidr_ranges:
            alive_count = sum(1 for host in cidr.hosts() 
                             if str(host) in self.results and self.results[str(host)]['alive'])
            total_hosts = cidr.num_addresses - 2 if cidr.num_addresses > 2 else 1

            cidr_info = {
                'network': cidr,
                'alive': alive_count,
                'total': total_hosts,
                'percentage': (alive_count/total_hosts*100) if total_hosts > 0 else 0
            }

            if alive_count > 0:
                reachable_cidrs.append(cidr_info)
            else:
                unreachable_cidrs.append(cidr_info)

        # Display reachable networks
        print("\n🟢 REACHABLE NETWORKS/IPs")
        print("=" * 50)

        if reachable_cidrs:
            print("\n## Subnets with Accessible Hosts:")
            for cidr_info in sorted(reachable_cidrs, key=lambda x: x['percentage'], reverse=True):
                print(f"  ✓ {cidr_info['network']}: {cidr_info['alive']}/{cidr_info['total']} hosts ({cidr_info['percentage']:.1f}%)")
        else:
            print("  ❌ No reachable networks found!")

        # Display unreachable networks
        print("\n🔴 UNREACHABLE NETWORKS/IPs")
        print("=" * 50)

        if unreachable_cidrs:
            print("\n## Subnets with No Accessible Hosts:")
            for cidr_info in sorted(unreachable_cidrs, key=lambda x: str(x['network'])):
                print(f"  ✗ {cidr_info['network']}: 0/{cidr_info['total']} hosts (0.0%)")
        else:
            print("  ✓ All networks are reachable!")

        # Special note for long timeouts
        if self.timeout >= 3.0:
            print(f"\n📝 SCAN NOTES:")
            print(f"    • Used {self.timeout}s timeout per host")
            print(f"    • Adjusted thresholds for slower networks")
            print(f"    • Consider even longer timeouts if still missing hosts")

        # Summary statistics
        print("\n" + "=" * 80)
        print("SUMMARY STATISTICS")
        print("=" * 80)

        total_hosts = len(self.results)
        alive_hosts = sum(1 for data in self.results.values() if data['alive'])
        total_networks = len(self.cidr_ranges)
        reachable_networks = len(reachable_cidrs)

        print(f"\n📊 Overall Results:")
        print(f"  Total Hosts Scanned: {total_hosts:,}")
        print(f"  Reachable Hosts: {alive_hosts:,} ({alive_hosts/total_hosts*100:.1f}%)")
        print(f"  Total Networks: {total_networks}")
        print(f"  Networks with Live Hosts: {reachable_networks} ({reachable_networks/total_networks*100:.1f}%)")
        print(f"  Scan Mode: {self.scan_mode.value.upper()}")
        print(f"  Timeout Used: {self.timeout}s")

        # Method-specific statistics
        ping_responses = sum(1 for data in self.results.values() if data['ping'])
        http_responses = sum(1 for data in self.results.values() if data['http'])
        https_responses = sum(1 for data in self.results.values() if data['https'])

        print(f"\n🔍 Detection Methods:")
        print(f"  ICMP Ping: {ping_responses:,} responses")
        print(f"  HTTP (Port 80): {http_responses:,} open")
        print(f"  HTTPS (Port 443): {https_responses:,} open")

        icmp_blocked_hosts = sum(1 for data in self.results.values() 
                                if not data['ping'] and (data['http'] or data['https']))
        if icmp_blocked_hosts > 0:
            print(f"  ICMP-blocked hosts: {icmp_blocked_hosts:,} (detected via port scans)")

        print(f"\n🛡️ Network Safety Summary:")
        print(f"  Congestion detected: {'Yes' if self.health_monitor.congestion_detected else 'No'}")
        print(f"  Final scan rate: {self.rate_controller.current_rate:.0f} pps")

        # Final network health summary
        health = self.health_monitor.get_network_health_summary()
        print(f"  Final network health: {health['avg_response_time']:.2f}s response, "
              f"{health['packet_loss_rate']:.1%} loss, {health['error_rate']:.1%} errors")

def main():
    parser = argparse.ArgumentParser(description='Large-Scale Network Scanner with Enhanced Timeout Support')
    parser.add_argument('targets', nargs='*', help='IP addresses or CIDR ranges')
    parser.add_argument('-t', '--timeout', type=float, default=1, help='Timeout in seconds (can use decimals like 2.5)')
    parser.add_argument('-r', '--rate', type=int, default=2000, help='Initial packets per second')
    parser.add_argument('-f', '--file', help='Read targets from file')
    parser.add_argument('--conservative', action='store_true', help='Conservative mode - lower rates')

    args = parser.parse_args()

    all_targets = []
    if args.targets:
        all_targets.extend(args.targets)

    if args.file:
        try:
            with open(args.file, 'r') as f:
                file_targets = [line.strip() for line in f if line.strip()]
            all_targets.extend(file_targets)
            print(f"[*] Loaded {len(file_targets)} targets from {args.file}")
        except FileNotFoundError:
            print(f"[!] File not found: {args.file}")
            return

    if not all_targets:
        print("[!] No targets specified")
        return

    scanner = LargeScaleScanner(
        initial_rate=args.rate,
        timeout=args.timeout,
        conservative_mode=args.conservative
    )

    try:
        asyncio.run(scanner.run_large_scale_scan(all_targets))
    except KeyboardInterrupt:
        print("\n[!] Scan interrupted by user")

if __name__ == "__main__":
    main()
