#!/usr/bin/env python3
"""
ScoutOut Packet Capture for Raspberry Pi
Captures network packets using scapy and sends them to ScoutOut API

Requirements:
- pip install scapy requests
- Run with sudo for packet capture permissions

Usage:
sudo python3 scoutout_capture.py --api-url http://your-scoutout-server:5050/api
"""

import json
import time
import signal
import sys
import argparse
import logging
import threading
from queue import Queue, Empty
from datetime import datetime
from typing import Optional, Dict, Any

import requests
from scapy.all import sniff, IP, IPv6, TCP, UDP, ICMP, Raw
from scapy.packet import Packet

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('/tmp/scoutout_capture.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

class PacketCapture:
    def __init__(self, api_url: str, interface: str = None, 
                 max_queue_size: int = 1000, batch_size: int = 10):
        self.api_url = api_url.rstrip('/')
        self.interface = interface
        self.max_queue_size = max_queue_size
        self.batch_size = batch_size
        
        self.packet_queue = Queue(maxsize=max_queue_size)
        self.packet_counter = 0
        self.running = False
        
        # Statistics
        self.stats = {
            'captured': 0,
            'sent': 0,
            'failed': 0,
            'dropped': 0,
            'start_time': None
        }
        
        # API session for connection pooling
        self.session = requests.Session()
        self.session.headers.update({
            'Content-Type': 'application/json',
            'User-Agent': 'ScoutOut-RPi-Capture/1.0'
        })
        
        # Register signal handlers for clean shutdown
        signal.signal(signal.SIGINT, self._signal_handler)
        signal.signal(signal.SIGTERM, self._signal_handler)

    def _signal_handler(self, signum, frame):
        """Handle shutdown signals gracefully"""
        logger.info(f"Received signal {signum}, shutting down...")
        self.stop()

    def _extract_packet_data(self, packet: Packet) -> Optional[Dict[str, Any]]:
        """Extract packet information and convert to API format"""
        try:
            self.packet_counter += 1
            
            # Initialize packet data structure
            packet_data = {
                'id': self.packet_counter,
                'timestamp': datetime.utcnow().isoformat() + 'Z',
                'protocol': 'Unknown',
                'sourceIP': '',
                'destIP': '',
                'sourcePort': 0,
                'destPort': 0,
                'length': len(packet),
                'flags': None,
                'payload': ''
            }

            # Handle IPv4 packets
            if IP in packet:
                ip_layer = packet[IP]
                packet_data['sourceIP'] = ip_layer.src
                packet_data['destIP'] = ip_layer.dst

                # TCP packets
                if TCP in packet:
                    tcp_layer = packet[TCP]
                    packet_data['protocol'] = 'TCP'
                    packet_data['sourcePort'] = int(tcp_layer.sport)
                    packet_data['destPort'] = int(tcp_layer.dport)
                    
                    # Extract TCP flags
                    flags = []
                    if tcp_layer.flags.S: flags.append('SYN')
                    if tcp_layer.flags.A: flags.append('ACK') 
                    if tcp_layer.flags.P: flags.append('PSH')
                    if tcp_layer.flags.F: flags.append('FIN')
                    if tcp_layer.flags.R: flags.append('RST')
                    if tcp_layer.flags.U: flags.append('URG')
                    packet_data['flags'] = '|'.join(flags) if flags else None
                    
                    # Identify application-layer protocols
                    if tcp_layer.dport == 80 or tcp_layer.sport == 80:
                        packet_data['protocol'] = 'HTTP'
                    elif tcp_layer.dport == 443 or tcp_layer.sport == 443:
                        packet_data['protocol'] = 'HTTPS'
                    elif tcp_layer.dport == 22 or tcp_layer.sport == 22:
                        packet_data['protocol'] = 'SSH'
                    elif tcp_layer.dport == 21 or tcp_layer.sport == 21:
                        packet_data['protocol'] = 'FTP'
                    elif tcp_layer.dport == 25 or tcp_layer.sport == 25:
                        packet_data['protocol'] = 'SMTP'
                    # elif tcp_layer.dport == 

                # UDP packets  
                elif UDP in packet:
                    udp_layer = packet[UDP]
                    packet_data['protocol'] = 'UDP'
                    packet_data['sourcePort'] = int(udp_layer.sport)
                    packet_data['destPort'] = int(udp_layer.dport)
                    
                    # Identify UDP-based protocols
                    if udp_layer.dport == 53 or udp_layer.sport == 53:
                        packet_data['protocol'] = 'DNS'
                    elif udp_layer.dport == 67 or udp_layer.sport == 67 or \
                         udp_layer.dport == 68 or udp_layer.sport == 68:
                        packet_data['protocol'] = 'DHCP'
                    elif udp_layer.dport == 123 or udp_layer.sport == 123:
                        packet_data['protocol'] = 'NTP'

                # ICMP packets
                elif ICMP in packet:
                    packet_data['protocol'] = 'ICMP'
                    packet_data['sourcePort'] = 0
                    packet_data['destPort'] = 0

            # Handle IPv6 packets
            elif IPv6 in packet:
                ipv6_layer = packet[IPv6]
                packet_data['sourceIP'] = ipv6_layer.src
                packet_data['destIP'] = ipv6_layer.dst
                packet_data['protocol'] = 'IPv6'

            # Extract payload (first 200 chars for brevity)
            if Raw in packet:
                try:
                    raw_data = packet[Raw].load
                    # Try to decode as UTF-8, fall back to hex
                    try:
                        payload = raw_data.decode('utf-8', errors='ignore')
                        packet_data['payload'] = payload[:200].strip()
                    except:
                        packet_data['payload'] = raw_data.hex()[:200]
                except:
                    packet_data['payload'] = f"{packet_data['protocol']} packet"
            else:
                packet_data['payload'] = f"{packet_data['protocol']} {packet_data['sourceIP']}:{packet_data['sourcePort']} -> {packet_data['destIP']}:{packet_data['destPort']}"

            return packet_data

        except Exception as e:
            logger.error(f"Error extracting packet data: {e}")
            return None

    def _packet_handler(self, packet: Packet):
        """Handle captured packets - called by scapy"""
        if not self.running:
            return

        packet_data = self._extract_packet_data(packet)
        if packet_data:
            try:
                self.packet_queue.put(packet_data, block=False)
                self.stats['captured'] += 1
                
                # Log progress every 100 packets
                if self.stats['captured'] % 100 == 0:
                    logger.info(f"Captured {self.stats['captured']} packets, "
                              f"sent {self.stats['sent']}, queue size: {self.packet_queue.qsize()}")
                    
            except:
                self.stats['dropped'] += 1
                if self.stats['dropped'] % 50 == 0:
                    logger.warning(f"Packet queue full, dropped {self.stats['dropped']} packets")

    def _api_sender_thread(self):
        """Background thread to send packets to API"""
        batch = []
        
        while self.running or not self.packet_queue.empty():
            try:
                # Get packet from queue (with timeout)
                try:
                    packet_data = self.packet_queue.get(timeout=1.0)
                    batch.append(packet_data)
                    
                    # Send batch when it reaches batch_size or queue is empty
                    if len(batch) >= self.batch_size or \
                       (not self.running and self.packet_queue.empty()):
                        self._send_batch(batch)
                        batch = []
                        
                except Empty:
                    # Send any remaining packets in batch
                    if batch:
                        self._send_batch(batch)
                        batch = []
                    continue

            except Exception as e:
                logger.error(f"Error in API sender thread: {e}")
                time.sleep(1)

    def _send_batch(self, batch):
        """Send a batch of packets to the API"""
        if not batch:
            return
            
        for packet_data in batch:
            try:
                response = self.session.post(
                    f"{self.api_url}/packets",
                    json=packet_data,
                    timeout=5.0
                )
                
                if response.status_code == 201:
                    self.stats['sent'] += 1
                else:
                    self.stats['failed'] += 1
                    logger.warning(f"API returned status {response.status_code}: {response.text}")
                    
            except requests.RequestException as e:
                self.stats['failed'] += 1
                logger.error(f"Failed to send packet {packet_data['id']}: {e}")
            except Exception as e:
                self.stats['failed'] += 1  
                logger.error(f"Unexpected error sending packet: {e}")

    def test_api_connection(self) -> bool:
        """Test connection to the ScoutOut API"""
        try:
            response = self.session.get(f"{self.api_url}/health", timeout=10.0)
            if response.status_code == 200:
                data = response.json()
                logger.info(f"✓ API connection successful - Server status: {data.get('status', 'OK')}")
                return True
            else:
                logger.error(f"✗ API health check failed: {response.status_code}")
                return False
        except requests.RequestException as e:
            logger.error(f"✗ Cannot connect to API: {e}")
            return False

    def start(self, packet_filter: str = ""):
        """Start packet capture"""
        logger.info("=" * 50)
        logger.info("ScoutOut Packet Capture Starting")
        logger.info("=" * 50)
        logger.info(f"API URL: {self.api_url}")
        logger.info(f"Interface: {self.interface or 'all interfaces'}")
        logger.info(f"Filter: {packet_filter or 'none'}")
        logger.info(f"Batch size: {self.batch_size}")

        # Test API connection
        if not self.test_api_connection():
            logger.error("Cannot connect to ScoutOut API. Please check:")
            logger.error("1. Server is running: cd server && node index.js")
            logger.error("2. URL is correct")
            logger.error("3. Network connectivity")
            return False

        self.running = True
        self.stats['start_time'] = time.time()

        # Start API sender thread
        api_thread = threading.Thread(target=self._api_sender_thread, daemon=True)
        api_thread.start()
        
        logger.info("Starting packet capture... Press Ctrl+C to stop")
        
        try:
            # Start packet sniffing
            sniff(
                iface=self.interface,
                prn=self._packet_handler,
                filter=packet_filter,
                store=False
            )
        except KeyboardInterrupt:
            logger.info("Received interrupt signal")
        except Exception as e:
            logger.error(f"Error during packet capture: {e}")
        finally:
            self.stop()
            
        return True

    def stop(self):
        """Stop packet capture and cleanup"""
        if not self.running:
            return
            
        logger.info("Stopping packet capture...")
        self.running = False
        
        # Wait for remaining packets to be sent
        remaining = self.packet_queue.qsize()
        if remaining > 0:
            logger.info(f"Sending {remaining} remaining packets...")
            time.sleep(min(5, remaining * 0.1))  # Wait up to 5 seconds

        # Print final statistics
        runtime = time.time() - (self.stats['start_time'] or time.time())
        logger.info("=" * 50)
        logger.info("Capture Statistics:")
        logger.info(f"  Runtime: {runtime:.1f} seconds")
        logger.info(f"  Packets captured: {self.stats['captured']}")
        logger.info(f"  Packets sent: {self.stats['sent']}")
        logger.info(f"  Send failures: {self.stats['failed']}")
        logger.info(f"  Packets dropped: {self.stats['dropped']}")
        if runtime > 0:
            logger.info(f"  Capture rate: {self.stats['captured']/runtime:.1f} pkt/sec")
        logger.info("=" * 50)


def main():
    parser = argparse.ArgumentParser(description='ScoutOut Packet Capture for Raspberry Pi')
    parser.add_argument('--api-url', '-a', 
                       default='http://localhost:5050/api',
                       help='ScoutOut API URL (default: http://localhost:5050/api)')
    parser.add_argument('--interface', '-i',
                       help='Network interface to capture on (default: all)')
    parser.add_argument('--filter', '-f', default='',
                       help='BPF packet filter (e.g., "tcp port 80")')
    parser.add_argument('--batch-size', '-b', type=int, default=1,
                       help='Number of packets to send per API call (default: 1)')
    parser.add_argument('--queue-size', '-q', type=int, default=1000,
                       help='Maximum packet queue size (default: 1000)')
    parser.add_argument('--verbose', '-v', action='store_true',
                       help='Enable verbose logging')

    args = parser.parse_args()

    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    # Check if running as root (required for packet capture)
    import os
    if os.geteuid() != 0:
        logger.error("This script must be run as root for packet capture")
        logger.error("Please run: sudo python3 scoutout_capture.py")
        sys.exit(1)

    # Create and start packet capture
    capture = PacketCapture(
        api_url=args.api_url,
        interface=args.interface,
        max_queue_size=args.queue_size,
        batch_size=args.batch_size
    )
    
    success = capture.start(args.filter)
    sys.exit(0 if success else 1)


if __name__ == '__main__':
    main()