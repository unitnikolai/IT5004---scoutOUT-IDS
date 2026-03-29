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
from datetime import datetime, timezone
from typing import Optional, Dict, Any
import os
import requests
from scapy.all import sniff,  IP, IPv6, TCP, UDP, ICMP, Raw
from scapy.packet import Packet

# Configure logging
logging.basicConfig(
    level=logging.DEBUG,  # Changed to DEBUG for more visibility
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('scoutout_capture.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

class PacketCapture:
    def __init__(self, api_url: str, interface: str = None, 
                 max_queue_size: int = 1000, batch_size: int = 50,
                 batch_wait_time: float = 0.5):
        self.api_url = api_url.rstrip('/')
        self.interface = interface
        self.max_queue_size = max_queue_size
        self.batch_size = batch_size
        self.batch_wait_time = batch_wait_time
        
        self.packet_queue = Queue(maxsize=max_queue_size)
        self.packet_counter = 0
        self.running = False
        self.last_batch_send_time = time.time()
        
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

    def _extract_sni_from_tls(self, data: bytes) -> Optional[str]:
        """Extract SNI (Server Name Indication) from TLS Client Hello"""
        try:
            # TLS Record Header check: 0x16 for Handshake
            if len(data) < 6 or data[0] != 0x16:
                return None
            
            # TLS version check (should be 0x03, 0x01 - 0x03 for TLS versions)
            if data[1] != 0x03:
                return None
            
            # Skip TLS record header (5 bytes) and handshake header (4 bytes)
            # Look for Client Hello (handshake type 0x01)
            if len(data) < 43 or data[5] != 0x01:
                return None
            
            # Skip: TLS record (5) + handshake header (4) + version (2) + random (32) = 43
            # Parse session ID
            session_id_length = data[43]
            offset = 44 + session_id_length
            
            if len(data) < offset + 2:
                return None
            
            # Parse cipher suites
            cipher_suites_length = int.from_bytes(data[offset:offset+2], 'big')
            offset += 2 + cipher_suites_length
            
            if len(data) < offset + 1:
                return None
            
            # Parse compression methods
            compression_methods_length = data[offset]
            offset += 1 + compression_methods_length
            
            if len(data) < offset + 2:
                return None
            
            # Parse extensions
            extensions_length = int.from_bytes(data[offset:offset+2], 'big')
            offset += 2
            extensions_end = offset + extensions_length
            
            # Look for server_name extension (type 0)
            while offset < extensions_end - 4:
                ext_type = int.from_bytes(data[offset:offset+2], 'big')
                ext_length = int.from_bytes(data[offset+2:offset+4], 'big')
                offset += 4
                
                if ext_type == 0:  # server_name extension
                    # Skip list length (2 bytes) and name type (1 byte)
                    if len(data) < offset + 3:
                        break
                    name_length = int.from_bytes(data[offset+3:offset+5], 'big')
                    if len(data) < offset + 5 + name_length:
                        break
                    hostname = data[offset+5:offset+5+name_length].decode('ascii', errors='ignore')
                    return hostname if hostname else None
                
                offset += ext_length
            
            return None
        except Exception as e:
            logger.debug(f"Failed to extract SNI: {e}")
            return None

    def _extract_packet_data(self, packet: Packet) -> Optional[Dict[str, Any]]:
        """Extract packet information and convert to API format"""
        try:
            self.packet_counter += 1
            
            # Initialize packet data structure
            packet_data = {
                'id': self.packet_counter,
                'timestamp': datetime.now(timezone.utc).isoformat().replace('+00:00', 'Z'),
                'protocol': 'Unknown',
                'sourceIP': '',
                'destIP': '',
                'sourcePort': 0,
                'destPort': 0,
                'length': len(packet),
                'flags': None,
                'payload': '',
                'hostname': ''
            }

            ip_layer = None
            is_ipv6 = False

            # Handle IPv4 packets
            if IP in packet:
                ip_layer = packet[IP]
                packet_data['sourceIP'] = ip_layer.src
                packet_data['destIP'] = ip_layer.dst
                is_ipv6 = False

            # Handle IPv6 packets
            elif IPv6 in packet:
                ip_layer = packet[IPv6]
                packet_data['sourceIP'] = ip_layer.src
                packet_data['destIP'] = ip_layer.dst
                is_ipv6 = True

            # Extract transport layer info if we have IP
            if ip_layer is not None:
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

            # Extract hostname from HTTP/HTTPS requests
            if packet_data['protocol'] == 'HTTP' and Raw in packet:
                # Extract Host header from HTTP
                try:
                    raw_data = packet[Raw].load
                    payload = raw_data.decode('utf-8', errors='ignore')
                    # Look for Host header in HTTP request
                    for line in payload.split('\r\n'):
                        if line.lower().startswith('host:'):
                            packet_data['hostname'] = line.split(':', 1)[1].strip()
                            break
                except:
                    pass
            
            elif packet_data['protocol'] == 'HTTPS' and Raw in packet:
                # Extract SNI from TLS handshake for HTTPS
                try:
                    raw_data = packet[Raw].load
                    sni = self._extract_sni_from_tls(raw_data)
                    if sni:
                        packet_data['hostname'] = sni
                except:
                    pass

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

        # Filter out backend server traffic (port 5050)
        if TCP in packet:
            tcp_layer = packet[TCP]
            if tcp_layer.sport == 5050 or tcp_layer.dport == 5050:
                return  # Skip API traffic
        elif UDP in packet:
            udp_layer = packet[UDP]
            if udp_layer.sport == 5050 or udp_layer.dport == 5050:
                return  # Skip API traffic

        packet_data = self._extract_packet_data(packet)
        if packet_data:
            try:
                self.packet_queue.put(packet_data, block=False)
                self.stats['captured'] += 1
                
                # Log progress every 10 packets for debugging
                if self.stats['captured'] % 10 == 0:
                    queue_size = self.packet_queue.qsize()
                    logger.info(f"Captured {self.stats['captured']} packets, "
                              f"sent {self.stats['sent']}, queue size: {queue_size}, "
                              f"dropped {self.stats['dropped']}")
                    
            except Exception as e:
                self.stats['dropped'] += 1
                if self.stats['dropped'] % 5 == 0:
                    logger.warning(f"Packet queue full, dropped {self.stats['dropped']} packets: {e}")

    def _api_sender_thread(self):
        """Background thread to send packets to API - prioritizes web traffic"""
        web_batch = []      # HTTP/HTTPS packets
        other_batch = []    # Other protocols
        web_batch_time = time.time()
        other_batch_time = time.time()
        
        WEB_BATCH_SIZE = 10  # Send web packets faster (smaller batches)
        WEB_BATCH_WAIT = 0.2  # Send web packets more frequently
        
        logger.info("API sender thread started")
        
        while self.running or not self.packet_queue.empty():
            try:
                # Get packet from queue (non-blocking to check multiple times)
                try:
                    packet_data = self.packet_queue.get(timeout=0.1)
                    
                    # Separate web traffic (HTTP/HTTPS) from other traffic
                    if packet_data['protocol'] in ['HTTP', 'HTTPS']:
                        web_batch.append(packet_data)
                        logger.debug(f"Web packet added to batch: {len(web_batch)}/{WEB_BATCH_SIZE}")
                    else:
                        other_batch.append(packet_data)
                        logger.debug(f"Other packet added to batch: {len(other_batch)}/{self.batch_size}")
                    
                except Empty:
                    pass
                
                # Check if web batch should be sent
                time_since_web_send = time.time() - web_batch_time
                web_should_send = (
                    (len(web_batch) >= WEB_BATCH_SIZE and time_since_web_send >= WEB_BATCH_WAIT) or
                    (len(web_batch) > 0 and time_since_web_send >= 0.5)  # Send after 0.5s regardless
                )
                
                if web_should_send:
                    logger.info(f"Sending web batch of {len(web_batch)} packets")
                    self._send_batch(web_batch)
                    web_batch = []
                    web_batch_time = time.time()
                
                # Check if other batch should be sent
                time_since_other_send = time.time() - other_batch_time
                other_should_send = (
                    (len(other_batch) >= self.batch_size and time_since_other_send >= self.batch_wait_time) or
                    (not self.running and len(other_batch) > 0)
                )
                
                if other_should_send:
                    logger.info(f"Sending other batch of {len(other_batch)} packets")
                    self._send_batch(other_batch)
                    other_batch = []
                    other_batch_time = time.time()
                
                # Send remaining batches on shutdown
                if not self.running:
                    if len(web_batch) > 0:
                        logger.info(f"Sending final web batch of {len(web_batch)} packets")
                        self._send_batch(web_batch)
                        web_batch = []
                    
                    if len(other_batch) > 0:
                        logger.info(f"Sending final other batch of {len(other_batch)} packets")
                        self._send_batch(other_batch)
                        other_batch = []

            except Exception as e:
                logger.error(f"Error in API sender thread: {e}", exc_info=True)
                time.sleep(1)

    def _send_batch(self, batch):
        """Send a batch of packets to the API in a single request"""
        if not batch:
            return
        
        retry_count = 0
        max_retries = 3
        
        while retry_count < max_retries:
            try:
                # Send entire batch in one request for efficiency
                response = self.session.post(
                    f"{self.api_url}/packets/",
                    json=batch,  # Send array of packets
                    timeout=10.0
                )
                
                if response.status_code == 201:
                    result = response.json()
                    packets_added = result.get('packetsAdded', len(batch))
                    self.stats['sent'] += packets_added
                    logger.debug(f"Batch sent successfully: {packets_added}/{len(batch)} packets")
                    return  # Success, exit retry loop
                    
                elif response.status_code == 429:
                    # Rate limited - implement exponential backoff
                    retry_after = int(response.headers.get('Retry-After', 5))
                    logger.warning(f"Rate limited. Waiting {retry_after}s before retry ({retry_count + 1}/{max_retries})...")
                    time.sleep(retry_after)
                    retry_count += 1
                    
                else:
                    self.stats['failed'] += len(batch)
                    logger.warning(f"Batch send failed with status {response.status_code}: {response.text}")
                    return  # Don't retry on other errors
                    
            except requests.Timeout as e:
                retry_count += 1
                if retry_count < max_retries:
                    wait_time = min(5 * (2 ** retry_count), 30)  # Exponential backoff, max 30s
                    logger.warning(f"Timeout sending batch. Retrying in {wait_time}s ({retry_count}/{max_retries})...")
                    time.sleep(wait_time)
                else:
                    self.stats['failed'] += len(batch)
                    logger.error(f"Failed to send batch after {max_retries} retries: {e}")
                    
            except requests.ConnectionError as e:
                retry_count += 1
                if retry_count < max_retries:
                    wait_time = min(5 * (2 ** retry_count), 30)
                    logger.warning(f"Connection error. Retrying in {wait_time}s ({retry_count}/{max_retries})...")
                    time.sleep(wait_time)
                else:
                    self.stats['failed'] += len(batch)
                    logger.error(f"Connection error sending batch: {e}")
                    
            except requests.RequestException as e:
                self.stats['failed'] += len(batch)
                logger.error(f"Failed to send batch: {e}")
                return
                
            except Exception as e:
                self.stats['failed'] += len(batch)  
                logger.error(f"Unexpected error sending batch: {e}")
                return

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
        logger.info(f"Batch wait time: {self.batch_wait_time} seconds")

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
    parser.add_argument('--batch-size', '-b', type=int, default=50,
                       help='Number of packets to send per API call (default: 50)')
    parser.add_argument('--batch-wait-time', '-w', type=float, default=0.5,
                       help='Wait time in seconds before sending batch to API (default: 0.5)')
    parser.add_argument('--queue-size', '-q', type=int, default=1000,
                       help='Maximum packet queue size (default: 1000)')
    parser.add_argument('--verbose', '-v', action='store_true',
                       help='Enable verbose logging')

    args = parser.parse_args()

    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    # Check if running as root (required for packet capture)
    if os.geteuid() != 0:
        logger.error("This script must be run as root for packet capture")
        logger.error("Please run: sudo python3 scoutout_capture.py")
        sys.exit(1)

    # Create and start packet capture
    capture = PacketCapture(
        api_url=args.api_url,
        interface=args.interface,
        max_queue_size=args.queue_size,
        batch_size=args.batch_size,
        batch_wait_time=args.batch_wait_time
    )
    
    success = capture.start(args.filter)
    sys.exit(0 if success else 1)


if __name__ == '__main__':
    main()