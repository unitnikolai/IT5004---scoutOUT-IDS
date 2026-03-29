#!/usr/bin/env python3
"""
ScoutOut Packet Capture for Raspberry Pi
Captures network packets using scapy and sends them to ScoutOut API

Requirements:
    pip install scapy requests

Run with sudo for packet capture permissions.

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
from collections import deque
from queue import Queue, Full, Empty
from datetime import datetime, timezone
from typing import Optional, Dict, Any, List
import os
import requests
from scapy.all import sniff, IP, IPv6, TCP, UDP, ICMP, Raw
from scapy.packet import Packet

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
    handlers=[
        logging.FileHandler("scoutout_capture.log"),
        logging.StreamHandler(),
    ],
)
logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

# Ports whose traffic should never be forwarded to the API
_FILTER_PORTS: frozenset = frozenset({5050})

# Application-layer protocol detection by port
_TCP_PROTO: Dict[int, str] = {
    80: "HTTP",
    443: "HTTPS",
    22: "SSH",
    21: "FTP",
    25: "SMTP",
    587: "SMTP",
    465: "SMTP",
    8080: "HTTP",
    8443: "HTTPS",
}

_UDP_PROTO: Dict[int, str] = {
    53: "DNS",
    67: "DHCP",
    68: "DHCP",
    123: "NTP",
    5353: "mDNS",
    1900: "SSDP",
}

# Queue high-water mark — stop extracting when we reach this fraction full
_QUEUE_HIGH_WATER: float = 0.85

# Payload preview length (bytes decoded / hex chars)
_PAYLOAD_PREVIEW: int = 200

# Web protocols that get priority batching
_WEB_PROTOCOLS: frozenset = frozenset({"HTTP", "HTTPS"})


# ---------------------------------------------------------------------------
# PacketCapture
# ---------------------------------------------------------------------------

class PacketCapture:
    """
    Captures network packets with scapy and forwards them in batches to the
    ScoutOut REST API.

    Architecture
    ────────────
    • scapy's sniff() calls _packet_handler() on every captured frame —
      synchronously, on scapy's internal thread.
    • _packet_handler() does a cheap early-exit check (queue saturation, port
      filter) *before* calling the expensive _extract_packet_data().
    • Extracted dicts are placed into a bounded Queue.
    • A single background sender thread drains the queue, separates web traffic
      from other traffic, and flushes each bucket either when it reaches its
      target size *or* when a time deadline expires — whichever comes first.
      This prevents either bucket from starving.
    • _send_batch() retries with exponential back-off on transient errors and
      honours HTTP 429 Retry-After headers.
    """

    def __init__(
        self,
        api_url: str,
        interface: Optional[str] = None,
        max_queue_size: int = 1000,
        batch_size: int = 50,
        batch_wait_time: float = 2.0,
    ) -> None:
        self.api_url = api_url.rstrip("/")
        self.interface = interface
        self.max_queue_size = max_queue_size
        self.batch_size = batch_size
        self.batch_wait_time = batch_wait_time

        # Internal queue — bounded so the process never OOMs
        self.packet_queue: Queue = Queue(maxsize=max_queue_size)

        self._packet_counter: int = 0
        self._counter_lock = threading.Lock()
        self.running: bool = False

        self.stats: Dict[str, Any] = {
            "captured": 0,
            "sent": 0,
            "failed": 0,
            "dropped": 0,
            "start_time": None,
        }
        self._stats_lock = threading.Lock()

        # Reusable HTTP session with connection pooling
        self.session = requests.Session()
        self.session.headers.update(
            {
                "Content-Type": "application/json",
                "User-Agent": "ScoutOut-RPi-Capture/1.0",
            }
        )
        # Keep up to 4 connections alive (enough for batched posts + health checks)
        adapter = requests.adapters.HTTPAdapter(
            pool_connections=2,
            pool_maxsize=4,
            max_retries=0,  # We handle retries ourselves
        )
        self.session.mount("http://", adapter)
        self.session.mount("https://", adapter)

        signal.signal(signal.SIGINT, self._signal_handler)
        signal.signal(signal.SIGTERM, self._signal_handler)

    # ------------------------------------------------------------------
    # Signal handling
    # ------------------------------------------------------------------

    def _signal_handler(self, signum, frame) -> None:
        logger.info("Received signal %s, shutting down…", signum)
        self.stop()

    # ------------------------------------------------------------------
    # Packet parsing helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _extract_sni(data: bytes) -> Optional[str]:
        """
        Parse a TLS ClientHello and return the SNI hostname, or None.
        All index arithmetic is bounds-checked; exceptions are swallowed.
        """
        try:
            # TLS record: type=0x16 (handshake), major version=0x03
            if len(data) < 6 or data[0] != 0x16 or data[1] != 0x03:
                return None
            # Handshake type must be ClientHello (0x01)
            if len(data) < 43 or data[5] != 0x01:
                return None

            # After: TLS record (5) + handshake header (4) + version (2) + random (32)
            offset = 43
            if offset >= len(data):
                return None

            session_id_len = data[offset]
            offset += 1 + session_id_len
            if offset + 2 > len(data):
                return None

            cipher_suites_len = int.from_bytes(data[offset : offset + 2], "big")
            offset += 2 + cipher_suites_len
            if offset + 1 > len(data):
                return None

            compression_len = data[offset]
            offset += 1 + compression_len
            if offset + 2 > len(data):
                return None

            extensions_len = int.from_bytes(data[offset : offset + 2], "big")
            offset += 2
            end = offset + extensions_len

            while offset + 4 <= end:
                ext_type = int.from_bytes(data[offset : offset + 2], "big")
                ext_len  = int.from_bytes(data[offset + 2 : offset + 4], "big")
                offset += 4
                if ext_type == 0:  # server_name
                    if offset + 5 > len(data):
                        break
                    name_len = int.from_bytes(data[offset + 3 : offset + 5], "big")
                    name_end = offset + 5 + name_len
                    if name_end > len(data):
                        break
                    hostname = data[offset + 5 : name_end].decode("ascii", errors="ignore")
                    return hostname or None
                offset += ext_len

        except Exception:
            pass
        return None

    @staticmethod
    def _extract_http_host(raw: bytes) -> str:
        """Return the HTTP Host header value, or empty string."""
        try:
            text = raw.decode("utf-8", errors="ignore")
            for line in text.split("\r\n"):
                low = line.lower()
                if low.startswith("host:"):
                    return line.split(":", 1)[1].strip()
        except Exception:
            pass
        return ""

    @staticmethod
    def _safe_payload(raw: bytes) -> str:
        """Return a UTF-8 decoded snippet, falling back to hex."""
        try:
            return raw.decode("utf-8", errors="ignore")[:_PAYLOAD_PREVIEW].strip()
        except Exception:
            return raw.hex()[:_PAYLOAD_PREVIEW]

    def _next_id(self) -> int:
        with self._counter_lock:
            self._packet_counter += 1
            return self._packet_counter

    def _extract_packet_data(self, packet: Packet) -> Optional[Dict[str, Any]]:
        """
        Convert a scapy Packet into a dict matching the API schema.
        Returns None if the packet has no IP/IPv6 layer (e.g. pure ARP).
        """
        try:
            pkt_id = self._next_id()
            now    = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")

            data: Dict[str, Any] = {
                "id":         pkt_id,
                "timestamp":  now,
                "protocol":   "Unknown",
                "sourceIP":   "",
                "destIP":     "",
                "sourcePort": 0,
                "destPort":   0,
                "length":     len(packet),
                "flags":      None,
                "payload":    "",
                "hostname":   "",
            }

            # ── Network layer ──────────────────────────────────────────
            if IP in packet:
                ip = packet[IP]
                data["sourceIP"] = ip.src
                data["destIP"]   = ip.dst
            elif IPv6 in packet:
                ip = packet[IPv6]
                data["sourceIP"] = ip.src
                data["destIP"]   = ip.dst
            else:
                return None  # No IP layer — skip (ARP, etc.)

            # ── Transport layer ────────────────────────────────────────
            if TCP in packet:
                tcp = packet[TCP]
                sport, dport = int(tcp.sport), int(tcp.dport)
                data["sourcePort"] = sport
                data["destPort"]   = dport

                # TCP flags
                flags = []
                f = tcp.flags
                if f.S: flags.append("SYN")
                if f.A: flags.append("ACK")
                if f.P: flags.append("PSH")
                if f.F: flags.append("FIN")
                if f.R: flags.append("RST")
                if f.U: flags.append("URG")
                if flags:
                    data["flags"] = "|".join(flags)

                # Protocol by well-known port (check both directions)
                proto = (
                    _TCP_PROTO.get(dport)
                    or _TCP_PROTO.get(sport)
                    or "TCP"
                )
                data["protocol"] = proto

                # Application-layer enrichment
                if Raw in packet:
                    raw = packet[Raw].load
                    if proto == "HTTP":
                        data["hostname"] = self._extract_http_host(raw)
                    elif proto == "HTTPS":
                        sni = self._extract_sni(raw)
                        if sni:
                            data["hostname"] = sni
                    data["payload"] = self._safe_payload(raw)

            elif UDP in packet:
                udp = packet[UDP]
                sport, dport = int(udp.sport), int(udp.dport)
                data["sourcePort"] = sport
                data["destPort"]   = dport
                data["protocol"] = (
                    _UDP_PROTO.get(dport)
                    or _UDP_PROTO.get(sport)
                    or "UDP"
                )
                if Raw in packet:
                    data["payload"] = self._safe_payload(packet[Raw].load)

            elif ICMP in packet:
                data["protocol"] = "ICMP"

            # Fallback payload summary when Raw is absent
            if not data["payload"]:
                data["payload"] = (
                    f"{data['protocol']} "
                    f"{data['sourceIP']}:{data['sourcePort']} "
                    f"-> {data['destIP']}:{data['destPort']}"
                )

            return data

        except Exception as exc:
            logger.debug("Packet extraction error: %s", exc)
            return None

    # ------------------------------------------------------------------
    # Packet handler (called by scapy — keep it lean)
    # ------------------------------------------------------------------

    def _packet_handler(self, packet: Packet) -> None:
        """
        Fast path called by scapy for every captured frame.
        We do as little work as possible here to avoid slowing scapy down.
        """
        if not self.running:
            return

        # ── Port filter (API traffic, etc.) ───────────────────────────
        if TCP in packet:
            tcp = packet[TCP]
            if tcp.sport in _FILTER_PORTS or tcp.dport in _FILTER_PORTS:
                return
        elif UDP in packet:
            udp = packet[UDP]
            if udp.sport in _FILTER_PORTS or udp.dport in _FILTER_PORTS:
                return

        # ── Back-pressure: skip expensive extraction if queue is nearly full ──
        if self.packet_queue.qsize() >= self.max_queue_size * _QUEUE_HIGH_WATER:
            with self._stats_lock:
                self.stats["dropped"] += 1
            return

        packet_data = self._extract_packet_data(packet)
        if packet_data is None:
            return

        try:
            self.packet_queue.put_nowait(packet_data)
            with self._stats_lock:
                self.stats["captured"] += 1
                captured = self.stats["captured"]

            if captured % 50 == 0:
                logger.info(
                    "Captured %d | sent %d | queue %d | dropped %d",
                    captured,
                    self.stats["sent"],
                    self.packet_queue.qsize(),
                    self.stats["dropped"],
                )
        except Full:
            with self._stats_lock:
                self.stats["dropped"] += 1

    # ------------------------------------------------------------------
    # Sender thread
    # ------------------------------------------------------------------

    def _api_sender_thread(self) -> None:
        """
        Background thread: drain the queue and POST packets to the API.

        Two separate buckets with independent flush triggers:
          • web_batch   — HTTP/HTTPS — small batches, short deadline
          • other_batch — everything else — larger batches, longer deadline

        Each bucket flushes when EITHER its size threshold OR its time
        deadline is reached.  This guarantees neither bucket can starve.
        """
        WEB_BATCH_SIZE  = 10
        WEB_BATCH_WAIT  = 0.5    # seconds
        OTHER_BATCH_WAIT = self.batch_wait_time  # configurable (default 2 s)

        web_batch:   List[Dict] = []
        other_batch: List[Dict] = []
        web_t   = time.monotonic()
        other_t = time.monotonic()

        logger.info("API sender thread started.")

        while self.running or not self.packet_queue.empty():
            # ── Drain up to 100 items per loop tick ──────────────────
            drained = 0
            while drained < 100:
                try:
                    pkt = self.packet_queue.get_nowait()
                    if pkt["protocol"] in _WEB_PROTOCOLS:
                        web_batch.append(pkt)
                    else:
                        other_batch.append(pkt)
                    drained += 1
                except Empty:
                    break

            if drained == 0:
                # Nothing in the queue — sleep briefly to avoid busy-spin
                time.sleep(0.05)

            now = time.monotonic()

            # ── Web batch flush ───────────────────────────────────────
            if web_batch and (
                len(web_batch) >= WEB_BATCH_SIZE
                or (now - web_t) >= WEB_BATCH_WAIT
            ):
                self._send_batch(web_batch)
                web_batch = []
                web_t = time.monotonic()

            # ── Other batch flush ─────────────────────────────────────
            if other_batch and (
                len(other_batch) >= self.batch_size
                or (now - other_t) >= OTHER_BATCH_WAIT
            ):
                self._send_batch(other_batch)
                other_batch = []
                other_t = time.monotonic()

        # ── Final drain on shutdown ───────────────────────────────────
        if web_batch:
            logger.info("Final flush: %d web packets", len(web_batch))
            self._send_batch(web_batch)
        if other_batch:
            logger.info("Final flush: %d other packets", len(other_batch))
            self._send_batch(other_batch)

        logger.info("API sender thread exiting.")

    # ------------------------------------------------------------------
    # HTTP send with retry / back-off
    # ------------------------------------------------------------------

    def _send_batch(self, batch: List[Dict]) -> None:
        """
        POST a batch of packet dicts to the API.

        Retry policy:
          • HTTP 429 → honour Retry-After header (default 5 s)
          • Timeout / connection error → exponential back-off (5 s, 10 s, 20 s)
          • All other non-2xx → log and give up (don't retry; avoids duplicate data)
          • Max 3 attempts total
        """
        if not batch:
            return

        max_retries = 3
        attempt = 0

        while attempt < max_retries:
            try:
                response = self.session.post(
                    f"{self.api_url}/packets/",
                    json=batch,
                    timeout=10.0,
                )

                if response.status_code == 201:
                    result = response.json()
                    added  = result.get("packetsAdded", len(batch))
                    with self._stats_lock:
                        self.stats["sent"] += added
                    logger.debug("Batch OK: %d/%d packets accepted", added, len(batch))
                    return

                if response.status_code == 429:
                    retry_after = int(response.headers.get("Retry-After", 5))
                    attempt += 1
                    logger.warning(
                        "Rate-limited (429). Waiting %ds (attempt %d/%d)…",
                        retry_after, attempt, max_retries,
                    )
                    time.sleep(retry_after)
                    continue

                # Non-retryable error
                with self._stats_lock:
                    self.stats["failed"] += len(batch)
                logger.warning(
                    "Batch rejected: HTTP %d — %s",
                    response.status_code,
                    response.text[:200],
                )
                return

            except (requests.Timeout, requests.ConnectionError) as exc:
                attempt += 1
                if attempt < max_retries:
                    wait = min(5 * (2 ** attempt), 30)
                    logger.warning(
                        "%s — retrying in %ds (attempt %d/%d)…",
                        type(exc).__name__, wait, attempt, max_retries,
                    )
                    time.sleep(wait)
                else:
                    with self._stats_lock:
                        self.stats["failed"] += len(batch)
                    logger.error("Batch failed after %d attempts: %s", max_retries, exc)

            except requests.RequestException as exc:
                with self._stats_lock:
                    self.stats["failed"] += len(batch)
                logger.error("Unrecoverable request error: %s", exc)
                return

            except Exception as exc:
                with self._stats_lock:
                    self.stats["failed"] += len(batch)
                logger.error("Unexpected send error: %s", exc, exc_info=True)
                return

    # ------------------------------------------------------------------
    # API health check
    # ------------------------------------------------------------------

    def test_api_connection(self) -> bool:
        try:
            resp = self.session.get(f"{self.api_url}/health", timeout=10.0)
            if resp.status_code == 200:
                status = resp.json().get("status", "OK")
                logger.info("✓ API reachable — server status: %s", status)
                return True
            logger.error("✗ Health check returned HTTP %d", resp.status_code)
            return False
        except requests.RequestException as exc:
            logger.error("✗ Cannot reach API: %s", exc)
            return False

    # ------------------------------------------------------------------
    # Start / stop
    # ------------------------------------------------------------------

    def start(self, packet_filter: str = "") -> bool:
        logger.info("=" * 60)
        logger.info("ScoutOut Packet Capture — starting")
        logger.info("  API URL   : %s", self.api_url)
        logger.info("  Interface : %s", self.interface or "all")
        logger.info("  BPF filter: %s", packet_filter or "(none)")
        logger.info("  Batch size: %d  |  wait: %.1fs", self.batch_size, self.batch_wait_time)
        logger.info("  Queue size: %d", self.max_queue_size)
        logger.info("=" * 60)

        if not self.test_api_connection():
            logger.error("Cannot connect to ScoutOut API. Aborting.")
            logger.error("  1. Is the server running?  cd server && node index.js")
            logger.error("  2. Is the URL correct?    %s", self.api_url)
            return False

        self.running = True
        self.stats["start_time"] = time.monotonic()

        sender = threading.Thread(
            target=self._api_sender_thread,
            name="api-sender",
            daemon=True,
        )
        sender.start()

        logger.info("Capturing packets… press Ctrl+C to stop.")

        try:
            sniff(
                iface=self.interface if self.interface else None,
                prn=self._packet_handler,
                filter=packet_filter,
                store=False,
            )
        except KeyboardInterrupt:
            logger.info("KeyboardInterrupt received.")
        except Exception as exc:
            logger.error("Capture error: %s", exc, exc_info=True)
        finally:
            self.stop()
            # Give sender thread up to 10 s to flush remaining packets
            sender.join(timeout=10)

        return True

    def stop(self) -> None:
        if not self.running:
            return

        logger.info("Stopping capture…")
        self.running = False

        # Brief wait so in-flight packets can reach the queue before the
        # sender thread's final drain runs.
        remaining = self.packet_queue.qsize()
        if remaining:
            logger.info("Waiting for %d queued packets to flush…", remaining)
            time.sleep(min(5.0, remaining * 0.05))

        runtime = time.monotonic() - (self.stats["start_time"] or time.monotonic())
        rate    = self.stats["captured"] / runtime if runtime > 0 else 0

        logger.info("=" * 60)
        logger.info("Capture statistics")
        logger.info("  Runtime  : %.1f s", runtime)
        logger.info("  Captured : %d  (%.1f pkt/s)", self.stats["captured"], rate)
        logger.info("  Sent     : %d", self.stats["sent"])
        logger.info("  Failed   : %d", self.stats["failed"])
        logger.info("  Dropped  : %d", self.stats["dropped"])
        logger.info("=" * 60)


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main() -> None:
    parser = argparse.ArgumentParser(
        description="ScoutOut Packet Capture for Raspberry Pi",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument(
        "--api-url", "-a",
        default="http://localhost:5050/api",
        help="ScoutOut API base URL",
    )
    parser.add_argument(
        "--interface", "-i",
        default=None,
        help="Network interface (omit to capture on all)",
    )
    parser.add_argument(
        "--filter", "-f",
        default="",
        help='BPF capture filter, e.g. "tcp port 80"',
    )
    parser.add_argument(
        "--batch-size", "-b",
        type=int, default=50,
        help="Max packets per API call (non-web traffic)",
    )
    parser.add_argument(
        "--batch-wait-time", "-w",
        type=float, default=2.0,
        help="Max seconds to wait before flushing a non-web batch",
    )
    parser.add_argument(
        "--queue-size", "-q",
        type=int, default=1000,
        help="Internal packet queue capacity",
    )
    parser.add_argument(
        "--verbose", "-v",
        action="store_true",
        help="Enable DEBUG logging",
    )

    args = parser.parse_args()

    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    if os.geteuid() != 0:
        logger.error("Packet capture requires root. Run: sudo python3 scoutout_capture.py")
        sys.exit(1)

    capture = PacketCapture(
        api_url=args.api_url,
        interface=args.interface,
        max_queue_size=args.queue_size,
        batch_size=args.batch_size,
        batch_wait_time=args.batch_wait_time,
    )

    success = capture.start(args.filter)
    sys.exit(0 if success else 1)


if __name__ == "__main__":
    main()