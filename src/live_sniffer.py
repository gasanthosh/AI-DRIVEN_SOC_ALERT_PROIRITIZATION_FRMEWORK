"""
live_sniffer.py - Real-time network traffic sniffer (SnifferManager class).
Captures packets, aggregates them into flows, and sends them to the SOC API.
Requires: scapy, requests
"""

import os
import sys
import time
import logging
import threading
from collections import defaultdict

import requests

log = logging.getLogger("SNIFFER")

# -- SnifferManager -----------------------------------------------------------

class SnifferManager:
    """Thread-safe, start/stop-controllable network sniffer."""

    def __init__(self, api_url: str = "http://localhost:8000/predict"):
        self.api_url = api_url
        self._stop_event = threading.Event()
        self._lock = threading.Lock()
        self._capture_thread: threading.Thread | None = None
        self._report_thread: threading.Thread | None = None
        self._flows = defaultdict(lambda: {
            "start": time.time(),
            "last":  time.time(),
            "pkts": 0,
            "bytes": 0,
            "fwd_pkts": 0, "bwd_pkts": 0,
            "fwd_bytes": 0, "bwd_bytes": 0,
            "syn_count": 0, "fin_count": 0, "rst_count": 0,
            "pkt_sizes": [],
            "src_ip": "", "dst_ip": "",
        })
        self._flows_lock = threading.Lock()

        # Stats
        self.packets_captured: int = 0
        self.flows_processed: int = 0
        self.interface: str | None = None
        self.interval: int = 5
        self._pkt_bucket: int = 0   # packets since last rate check
        self._pkt_rate: float = 0.0
        self._rate_ts: float = time.time()

    # ── Public API ────────────────────────────────────────────────────────────

    def start(self, interface: str | None = None, interval: int = 5):
        with self._lock:
            if self._capture_thread and self._capture_thread.is_alive():
                return False   # already running
            self._stop_event.clear()
            self.interface = interface
            self.interval  = interval
            self.packets_captured = 0
            self.flows_processed  = 0
            self._pkt_bucket = 0
            self._pkt_rate   = 0.0
            self._rate_ts    = time.time()
            with self._flows_lock:
                self._flows.clear()

            self._report_thread = threading.Thread(
                target=self._report_loop, daemon=True, name="soc-report"
            )
            self._capture_thread = threading.Thread(
                target=self._capture_loop, daemon=True, name="soc-capture"
            )
            self._report_thread.start()
            self._capture_thread.start()
            log.info(f"SnifferManager started on interface={interface!r} interval={interval}s")
            return True

    def stop(self):
        with self._lock:
            if not self._capture_thread:
                return False
        self._stop_event.set()
        if self._capture_thread:
            self._capture_thread.join(timeout=6)
        if self._report_thread:
            self._report_thread.join(timeout=3)
        self._capture_thread = None
        self._report_thread  = None
        log.info("SnifferManager stopped.")
        return True

    def is_running(self) -> bool:
        return bool(self._capture_thread and self._capture_thread.is_alive())

    def get_status(self) -> dict:
        now = time.time()
        elapsed = now - self._rate_ts
        if elapsed >= 1.0:
            self._pkt_rate = round(self._pkt_bucket / elapsed, 2)
            self._pkt_bucket = 0
            self._rate_ts = now
        return {
            "running":           self.is_running(),
            "interface":         self.interface,
            "interval":          self.interval,
            "packets_captured":  self.packets_captured,
            "flows_processed":   self.flows_processed,
            "pkt_rate":          self._pkt_rate,
        }

    # ── Internal ──────────────────────────────────────────────────────────────

    def _packet_callback(self, pkt):
        """Callback for each sniffed packet."""
        try:
            from scapy.all import IP, TCP, UDP
        except ImportError:
            return

        if not pkt.haslayer(IP):
            return

        self.packets_captured += 1
        self._pkt_bucket += 1

        proto  = pkt.proto
        src_ip = pkt[IP].src
        dst_ip = pkt[IP].dst
        pkt_len = len(pkt)
        src_port = dst_port = 0
        tcp_flags = {}

        if pkt.haslayer(TCP):
            src_port = pkt[TCP].sport
            dst_port = pkt[TCP].dport
            flags    = pkt[TCP].flags
            tcp_flags = {
                "syn": bool(flags & 0x02),
                "fin": bool(flags & 0x01),
                "rst": bool(flags & 0x04),
            }
        elif pkt.haslayer(UDP):
            src_port = pkt[UDP].sport
            dst_port = pkt[UDP].dport

        key = tuple(sorted([src_ip, dst_ip]) + sorted([src_port, dst_port]) + [proto])
        with self._flows_lock:
            flow = self._flows[key]
            flow["last"]  = time.time()
            flow["pkts"] += 1
            flow["bytes"] += pkt_len
            flow["pkt_sizes"].append(pkt_len)
            # Store the actual IPs for display
            if not flow["src_ip"]:
                flow["src_ip"] = src_ip
                flow["dst_ip"] = dst_ip
            if src_ip <= dst_ip:
                flow["fwd_pkts"]  += 1
                flow["fwd_bytes"] += pkt_len
            else:
                flow["bwd_pkts"]  += 1
                flow["bwd_bytes"] += pkt_len
            if tcp_flags.get("syn"): flow["syn_count"] += 1
            if tcp_flags.get("fin"): flow["fin_count"] += 1
            if tcp_flags.get("rst"): flow["rst_count"] += 1

    def _extract_features(self, stats: dict) -> dict:
        import numpy as np
        duration    = max(stats["last"] - stats["start"], 1e-9)
        duration_us = duration * 1_000_000
        pkts        = max(stats["pkts"], 1)
        sizes       = stats["pkt_sizes"] if stats["pkt_sizes"] else [0]

        return {
            "source": "SNIFFER",
            "src_ip":  stats.get("src_ip", ""),
            "dst_ip":  stats.get("dst_ip", ""),
            "Flow Duration":                   duration_us,
            "Total Fwd Packets":               stats["fwd_pkts"],
            "Total Backward Packets":          stats["bwd_pkts"],
            "Total Length of Fwd Packets":     stats["fwd_bytes"],
            "Total Length of Bwd Packets":     stats["bwd_bytes"],
            "Flow Bytes/s":                    stats["bytes"] / duration,
            "Flow Packets/s":                  pkts / duration,
            "Flow IAT Mean":                   duration_us / pkts,
            "Fwd Packet Length Max":           max(sizes),
            "Fwd Packet Length Min":           min(sizes),
            "Fwd Packet Length Mean":          float(np.mean(sizes)),
            "Fwd Packet Length Std":           float(np.std(sizes)) if len(sizes) > 1 else 0.0,
            "SYN Flag Count":                  stats["syn_count"],
            "FIN Flag Count":                  stats["fin_count"],
            "RST Flag Count":                  stats["rst_count"],
            "Down/Up Ratio":                   (stats["bwd_bytes"] / stats["fwd_bytes"])
                                                if stats["fwd_bytes"] > 0 else 0,
        }

    def _report_loop(self):
        """Periodically classify flows and POST to API."""
        while not self._stop_event.is_set():
            self._stop_event.wait(self.interval)
            with self._flows_lock:
                snapshot = dict(self._flows)
                self._flows.clear()

            if not snapshot:
                continue

            log.info(f"Processing {len(snapshot)} flows…")
            for key, stats in snapshot.items():
                if stats["pkts"] < 2:
                    continue
                features = self._extract_features(stats)
                try:
                    res = requests.post(self.api_url, json=features, timeout=2)
                    if res.status_code == 200:
                        data = res.json()
                        self.flows_processed += 1
                        if data["priority"] != "LOW":
                            log.info(
                                f"ALERT {data['attack_type']} "
                                f"({data['priority']}) risk={data['risk_score']}"
                            )
                except Exception as e:
                    log.debug(f"Failed to POST flow: {e}")

    def _capture_loop(self):
        """Run scapy sniffer, blocking until stop_event is set."""
        try:
            from scapy.all import sniff
            log.info(f"Scapy sniff starting on {self.interface!r}…")
            sniff(
                iface=self.interface,
                prn=self._packet_callback,
                store=0,
                stop_filter=lambda _: self._stop_event.is_set(),
            )
        except Exception as e:
            log.error(f"Scapy capture error: {e}")
        finally:
            self._stop_event.set()   # unblock report_loop too


# Singleton used by api/main.py
sniffer_manager = SnifferManager()


# ── CLI entry-point (unchanged) ───────────────────────────────────────────────
if __name__ == "__main__":
    import argparse
    logging.basicConfig(level=logging.INFO, format="%(asctime)s [SNIFFER] %(message)s")
    parser = argparse.ArgumentParser(description="Real-time SOC Sniffer")
    parser.add_argument("--interface", default=None)
    parser.add_argument("--interval",  type=int, default=5)
    args = parser.parse_args()

    sniffer_manager.api_url = "http://localhost:8000/predict"
    sniffer_manager.start(interface=args.interface, interval=args.interval)

    try:
        while sniffer_manager.is_running():
            time.sleep(1)
    except KeyboardInterrupt:
        sniffer_manager.stop()
        log.info("Stopped by user.")
