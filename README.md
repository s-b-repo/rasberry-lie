# Rasberry-Liez

Multi-vector WiFi auditing framework. Merges all original rasberry-lie scripts into a single tool with 11 parallel attack modes, automatic monitor mode management, and vendor MAC spoofing.

**For authorized security testing only. You must have explicit permission to test any network.**

```
  ____            _                            _     _
 |  _ \ __ _ ___ | |__   ___ _ __ _ __ _   _  | |   (_) ___ ____
 | |_) / _` / __|| '_ \ / _ \ '__| '__| | | | | |   | |/ _ \_  /
 |  _ < (_| \__ \| |_) |  __/ |  | |  | |_| | | |___| |  __// /
 |_| \_\__,_|___/|_.__/ \___|_|  |_|   \__, | |_____|_|\___/___|
                                        |___/
```

## Features

- **11 attack modes** running in parallel across all discovered networks simultaneously
- **Scapy raw injection** (5 modes): deauth, disassoc, auth-flood, beacon-flood, probe-flood
- **Tool-based attacks** (6 modes): aireplay-ng deauth, aireplay-ng fakeauth, mdk4 deauth, mdk4 EAPOL, mdk4 Michael, mdk4 WIDS confusion
- **Vendor MAC spoofing** by default — 100+ real OUIs (Apple, Samsung, Intel, Broadcom, etc.)
- **Per-request MAC rotation** — fresh spoofed MAC for every attack burst
- **Multi-source parallel injection** — multiple spoofed sources per scapy attack
- **Monitor mode watchdog** — auto-detects and recovers if monitor drops mid-attack
- **Automatic network state restoration** — firewall rules removed, monitor stopped, NetworkManager/wpa_supplicant restarted, original MAC restored on Ctrl+C or SIGTERM
- **airodump-ng CSV scanning** with iwlist fallback — discovers clients for targeted per-client deauth
- **Virtual interface support** — `--multi-source` creates VIFs for true multi-radio parallel sending
- **Scoped iptables** — blocks incoming traffic only on the wireless interface, not system-wide
- **ICMP anti-fingerprinting** — blocks timestamp and address-mask requests
- **4 attack profiles**: stealth (default), balanced, aggressive, chaos
- **Verbose DEBUG logging** by default — use `-q` to quiet down
- **Network filtering** — whitelist/blacklist by ESSID or BSSID, filter by signal strength, encryption type, band

## Requirements

```bash
sudo apt-get update
sudo apt-get install net-tools aircrack-ng macchanger mdk4 python3-scapy
```

| Tool | Required for |
|------|-------------|
| `ifconfig` / `iwconfig` | Interface management |
| `airmon-ng` | Monitor mode (default, use `--no-airmon` to skip) |
| `aireplay-ng` | Classic deauth + fakeauth attacks |
| `airodump-ng` | Network scanning (falls back to iwlist) |
| `macchanger` | MAC spoofing (disable with `--no-mac-spoof`) |
| `mdk4` | EAPOL, Michael, WIDS, data-based deauth |
| `scapy` (Python) | Raw frame injection attacks |
| `iptables` | Firewall rules |

## Usage

```bash
# Default: stealth profile, all 11 attacks, vendor MACs, verbose output
sudo python3 rasberryliez.py

# Specify interface
sudo python3 rasberryliez.py -i wlan1 -m wlan1mon

# Aggressive profile, 8 worker threads
sudo python3 rasberryliez.py --profile aggressive -w 8

# Target a single AP
sudo python3 rasberryliez.py -t AA:BB:CC:DD:EE:FF

# Only deauth + disassoc, custom frame count
sudo python3 rasberryliez.py -A deauth disassoc --count 128 --sources 8

# Multi-source with virtual interfaces
sudo python3 rasberryliez.py --multi-source

# Quiet mode (INFO only)
sudo python3 rasberryliez.py -q

# Filter by encryption and signal
sudo python3 rasberryliez.py --enc-filter WPA2 --min-power -70 --band 2ghz

# Blacklist your own network
sudo python3 rasberryliez.py --blacklist MyHomeWiFi

# Save attack log to CSV
sudo python3 rasberryliez.py --logfile attacks.csv

# List all attacks and profiles
sudo python3 rasberryliez.py --list-attacks
sudo python3 rasberryliez.py --list-profiles
```

## Attack Modes

| Mode | Engine | Description |
|------|--------|-------------|
| `deauth` | scapy | Multi-source deauthentication (per-client if clients discovered) |
| `disassoc` | scapy | Multi-source disassociation |
| `auth-flood` | scapy | Authentication flood from many spoofed clients |
| `beacon-flood` | scapy | Fake AP beacon flood |
| `probe-flood` | scapy | Probe request flood |
| `aireplay` | aireplay-ng | Classic deauthentication |
| `fakeauth` | aireplay-ng | Fake authentication to AP |
| `mdk4-deauth` | mdk4 | Data-traffic based deauth/disassoc |
| `eapol` | mdk4 | EAPOL start/logoff injection |
| `michael` | mdk4 | Michael TKIP countermeasure exploit |
| `wids` | mdk4 | WIDS/WIPS confusion |

## Profiles

| Profile | Attacks | Sources | Count | Jitter | Notes |
|---------|---------|---------|-------|--------|-------|
| **stealth** (default) | All 11 | 3 | 20 | 4.0s | Low volume, heavy jitter, vendor MACs |
| balanced | 6 major | 6 | 64 | 1.0s | Moderate volume |
| aggressive | 8 | 10 | 128 | 0.0s | High volume, no jitter |
| chaos | All 11 | 16 | 256 | 0.0s | Everything at maximum |

## Architecture

```
Orchestrator._run_all()
  |
  +-- ThreadPoolExecutor(max_workers=N)  # networks in parallel
       |
       +-- _attack_network_all_parallel(net1, all_modes)
       |     |
       |     +-- ThreadPoolExecutor  # attacks in parallel per network
       |           +-- scapy_deauth (no lock, raw inject)
       |           +-- scapy_disassoc (no lock)
       |           +-- scapy_auth_flood (no lock)
       |           +-- scapy_beacon_flood (no lock)
       |           +-- scapy_probe_flood (no lock)
       |           +-- aireplay_deauth (_tool_lock)
       |           +-- mdk4_deauth (_tool_lock)
       |           +-- mdk4_eapol (_tool_lock)
       |           +-- ... (tool attacks serialize through _tool_lock)
       |
       +-- _attack_network_all_parallel(net2, all_modes)
       +-- _attack_network_all_parallel(net3, all_modes)
       +-- ...
```

- **Scapy attacks** are truly parallel (raw frame injection, no interface state changes needed)
- **Tool attacks** serialize through `_tool_lock` (external tools need exclusive interface access)
- **Monitor watchdog** runs before each cycle, auto-recovers if mode drops
- **Cleanup** always runs via `try/finally` — restores interface, firewall, killed services

## Cleanup / Auto-Restore

On exit (Ctrl+C, SIGTERM, or exception):
1. Removes scoped iptables rules (INPUT + FORWARD)
2. Removes ICMP timestamp/address-mask blocks
3. Destroys any virtual monitor interfaces
4. Stops monitor mode via airmon-ng
5. Restores interface to managed mode with original MAC
6. Restarts NetworkManager and wpa_supplicant if they were killed

## Disclaimer

This tool is for **authorized penetration testing and security research only**. Unauthorized use against networks you do not own or have explicit permission to test is illegal. You are solely responsible for your actions.
