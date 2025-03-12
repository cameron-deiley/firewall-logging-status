import json
import re
from pathlib import Path

failover_json_path = Path("D:/Temp/Analysts/Cam/Threat Engineering/firewall_failovers.json")

def load_failover_json():
    """Loads existing firewall failover pairs from JSON, handling errors gracefully."""
    if failover_json_path.exists():
        try:
            with open(failover_json_path, "r") as file:
                print("Loading failover firewall JSON")
                return json.load(file)
        except json.JSONDecodeError:
            print("Error: Corrupt firewall failover JSON. Resetting data")
            return {}  # Return empty if JSON is invalid
    print("No existing firewall failover JSON found. Initializing new data")
    return {}  # Return empty if JSON does not exist

def scan_for_failovers(client_path):
    """Scans client folders for failover firewall settings in nDiscovery.ini files."""
    detected_failovers = {}

    print(f"Scanning client folders in {client_path}")

    for client_folder in client_path.iterdir():
        if not client_folder.is_dir():
            continue  # Skip non-folder items

        print(f"Checking client folder {client_folder.name}")

        ini_file = client_folder / "nDiscovery.ini"
        if ini_file.exists():
            print(f"Found nDiscovery.ini in {client_folder.name}, reading file")

            with open(ini_file, "r") as file:
                for line in file:
                    if "Failover_FW=" in line:
                        match = re.search(r"\|(.*?)\((.*?)\)\|", line.strip())  # Extract FW1(FW2)
                        if match:
                            primary_fw, failover_fw = match.groups()
                            detected_failovers[client_folder.name] = [primary_fw, failover_fw]
                            print(f"Found failover pair in {client_folder.name}: Primary - {primary_fw}, Failover - {failover_fw}")

    print(f"Scanning complete. {len(detected_failovers)} failover pairs found")
    return detected_failovers

def save_failover_json(data):
    """Saves firewall failover pairs to a JSON file."""
    with open(failover_json_path, "w") as file:
        json.dump(data, file, indent=4)
    print("Firewall failover data updated")

def manage_failover_firewalls(client_path):
    """
    Detects and updates firewall failover pairs for each client.
    Returns the latest failover firewall data as a dictionary.
    """
    print("Running manage_failover_firewalls")

    existing_failovers = load_failover_json()  # Load existing failover data
    detected_failovers = scan_for_failovers(client_path)  # Scan for new failovers

    print("Comparing detected failovers with existing failover data")

    if detected_failovers != existing_failovers:
        print("Changes detected Updating firewall failover JSON")
        save_failover_json(detected_failovers)
    else:
        print("No changes detected in failover firewall pairs JSON remains unchanged")

    print("Firewall failover management complete")
    return detected_failovers  # Return updated failover data
