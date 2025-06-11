# Firewall Logging Script - Cameron Deiley
# This script has been developed with the purpose of keeping better track of the current status of our client's firewalls. The script has the following functionality:

# Iterates through client folder and grabs all summary firewall database files and checks if any of them are missing any of the following conditions:
# 1. Traffic direction (Inbound + Outbound), size, permission (allowed/denied), debug events (too much info)
# 2. Prints out failover pairs for each client
# 3. Can be ran on one client or across all clients
# 4. Shows vendor of FW for easier troubleshooting

import pyodbc
from pathlib import Path
from datetime import datetime, timedelta
import re
import json
import logging
import csv

# ========================== PATH CONFIG ==========================
clients_folder = Path('D:/Clients')
client_name_exceptions_file = Path('D:/Temp/Analysts/Julian/Script_Source/ClientExclusions.txt')
local_output_dir = Path("D:/Temp/Analysts/Cam/Threat Engineering/FW Script Outputs")
failover_data_file = Path("D:/Temp/Analysts/Cam/Threat Engineering/FW Settings/chatfirewall_failovers.txt")
csv_path = Path("D:/Documentation/Internal/ClientFirewallDetails.csv")
client_date_exceptions_file = Path('D:/Temp/Analysts/Julian/Script_Source/ClientFolderDateExceptions.txt')
client_fw_exceptions_file = Path('D:\Temp\Analysts\Cam\Threat Engineering\FW Settings\client_fw_exceptions.json')

# ========================== VARIABLE CONFIG ==========================
timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M")
ip_regex_pattern = re.compile(r"(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})")
default_folder_date = (datetime.now() - timedelta(days=1)).strftime("%Y%m%d")
current_date = datetime.now().strftime("%Y%m%d")
input_folder = "Input"
traffic_summary_table = "TrafficSummary"
client = clients_folder.name
log_file_path = local_output_dir / f"FW_logging_{timestamp}.log"
folder_loc = None
db_path = None
output_file = None

# ========================== PATTERNS AND LISTS ==========================
custom_fw_names = [
    "BRANCH", "CORPORATE", "CITYHALL", "CORP", "FIREDEPARTMENT",
    "GUEST", "PCI", "REMOTE", "SCADA", "SCHOOLS", "SEWERPLANT", 
    "STUDENT", "SYSMON"
]

regex_fw_pattern = "|".join(map(re.escape, custom_fw_names))

mdb_filename_patterns = [
    r"^\d{4}-\d{2}-\d{2}-\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}-Summary-firewall\.mdb$",
    fr"^\d{{4}}-\d{{2}}-\d{{2}}-({regex_fw_pattern})-Summary-firewall\.mdb$"
]

expected_conditions = {
    "Traffic Size": True,
    "Inbound Traffic": True,
    "Outbound Traffic": True,
    "Allowed Traffic": True,
    "Denied Traffic": True,
    "Debug Events": False
}

fw_type_normalization = {
    "palo": "Palo Alto",
    "sonicwall": "Sonicwall",
    "arista": "Arista",
    "barracuda_11_13": "Barracuda",
    "Barracuda_11_13": "Barracuda",
    "asa": "Cisco ASA",
    "fortigate": "Fortigate",
    "meraki": "Meraki",
    "sophoswaf": "Sophos WAF",
    "cyberoam": "Cyberoam",
    "firepower": "Cisco Firepower",
    "watchguard113": "WatchGuard",
    "ubiquiti": "Ubiquiti",
    "checkpoint": "Checkpoint"
}

# ========================== HELPER FUNCTIONS ==========================
def load_excluded_clients(exceptions_file_path):
    # Reads the exclusion file and returns a list of folder names to skip.
    excluded = []
    if exceptions_file_path.exists():
        with exceptions_file_path.open('r', errors='ignore') as file:
            for line in file:
                clean = line.strip()
                if clean and clean not in excluded:
                    excluded.append(clean)
    return excluded

def load_date_exclustions(date_exclustions_file_path):
    # Loads exclusions based on date
    excluded = []
    if date_exclustions_file_path.exists():
        with date_exclustions_file_path.open('r', errors='ignore') as file:
            for line in file:
                clean = line.strip()
                if clean and clean not in excluded:
                    excluded.append(clean)
    return excluded

def get_mode_selection():
    available_clients = [folder.name for folder in clients_folder.iterdir() if folder.is_dir()]
    available_clients.sort()
    while True:
        mode = input("Check all clients or a specific one? (all/one): ").strip().lower()
        if mode == "all":
            return mode, None
        elif mode == "one":
            while True:
                user_input = input("\nType part of the client name to search: ").strip()
                matching_clients = [name for name in available_clients if user_input.lower() in name.lower()]
                if not matching_clients:
                    print("No matching clients found. Try again.")
                    continue
                elif len(matching_clients) == 1:
                    confirm = input(f"Did you mean '{matching_clients[0]}'? (y/n): ").strip().lower()
                    if confirm == 'y':
                        return mode, matching_clients[0]
                    else:
                        continue
                else:
                    print("Multiple matching clients found:")
                    for match in matching_clients:
                        print(f"  - {match}")
                    exact_input = input("Type the full client name from above exactly as shown: ").strip()
                    if exact_input in matching_clients:
                        confirm = input(f"You selected '{exact_input}'. Confirm? (y/n): ").strip().lower()
                        if confirm == 'y':
                            return mode, exact_input
                        else:
                            continue
                    else:
                        print("That name wasn’t in the list. Try again.")
                        continue
        else:
            print("Invalid mode. Please type 'all' or 'one'.")

def get_folder_loc(client_folder, folder_date):
    return client_folder/"Source"/folder_date/input_folder

def get_db_path(folder_loc, mdb_file):
    return folder_loc/mdb_file

def get_output_file(specific_client, timestamp, local_output_dir):
    if specific_client:
        filename = f"Logging Configurations Script_{specific_client}_{timestamp}.txt"
    else:
        filename = f"Logging Configurations Script_(ALL CLIENTS)_{timestamp}.txt"
    return local_output_dir / filename

def setup_logger(log_file_path):
    logger = logging.getLogger("fw_logger")
    logger.setLevel(logging.INFO)

    # File handler
    file_handler = logging.FileHandler(log_file_path)
    formatter = logging.Formatter('%(asctime)s - %(message)s')
    file_handler.setFormatter(formatter)

    logger.addHandler(file_handler)
    return logger

def parse_client_firewall_types_from_csv(csv_path: Path) -> dict:
    client_fw_type_map = {}
    f_ip_pattern = re.compile(r"--f\s+(\d{1,3}(?:\.\d{1,3}){3})")
    type_pattern = re.compile(r"--(\w+)\b")

    if not csv_path.exists():
        print(f"Warning: CSV not found: {csv_path}")
        return client_fw_type_map

    try:
        with csv_path.open("r", encoding="utf-8") as file:
            reader = csv.reader(file)
            for row in reader:
                if len(row) < 2:
                    continue

                client_name = row[0].strip()
                content = row[1]

                # Find --f IP
                f_ip_match = f_ip_pattern.search(content)
                # Find last --type
                all_types = type_pattern.findall(content)
                fw_type = all_types[-1] if all_types else None

                if f_ip_match and fw_type:
                    ip = f_ip_match.group(1)
                    normalized_ip = ".".join(str(int(octet)) for octet in ip.split("."))

                    if client_name not in client_fw_type_map:
                        client_fw_type_map[client_name] = {}
                    client_fw_type_map[client_name][normalized_ip] = fw_type
    except Exception as e:
        print(f"Error reading firewall type CSV: {e}")

    return client_fw_type_map

def check_debug_for_ip(folder_loc: Path, fw_identifier: str) -> bool:
    """
    Checks if a .Syslog.txt file exists for the given IP (zero-padded format) and contains '.Debug' entries.
    Returns True if debug events are found, False otherwise.
    """
    if not re.match(r"^\d+\.\d+\.\d+\.\d+$", fw_identifier):
        return False  # Only check IP-based firewalls

    # Zero-pad the IP to match syslog filename pattern
    padded_ip = ".".join(octet.zfill(3) for octet in fw_identifier.split("."))

    # Look for file like: 2024-04-16-00-010.100.000.001-Syslog.txt
    try:
        syslog_file = next(folder_loc.glob(f"*-{padded_ip}-Syslog.txt"), None)
        if not syslog_file or not syslog_file.exists():
            return False

        with syslog_file.open("r", encoding="utf-8", errors="ignore") as f:
            return any(".Debug" in line for line in f)

    except Exception as e:
        print(f"Error checking debug events for {fw_identifier}: {e}")
        return False

# ========================== MAIN FUNCTION ==========================
def check_ALL_fw_logging_levels(mode="all", specific_client=None):
    logger = setup_logger(log_file_path)
    
    print("Script has started running...")
    logger.info("Script has started running...")
    results = {}
    printed_clients = set()
    failover_pairs = {}
    failover_lookup = {}

    # Load client exclusions
    client_name_exceptions = load_excluded_clients(client_name_exceptions_file)
    print("Client exemptions loaded!")

    client_date_exceptions = load_date_exclustions(client_date_exceptions_file)
    print("Client date exemptions loaded!")
    
    # Load FW types
    client_fw_type_map = parse_client_firewall_types_from_csv(csv_path)
    print("Client firewall types mapped!")

    # Load failover pairs
    if failover_data_file.exists():
        with failover_data_file.open("r", encoding="utf-8") as file:
            failover_pairs = json.load(file)
    print("Failover pairs loaded!")

    # Bidirectional lookup for failover pairs
    for client, (primary, secondary) in failover_pairs.items():
        failover_lookup[primary] = secondary
        failover_lookup[secondary] = primary

    # Prepare name for output file
    global output_file
    output_file = get_output_file(specific_client, timestamp, local_output_dir)
    local_output_dir.mkdir(parents=True, exist_ok=True)

    # Everything after this point is with the output file open
    with output_file.open("w", encoding="utf-8", buffering=1) as file:
        file.write(f"Firewall Settings Search Results - {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
        file.write(f"Checking FW logging status for {default_folder_date}\n")
        file.write("=" * 50 + "\n")

        for client_folder in clients_folder.iterdir():
            if not client_folder.is_dir():
                continue
            
            client = client_folder.name
            if specific_client and client != specific_client:
                continue
            
            # Client exceptions loaded from source file (.txt)
            if client in client_name_exceptions:
                logger.info(f"Skipping excluded folder: {client}\n")
                file.write(f"\nSkipping excluded folder: {client}\n")
                continue
            
            if client in client_date_exceptions:
                folder_date = current_date
            else:
                folder_date = default_folder_date
            
            global folder_loc
            folder_loc = get_folder_loc(client_folder, folder_date)

            # Start writing to output file
            logger.info(f"Processing: {client}")
            file.write(f"\nProcessing: {client}\n")
            print(f"\nProcessing: {client}")

            logger.info(f"Checking client folder: {folder_loc}")
            if not folder_loc.exists():
                print(f"Warning: Folder path '{folder_loc}' does not exist. Please investigate this!")
                logger.warning(f"Warning: Folder path '{folder_loc}' does not exist. Please investigate this!")
                file.write(f"Warning: Folder path '{folder_loc}' does not exist. Please investigate this!\n")
                continue

            # Write failover pairs for client with results from failover script
            if client in failover_pairs and client not in printed_clients:
                primary, secondary = failover_pairs[client]
                file.write(f"Failover Pair: {primary} -> {secondary}\n")
                logger.info(f"Failover Pair: {primary} -> {secondary}\n")
                print(f"Failover Pair: {primary} -> {secondary}\n")
                printed_clients.add(client)
            file.write("-" * 50 + "\n")

            # Working with the DBs after this point
            found_mdb_file = False
            for mdb_file in folder_loc.iterdir():
                db_file_str = str(mdb_file)
                
                # Only proceed if filename matches our expected .mdb patterns
                if not any(re.search(pattern, mdb_file.name, re.IGNORECASE) for pattern in mdb_filename_patterns):
                    continue

                # Now we're sure it's a valid firewall .mdb file
                found_mdb_file = True
                global db_path
                db_path = get_db_path(folder_loc, mdb_file)

                # Match IP first -> FW name if no IP is found
                raw_ip_match = re.search(r"(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})", db_file_str)
                fw_name_match = re.search(fr"({regex_fw_pattern})", db_file_str)
                normalized_ip = None

                try:
                    logger.info(f"Attempting to connect to {mdb_file.name}")
                    conn = pyodbc.connect(rf"DRIVER={{Microsoft Access Driver (*.mdb, *.accdb)}};DBQ={db_path};")
                    cursor = conn.cursor()
                    logger.info(f"Successfully connected to {mdb_file.name}! ")

                    # Identify firewall
                    # 1. Determine the firewall_identifier
                    if raw_ip_match:
                        normalized_ip = ".".join(str(int(octet)) for octet in raw_ip_match.group(1).split("."))
                        firewall_identifier = normalized_ip
                        is_custom_fw = False
                    elif fw_name_match:
                        firewall_identifier = fw_name_match.group(1)
                        is_custom_fw = True
                    else:
                        firewall_identifier = mdb_file.name
                        is_custom_fw = False

                    # 2. THEN safely check if we want to include firewall type
                    if not is_custom_fw:
                        raw_type = client_fw_type_map.get(client, {}).get(firewall_identifier, "Unknown")
                        fw_type = fw_type_normalization.get(raw_type.strip(), raw_type)
                        identifier_with_type = f"{firewall_identifier} ({fw_type})"
                    else:
                        identifier_with_type = firewall_identifier

                    # Get IPs if it's a custom-named firewall
                    custom_fw_ips = []
                    if is_custom_fw:
                        try:
                            cursor.execute("SELECT Firewall FROM Firewalls")
                            custom_fw_ips = list({
                                ".".join(str(int(octet)) for octet in row[0].split(".")) for row in cursor.fetchall()
                            })

                        except Exception as exception:
                            custom_fw_ips = [f"Error retrieving IPs: {str(exception)}"]

                    # Run logging conditions query
                    conditions_query = f"""
                        SELECT 'Inbound Traffic' FROM {traffic_summary_table} WHERE Direction = 'I'
                        UNION SELECT 'Outbound Traffic' FROM {traffic_summary_table} WHERE Direction = 'O'
                        UNION SELECT 'Traffic Size' FROM {traffic_summary_table} WHERE Bytes >= 10
                        UNION SELECT 'Allowed Traffic' FROM {traffic_summary_table} WHERE Allowed = 'A'
                        UNION SELECT 'Denied Traffic' FROM {traffic_summary_table} WHERE Allowed = 'D'
                    """

                    logger.info("Executing query!")
                    cursor.execute(conditions_query)
                    conditions_found = cursor.fetchall()

                    found_conditions = []
                    if conditions_found:
                        found_conditions = [condition[0] for condition in conditions_found]

                    # if is_custom_fw == False:
                    #     if check_debug_for_ip(folder_loc, firewall_identifier):
                    #         found_conditions.append("Debug Events")

                    # Step 2: Build state map and fill in expected keys
                    condition_states = {cond: True for cond in found_conditions}
                    for key in expected_conditions:
                        if key not in condition_states:
                            condition_states[key] = False

                    # Step 3: Compare actual vs expected
                    misconfigurations = []
                    for condition, expected_value in expected_conditions.items():
                        actual_value = condition_states[condition]
                        if actual_value != expected_value:
                            misconfigurations.append(
                                f"{condition}={'Yes' if actual_value else 'No'} (Expected: {'Yes' if expected_value else 'No'})")
                            
                    # Write condition summary
                    if len(misconfigurations) == 0:
                        status_line = f"{identifier_with_type}: Optimal!"
                        file.write(status_line + "\n")
                        print(status_line)
                    elif len(misconfigurations) == 5:
                        status_line = f"{identifier_with_type}: No Data! Outage or Failover?"
                        file.write(status_line + "\n")
                        print(status_line)
                    else:
                        status_line = f"{identifier_with_type}:"
                        file.write(status_line + "\n")
                        print(status_line)

                        # Calculate alignment length based on the status line
                        alignment_space = " " * 5

                        for mis in misconfigurations:
                            aligned_line = f"{alignment_space}{mis}"
                            file.write(aligned_line + "\n")
                            print(aligned_line)

                    # Assign severity based on logic
                    if len(found_conditions) == 0:
                        severity = "ERROR"
                    elif len(misconfigurations) > 0:
                        severity = "WARNING"
                    else:
                        severity = "INFO"

                    # Log severity level
                    if severity == "INFO":
                        logger.info(status_line)
                    elif severity == "WARNING":
                        logger.warning(status_line)
                    elif severity == "ERROR":
                        logger.error(status_line)


                    if custom_fw_ips:
                        formatted_ips = ", ".join(custom_fw_ips)
                        file.write(f"     IPs in network: {formatted_ips} (DO NOT INCLUDE IN CLIENT COMMUNICATIONS!)\n")
                        
                        print(f"     IPs in network: {formatted_ips} (DO NOT INCLUDE IN CLIENT COMMUNICATIONS!)")
                        logger.info(f"{identifier_with_type} IPs in network: {formatted_ips} (DO NOT INCLUDE IN CLIENT COMMUNICATIONS!)")

                    cursor.close()
                    conn.close()
                    logger.info(f"Closed connection to {mdb_file.name}")

                except Exception as exception:
                    error_msg = f"Error processing {mdb_file.name}: {str(exception)}"
                    results[mdb_file.name] = [f"Error: {str(exception)}"]
                    file.write(f"{error_msg}\n")
                    logger.critical(error_msg)

            if not found_mdb_file:
                logger.warning(f"No .mdb files found for {client}")
                file.write(f"No .mdb files found for {client}!\n")
                print(f"No .mdb files found for {client}!\n")

    logger.info("Script has finished running! All client folders have been processed.")

# ========================== EXECUTION ==========================
mode, specific_client = get_mode_selection()
check_ALL_fw_logging_levels(mode, specific_client)
