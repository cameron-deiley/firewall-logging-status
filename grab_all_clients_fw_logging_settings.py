import pyodbc
from pathlib import Path
from datetime import datetime, timedelta
import re
import json
import logging

# ========================== PATH CONFIG ==========================
clients_folder = Path('D:/Clients')
client_name_exceptions_file = Path('D:/Temp/Analysts/Julian/Script_Source/ClientExclusions.txt')
local_output_dir = Path("D:/Temp/Analysts/Cam/Threat Engineering/FW Script Outputs")
failover_data_file = Path("D:/Temp/Analysts/Cam/Threat Engineering/firewall_failovers.txt")

# ========================== VARIABLE CONFIG ==========================
timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M")
ip_regex_pattern = re.compile(r"(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})")
default_folder_date = (datetime.now() - timedelta(days=1)).strftime("%Y%m%d")
current_date = datetime.now().strftime("%Y%m%d")
the_folder = "Input"
traffic_summary_table = "TrafficSummary"
client = clients_folder.name
folder_date = current_date if client == "RepublicofPalau" else default_folder_date
folder_loc = None
db_path = None
output_file = None
log_file_path = local_output_dir / f"FW_logging_{timestamp}.log"

# ========================== FIREWALL MATCHING ==========================
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

# ========================== CHECK CRITERIA ==========================
expected_conditions = [
    "Traffic Size", "Inbound Traffic", "Outbound Traffic", 
    "Allowed Traffic", "Denied Traffic"
]

firewall_syntax_patterns = {
    "WatchGuard": re.compile(r"firebox|Allow:|Block:", re.IGNORECASE),
    "Fortinet": re.compile(r"srcip=", re.IGNORECASE),
    "SonicWall": re.compile(r"msg=", re.IGNORECASE),
    "PaloAlto": re.compile(r"TRAFFIC,", re.IGNORECASE),
    "Barracuda": re.compile(r"barracuda", re.IGNORECASE),
    "Cisco ASA": re.compile(r"%ASA-", re.IGNORECASE),
    "Cisco Firepower": re.compile(r"SFIMS:", re.IGNORECASE),
    "Cyberoam": re.compile(r"cyberoam", re.IGNORECASE),
    "Cisco PIX": re.compile(r"%PIX-", re.IGNORECASE),
    "Checkpoint": re.compile(r"action=", re.IGNORECASE)
}


# ========================= FEATURES TO WORK ON =======================
# Add url checking (regex match?) on syslog.txt files
# Firewall type (regex match?) on syslog.txt files -> Work on matching syslog syntax with Jaehee
# Print IPs from FW tables in DB with queries
# Add check if we are getting "debug" events (WE DO NOT WANT THOSE), tricky dependant on FW
# Move the second "Firewalls" query to the same connection as "conditions_query"
# Add auto-filling client name feature to help with client lookup + input validation
# Detect different AV products through logs

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

def get_mode_selection():
    mode = input("Check all clients or a specific one? (all/one): ").strip().lower()
    if mode == "one":
        client = input("Enter the name of the client folder as it appears in the LP: ").strip()
        return mode, client
    return mode, None

def get_folder_loc(client_folder, folder_date):
    return client_folder/"Source"/folder_date/the_folder

def get_db_path(folder_loc, mdb_file):
    return folder_loc/mdb_file

def get_output_file(specific_client, timestamp, local_output_dir):
    if specific_client:
        filename = f"FW_settings_script_{specific_client}_{timestamp}.txt"
    else:
        filename = f"FW_settings_script_all_{timestamp}.txt"
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

def detect_all_firewall_types(clients_folder: Path, folder_date: str, the_folder: str) -> dict:
    firewall_results = {}

    for client_folder in clients_folder.iterdir():
        if not client_folder.is_dir():
            continue

        client_name = client_folder.name
        input_folder = client_folder / "Source" / folder_date / the_folder
        syslog_file = next(input_folder.glob("*-Syslog.txt"), None)

        if syslog_file and syslog_file.exists():
            try:
                with syslog_file.open("r", encoding="utf-8", errors="ignore") as file:
                    for _ in range(500):  # Read up to 500 lines
                        line = file.readline()
                        if not line:
                            break
                        for fw_type, pattern in firewall_syntax_patterns.items():
                            if pattern.search(line):
                                firewall_results[client_name] = fw_type
                                break
                        if client_name in firewall_results:
                            break
                if client_name not in firewall_results:
                    firewall_results[client_name] = "Unknown"
            except Exception as e:
                firewall_results[client_name] = f"Error: {str(e)}"
        else:
            firewall_results[client_name] = "No Syslog Found"

    return firewall_results

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

    # Load FW types
    firewall_type_map = detect_all_firewall_types(clients_folder, folder_date, the_folder)

    # Load failover pairs
    if failover_data_file.exists():
        with failover_data_file.open("r", encoding="utf-8") as file:
            failover_pairs = json.load(file)
    #print(failover_pairs)

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
            if client in client_name_exceptions:
                logger.info(f"Skipping excluded folder: {client}\n")
                file.write(f"\nSkipping excluded folder: {client}\n")
                continue
            
            global folder_loc
            folder_loc = get_folder_loc(client_folder, folder_date)

            # Start writing to output file
            logger.info(f"Processing: {client}")
            file.write(f"\nProcessing: {client}\n")
            print(f"\nProcessing: {client}")

            logger.info(f"Checking client folder: {folder_loc}")
            if not folder_loc.exists():
                print(f"Warning: Folder path '{folder_loc}' does not exist. Please investigate this!\n")
                logger.warning(f"Warning: Folder path '{folder_loc}' does not exist. Please investigate this!")
                file.write(f"Warning: Folder path '{folder_loc}' does not exist. Please investigate this!\n")
                continue

            # Write failover pairs for client with results from failover script
            if client in failover_pairs and client not in printed_clients:
                primary, secondary = failover_pairs[client]
                file.write(f"Failover Pair: {primary} -> {secondary}\n")
                printed_clients.add(client)
            

            # Writing of FW types to output
            fw_type = firewall_type_map.get(client, "Unknown")
            file.write(f"Client FW Type: {fw_type}\n")
            print(f"Client FW Type: {fw_type}")
            if fw_type == "Unknown":
                logger.warning(f"Client FW Type: {fw_type}")
            else:
                logger.info(f"Client FW Type: {fw_type}")
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
                custom_network_ips = [] # Populated only when matching FW name
                ips_to_write = []       # List used for output writing

                if raw_ip_match:
                    normalized_ip = raw_ip_match.group(1)
                    normalized_ip = ".".join(str(int(octet)) for octet in normalized_ip.split("."))
                    firewall_identifier = normalized_ip  # Used downstream as the primary label
                elif fw_name_match:
                    fw_name = fw_name_match.group(1)
                    firewall_identifier = fw_name
                else:
                    firewall_identifier = db_file_str

                try:
                    logger.info(f"Attempting to connect to {mdb_file.name}")
                    conn = pyodbc.connect(rf"DRIVER={{Microsoft Access Driver (*.mdb, *.accdb)}};DBQ={db_path};")
                    cursor = conn.cursor()
                    logger.info(f"Successfully connected to {mdb_file.name}! ")

                    # Identify firewall
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

                    # Get IPs if it's a custom-named firewall
                    custom_fw_ips = []

                    if is_custom_fw:
                        try:
                            cursor.execute("SELECT Firewall FROM Firewalls")
                            custom_fw_ips = list({
                                ".".join(str(int(octet)) for octet in row[0].split(".")) for row in cursor.fetchall()
                            })

                        except Exception as e:
                            custom_fw_ips = [f"Error retrieving IPs: {str(e)}"]


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

                    if conditions_found:
                        conditions = [condition[0] for condition in conditions_found]
                        results[mdb_file.name] = conditions
                        logger.info(f"Conditions found: {', '.join(conditions)}")
                        missing_conditions = [c for c in expected_conditions if c not in conditions]

                        if not missing_conditions:
                            severity = "INFO"
                            status_line = f"{firewall_identifier}: All Conditions!"
                        else:
                            severity = "WARNING"
                            status_line = f"{firewall_identifier}: Missing Conditions: {', '.join(missing_conditions)}"
                    else:
                        results[mdb_file.name] = "No Matching Conditions"
                        severity = "ERROR"
                        status_line = f"{firewall_identifier}: No Conditions! Potential outage or failover FW!"

                    file.write(status_line + "\n")
                    print(status_line)

                    if custom_fw_ips:
                        formatted_ips = ", ".join(custom_fw_ips)
                        file.write(f"    IPs in network: {formatted_ips}\n")
                        print(f"    IPs in network: {formatted_ips}")
                        logger.info(f"{firewall_identifier} IPs in network: {formatted_ips}")

                    if severity == "INFO":
                        logger.info(status_line)
                    elif severity == "WARNING":
                        logger.warning(status_line)
                    elif severity == "ERROR":
                        logger.error(status_line)

                    cursor.close()
                    conn.close()
                    logger.info(f"Closed connection to {mdb_file.name}")

                except Exception as e:
                    error_msg = f"Error processing {mdb_file.name}: {str(e)}"
                    results[mdb_file.name] = [f"Error: {str(e)}"]
                    file.write(f"{error_msg}\n")
                    logger.critical(error_msg)

            if not found_mdb_file:
                logger.warning(f"No .mdb files found for {client}")
                file.write(f"No .mdb files found!\n")

    logger.info("Script has finished running! All client folders have been processed.")

# ========================== EXECUTION ==========================
mode, specific_client = get_mode_selection()
check_ALL_fw_logging_levels(mode, specific_client)
