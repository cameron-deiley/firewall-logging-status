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
    "Fortinet": re.compile(r"msg=.*? action=.*? src=.*? dst=.*?", re.IGNORECASE),
    "PaloAlto": re.compile(r"TRAFFIC.*?source=.*?destination=.*?", re.IGNORECASE),
    "Juniper": re.compile(r"<\d+>.*?RT_FLOW.*?", re.IGNORECASE),
    "Cisco ASA": re.compile(r"%ASA-\d+-\d+: .*?", re.IGNORECASE),
    "SonicWall": re.compile(r"MsgID=\d+;.*?Category=.*?; Priority=.*?;", re.IGNORECASE),
    "WatchGuard": re.compile(r"Firebox.*?Allow.*?tcp.*?->", re.IGNORECASE),
}

# ========================= FEATURES TO WORK ON =======================
# Add url checking (regex match?) on syslog.txt files
# Firewall type (regex match?) on syslog.txt files -> Reworking this to reflect features of Chatty convo but direct implementation in current script
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

def detect_firewall_type(syslog_path: Path, max_lines=500):
    if not syslog_path.exists():
        return "File Not Found"

    try:
        with syslog_path.open("r", encoding="utf-8", errors="ignore") as f:
            for _ in range(max_lines):
                line = f.readline()
                if not line:
                    break
                for fw_type, pattern in firewall_syntax_patterns.items():
                    if pattern.search(line):
                        return fw_type
        return "Unknown"
    except Exception as e:
        return f"Error: {str(e)}"

def generate_firewall_type(clients_folder: Path, folder_Date: str, the_folder: str, output_path: Path):
    firewall_results = {}

    for client_folder in clients_folder.iterdir():
        if not client_folder.is_dir():
            continue

        client_name = client.folder.name
        input_folder = client_folder/"Source"/folder_date/the_folder

        # Get syslog file in folder
        syslog_file = None
        for file in input_folder.glob("*-Syslog.txt"):
            syslog_file = file
            break
        
        if syslog_file:
            fw_type = detect_firewall_type(syslog_file)
        else:
            fw_type = "No Syslog Found"

        firewall_results[client_name] = fw_type

    # Save results
    with output_path.open("w", encoding="utf-8") as f:
        for client, fw_type in firewall_results.items():
            f.write(f"{client}: {fw_type}\n")

    print(f"Firewall type mapping written to {output_path}")
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
            print(f"Processing: {client}")

            logger.info(f"Checking client folder: {folder_loc}")
            if not folder_loc.exists():
                warning_msg = f"Warning: Folder path '{folder_loc}' does not exist. Please investigate this!"
                print(warning_msg.strip())
                logger.warning(warning_msg)
                file.write("\n" + warning_msg + "\n")
                continue

            # Write failover pairs for client with results from failover script
            if client in failover_pairs and client not in printed_clients:
                primary, secondary = failover_pairs[client]
                file.write(f"Failover Pair: {primary} -> {secondary}\n")
                printed_clients.add(client)
            file.write("-" * 50 + "\n")

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
                    try:
                        conn = pyodbc.connect(rf"DRIVER={{Microsoft Access Driver (*.mdb, *.accdb)}};DBQ={db_path};")
                        cursor = conn.cursor()
                        cursor.execute("SELECT * FROM Firewalls WHERE Firewall = ?", (fw_name,))
                        cursor.close()
                        conn.close()
                        custom_network_ips = [row[0] for row in cursor.fetchall()]
                        print(custom_network_ips)
                        ips_to_write = [
                        ".".join(str(int(octet)) for octet in ip.split(".")) for ip in custom_network_ips
                        ]
                    except Exception as e:
                        ips_to_write = [f"Error retrieving IPs: {str(e)}"]
                else:
                    firewall_identifier = db_file_str

                try:
                    logger.info(f"Attempting to connect to {mdb_file.name}")
                    conn = pyodbc.connect(rf"DRIVER={{Microsoft Access Driver (*.mdb, *.accdb)}};DBQ={db_path};")
                    cursor = conn.cursor()
                    logger.info(f"Successfully connected to {mdb_file.name}! ")
                    
                    conditions_query = f"""
                        SELECT 'Inbound Traffic' FROM {traffic_summary_table} WHERE Direction = 'I'
                        UNION SELECT 'Outbound Traffic' FROM {traffic_summary_table} WHERE Direction = 'O'
                        UNION SELECT 'Traffic Size' FROM {traffic_summary_table} WHERE Bytes >= 10
                        UNION SELECT 'Allowed Traffic' FROM {traffic_summary_table} WHERE Allowed = 'A'
                        UNION SELECT 'Denied Traffic' FROM {traffic_summary_table} WHERE Allowed = 'D'
                    """

                    logger.info(f"Executing query!")
                    cursor.execute(conditions_query)
                    conditions_found = cursor.fetchall()
                    # Writing of missing conditions to file
                    if conditions_found:
                        conditions = [condition[0] for condition in conditions_found]
                        results[mdb_file.name] = conditions
                        logger.info(f"Conditions found: {', '.join(conditions)}")
                        missing_conditions = [condition for condition in expected_conditions if condition not in conditions]

                        if not missing_conditions:
                            severity = "INFO"
                            status_line = f"{firewall_identifier}: All Conditions!"
                            file.write(status_line + "\n")
                            print(status_line)
                        else:
                            severity = "WARNING"
                            status_line = f"{firewall_identifier}: Missing Conditions: {', '.join(missing_conditions)}"
                            file.write(status_line + "\n")
                            print(status_line)

                        # if missing_conditions:
                        #     file.write(f"{firewall_identifier}: Missing Conditions: {', '.join(missing_conditions)}\n")
                        # else:
                        #     file.write(f"{firewall_identifier}: All expected logging conditions met!\n"

                        # if ips_to_write and normalized_ip and normalized_ip in ips_to_write:
                        #     print(f"    IPs in network: {', '.join(custom_network_ips)}\n")
                        #     file.write(f"    IPs in network: {', '.join(custom_network_ips)}\n")

                    else:
                        conditons = []
                        results[mdb_file.name] = "No Matching Conditions"
                        severity = "ERROR"
                        status_line = f"{firewall_identifier}: No Conditions! Potential outage or failover FW!"

                        file.write(status_line + "\n")
                        print(status_line)
                        
                        if severity == "INFO":
                            logger.info(status_line)
                        elif severity == "WARNING":
                            logger.warning(status_line)
                        elif severity == "ERROR":
                            logger.error(status_line)
                        
                        # results[mdb_file.name] = ["No Matching Condition"]
                        # file.write(f"{firewall_identifier}: No data in summary DB = potential outage! \n")
                        # logger.warning(f"No matching conditions found for {firewall_identifier}")

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
