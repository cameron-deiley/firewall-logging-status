import pyodbc
from pathlib import Path
from datetime import datetime, timedelta
import re
import json
import logging

# ========================== VARIABLE CONFIG ==========================
timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M")
default_folder_date = (datetime.now() - timedelta(days=1)).strftime("%Y%m%d")
current_date = datetime.now().strftime("%Y%m%d")
the_folder = "Input"
traffic_summary_table = "TrafficSummary"
client_name_exceptions_file = Path('D:/Temp/Analysts/Julian/Script_Source/ClientExclusions.txt')
local_output_dir = Path("D:/Temp/Analysts/Cam/Threat Engineering/FW Script Outputs")
failover_data_file = Path("D:/Temp/Analysts/Cam/Threat Engineering/firewall_failovers.txt")
clients_folder = Path('D:/Clients')

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

# ========================== HELPER FUNCTIONS ==========================
def load_excluded_clients(exceptions_file_path):
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
        client_names = sorted([f.name for f in clients_folder.iterdir() if f.is_dir()])
        print("\\nAvailable clients:")
        for name in client_names:
            print(f" - {name}")
        while True:
            client = input("Enter client name: ").strip()
            if client in client_names:
                return mode, client
            print("Invalid client. Try again.")
    return mode, None

# ========================== MAIN FUNCTION ==========================
def check_ALL_fw_logging_levels(mode="all", specific_client=None):
    logging.basicConfig(level=logging.DEBUG, format='%(asctime)s [%(levelname)s] - %(message)s', handlers=[
        logging.StreamHandler(),  # Print to console
        logging.FileHandler(local_output_dir / f"FW_logging_{timestamp}.log", mode='w', encoding="utf-8")  # Log to file
    ])

    logger = logging.getLogger()

    logger.info("Script has started running...\n")
    results = {}
    printed_clients = set()

    # Load client exclusions and failover pairs
    client_name_exceptions = load_excluded_clients(client_name_exceptions_file)

    failover_pairs = {}
    failover_lookup = {}
    if failover_data_file.exists():
        with failover_data_file.open("r", encoding="utf-8") as file:
            failover_pairs = json.load(file)
    for client, (primary, secondary) in failover_pairs.items():
        failover_lookup[primary] = secondary
        failover_lookup[secondary] = primary

    output_filename = f"FW_settings_script_{specific_client or 'all'}_{timestamp}.txt"
    output_file = local_output_dir / output_filename
    local_output_dir.mkdir(parents=True, exist_ok=True)

    with output_file.open("w", encoding="utf-8", buffering=1) as file:
        file.write(f"Firewall Settings Search Results - {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
        file.write(f"Checking FW logging status for {default_folder_date}\n")
        file.write("=" * 50 + "\n")

        for client_folder in clients_folder.iterdir():
            if not client_folder.is_dir():
                continue
            if specific_client and client_folder.name != specific_client:
                continue
            if client_folder.name in client_name_exceptions:
                logger.info(f"Skipping excluded folder: {client_folder.name}\n")
                file.write(f"\nSkipping excluded folder: {client_folder.name}\n")
                continue

            client = client_folder.name
            folder_date = current_date if client == "RepublicofPalau" else default_folder_date
            folder_loc = client_folder / "Source" / folder_date / the_folder

            logger.debug(f"Checking client folder: {folder_loc}")
            if not folder_loc.exists():
                warning_msg = f"Warning: Folder path '{folder_loc}' does not exist. Please investigate this!"
                logger.warning(warning_msg.strip())
                file.write("\n" + warning_msg + "\n")
                continue

            # Start writing to output file
            logger.debug(f"Processing: {client}")
            file.write(f"\nProcessing: {client}\n")

            # Write failover pairs for client if detected by the failover script
            if client in failover_pairs and client not in printed_clients:
                primary, secondary = failover_pairs[client]
                file.write(f"Failover Pair: {primary} -> {secondary}\n")
                printed_clients.add(client)
            file.write("-" * 50 + "\n")

            found_mdb_file = False
            for mdb_file in folder_loc.iterdir():
                db_file_str = str(mdb_file)

                if not any(re.search(pattern, mdb_file.name, re.IGNORECASE) for pattern in mdb_filename_patterns):
                    continue

                found_mdb_file = True
                db_path = folder_loc / mdb_file

                raw_ip_match = re.search(r"(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})", db_file_str)
                fw_name_match = re.search(fr"({regex_fw_pattern})", db_file_str)

                normalized_ip = None
                custom_network_ips = []  # Populated only when matching FW name
                ips_to_write = []  # List used for output writing

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
                        logger.debug(f"Custom network IPs: {custom_network_ips}")
                        ips_to_write = [
                            ".".join(str(int(octet)) for octet in ip.split(".")) for ip in custom_network_ips
                        ]
                    except Exception as e:
                        ips_to_write = [f"Error retrieving IPs: {str(e)}"]
                else:
                    firewall_identifier = db_file_str

                try:
                    logger.debug(f"Attempting to connect to {mdb_file.name}")
                    conn = pyodbc.connect(rf"DRIVER={{Microsoft Access Driver (*.mdb, *.accdb)}};DBQ={db_path};")
                    cursor = conn.cursor()

                    conditions_query = f"""
                        SELECT 'Inbound Traffic' FROM {traffic_summary_table} WHERE Direction = 'I'
                        UNION SELECT 'Outbound Traffic' FROM {traffic_summary_table} WHERE Direction = 'O'
                        UNION SELECT 'Traffic Size' FROM {traffic_summary_table} WHERE Bytes >= 10
                        UNION SELECT 'Allowed Traffic' FROM {traffic_summary_table} WHERE Allowed = 'A'
                        UNION SELECT 'Denied Traffic' FROM {traffic_summary_table} WHERE Allowed = 'D'
                    """

                    logger.debug(f"Executing query!")
                    cursor.execute(conditions_query)
                    conditions_found = cursor.fetchall()

                    if conditions_found:
                        conditions = [condition[0] for condition in conditions_found]
                        results[mdb_file.name] = conditions
                        missing_conditions = [condition for condition in expected_conditions if condition not in conditions]

                        if missing_conditions:
                            file.write(f"{firewall_identifier}: Missing Conditions: {', '.join(missing_conditions)}\n")
                        else:
                            file.write(f"{firewall_identifier}: All expected logging conditions met!\n")

                        if ips_to_write and normalized_ip and normalized_ip in ips_to_write:
                            file.write(f"    IPs in network: {', '.join(custom_network_ips)}\n")

                    else:
                        results[mdb_file.name] = ["No Matching Condition"]
                        file.write(f"{firewall_identifier}: No data in summary DB = potential outage! \n")

                    cursor.close()
                    conn.close()

                except Exception as e:
                    error_msg = f"Error processing {mdb_file.name}: {str(e)}"
                    results[mdb_file.name] = [f"Error: {str(e)}"]
                    file.write(f"{error_msg}\n")

            if not found_mdb_file:
                file.write(f"{firewall_identifier}: No .mdb files found!\n")

    logger.info("Script has finished running! All client folders have been processed.")

# ========================== EXECUTION ==========================
mode, specific_client = get_mode_selection()
check_ALL_fw_logging_levels(mode, specific_client)