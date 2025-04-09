import pyodbc
from pathlib import Path
from datetime import datetime, timedelta
import re
import json

# ========================== VARIABLE CONFIG ==========================
default_folder_date = (datetime.now() - timedelta(days=1)).strftime("%Y%m%d")
current_date = datetime.now().strftime("%Y%m%d")
the_folder = "Input"
traffic_summary_table = "TrafficSummary"
# FW_table 
timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M")
ip_regex_pattern = re.compile(r"(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})")
ip_with_firewall_pattern = re.compile(r"(\d{1,3}(?:\.\d{1,3}){3})\s+Firewall", re.IGNORECASE)

# ========================== PATH CONFIG ==========================
clients_folder = Path('D:/Clients')
client_name_exceptions_file = Path('D:/Temp/Analysts/Julian/Script_Source/ClientExclusions.txt')
local_output_dir = Path("D:/Temp/Analysts/Cam/Threat Engineering/FW Script Outputs")
failover_data_file = Path("D:/Temp/Analysts/Cam/Threat Engineering/firewall_failovers.txt")
outage_script_filename = f"{timestamp}_Syslog_Cloud_Outages.txt"
outage_script_results_dir = Path("D:/Temp/Analysts/Julian/DataCollection/Outages")
outage_script_file = outage_script_results_dir/outage_script_filename

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
# add url checking (regex match?) on syslog.txt files
# firewall type (regex match?) on syslog.txt files
# print IPs from FW tables in DB with queries

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

# ========================== MAIN FUNCTION ==========================
def check_ALL_fw_logging_levels(mode="all", specific_client=None):
    print("Script has started running...\n")
    results = {}
    printed_clients = set()

    # Load client exclusions and outages
    client_name_exceptions = load_excluded_clients(client_name_exceptions_file)

    # Load failover pairs
    failover_pairs = {}
    if failover_data_file.exists():
        with failover_data_file.open("r", encoding="utf-8") as file:
            failover_pairs = json.load(file)
    #print(failover_pairs)

    # Bidirectional lookup for failover pairs
    failover_lookup = {}
    for client, (primary, secondary) in failover_pairs.items():
        failover_lookup[primary] = secondary
        failover_lookup[secondary] = primary

    # Prepare output
    if specific_client:
        output_filename = f"FW_settings_script_{specific_client}_{timestamp}.txt"
    else:
        output_filename = f"FW_settings_script_all_{timestamp}.txt"
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
                print(f"Skipping excluded folder: {client_folder.name}\n")
                file.write(f"\nSkipping excluded folder: {client_folder.name}\n")
                continue

            client = client_folder.name
            folder_date = current_date if client == "RepublicofPalau" else default_folder_date
            folder_loc = client_folder / "Source" / folder_date / the_folder

            print(f"\nChecking client folder: {folder_loc}")
            if not folder_loc.exists():
                warning_msg = f"Warning: Folder path '{folder_loc}' does not exist. Please investigate this!"
                print(warning_msg.strip())
                file.write("\n" + warning_msg + "\n")
                continue

            # Start writing to output file
            print(f"Processing: {client}\n")
            file.write(f"\nProcessing: {client}\n")

            # Write failover pairs for client if detected by other script
            if client in failover_pairs and client not in printed_clients:
                primary, secondary = failover_pairs[client]
                file.write(f"Failover Pair: {primary} -> {secondary}\n")
                printed_clients.add(client)
            file.write("-" * 50 + "\n")

            found_mdb_file = False
            for db_file in folder_loc.iterdir():
                db_file_str = str(db_file)
                found_mdb_file = True
                db_path = folder_loc / db_file
                
                # Match IP first -> FW name if no IP is found
                fw_ip_pattern = re.search(r"(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})", db_file_str)
                fw_name_pattern = re.search(fr"({regex_fw_pattern})", db_file_str)
                if fw_ip_pattern:
                    zero_padded_ip = fw_ip_pattern.group(1)
                    non_zero_padded_ip = ".".join(str(int(octet)) for octet in zero_padded_ip.split("."))
                elif fw_name_pattern:
                    non_zero_padded_ip = fw_name_pattern.group(1)
                else:
                    non_zero_padded_ip = db_file_str

                if not any(re.search(pattern, db_file.name, re.IGNORECASE) for pattern in mdb_filename_patterns):
                    continue
                try:
                    print(f"Attempting to connect to {db_file.name}")
                    
                    conn = pyodbc.connect(rf"DRIVER={{Microsoft Access Driver (*.mdb, *.accdb)}};DBQ={db_path};")
                    cursor = conn.cursor()

                    print(f"Successfully connected! ")
                    conditions_query = f"""
                        SELECT 'Inbound Traffic' FROM {traffic_summary_table} WHERE Direction = 'I'
                        UNION SELECT 'Outbound Traffic' FROM {traffic_summary_table} WHERE Direction = 'O'
                        UNION SELECT 'Traffic Size' FROM {traffic_summary_table} WHERE Bytes >= 10
                        UNION SELECT 'Allowed Traffic' FROM {traffic_summary_table} WHERE Allowed = 'A'
                        UNION SELECT 'Denied Traffic' FROM {traffic_summary_table} WHERE Allowed = 'D'
                    """

                    print(f"Executing query!")
                    cursor.execute(conditions_query)
                    matches = cursor.fetchall()

                    # Writing of missing conditions to file
                    if matches:
                        conditions = [match[0] for match in matches]
                        results[db_file.name] = conditions

                        print(f"Conditions found: {', '.join(conditions)}")
                        missing_conditions = [cond for cond in expected_conditions if cond not in conditions]

                        if missing_conditions:
                            file.write(f"{non_zero_padded_ip}: Missing Conditions: {', '.join(missing_conditions)}\n")
                        else:
                            file.write(f"{non_zero_padded_ip}: All expected logging conditions met!\n")

                        
                    else:
                        results[db_file.name] = ["No Matching Condition"]
                        file.write(f"{non_zero_padded_ip}: No data in summary DB = potential outage! \n")
                        print(f"No matching conditions found for {non_zero_padded_ip}")

                    cursor.close()
                    conn.close()
                    print(f"Closed connection to {db_file.name}")

                except Exception as e:
                    error_msg = f"Error processing {db_file.name}: {str(e)}"
                    results[db_file.name] = [f"Error: {str(e)}"]
                    file.write(f"{error_msg}\n")
                    print(error_msg)

            if not found_mdb_file:
                print(f"No .mdb files found for {client}")
                file.write(f"No .mdb files found!\n")

    print("\nScript has finished running! All client folders have been processed.")

# ========================== EXECUTION ==========================
mode, specific_client = get_mode_selection()
check_ALL_fw_logging_levels(mode, specific_client)
