import pyodbc
from pathlib import Path
from datetime import datetime, timedelta
import re
import os
import json

# Define global paths
client_path = Path('D:/Clients')
client_name_exceptions_file = Path('D:\Temp\Analysts\Julian\Script_Source\ClientExclusions.txt')
local_output_dir = Path("D:/Temp/Analysts/Cam/Threat Engineering/FW Script Outputs")


# Define constants
the_folder = "Input"
folder_date = (datetime.now() - timedelta(days=1)).strftime("%Y%m%d")
traffic_summary_table = "TrafficSummary"

client_name_exceptions = []
def import_client_exceptions(exceptions_file):
    """Reads the exclusion file and stores folder names to skip."""
    if exceptions_file.exists():
        with open(exceptions_file, 'r', errors='ignore') as f:
            for line in f:
                line_corrected = line.strip()
                if line_corrected and line_corrected not in client_name_exceptions:
                    client_name_exceptions.append(line_corrected)
import_client_exceptions(client_name_exceptions_file)

def get_all_folders(directory):
    """
    Returns a list of folder names in the given directory.
    """
    return [folder.name for folder in Path(directory).iterdir() if folder.is_dir()]
the_clients = get_all_folders(client_path)

def check_fw_levels():
    print("Script has started running...\n")
    results = {}

    # Generate a timestamp and path for the output file
    timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M")
    output_file = local_output_dir / f"FW_settings_script_{timestamp}.txt"

    # Ensure output directory exists
    local_output_dir.mkdir(parents=True, exist_ok=True)

    with output_file.open("w", encoding="utf-8") as file:
        file.write(f"Firewall Settings Search Results - {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
        file.write(f"Checking FW logging for traffic direction, size, allowed/denied...\n")
        file.write("=" * 50 + "\n")

        for client_folder in client_path.iterdir():
            if not client_folder.is_dir():
                continue  # Skip non-folder items

            if client_folder.name in client_name_exceptions:
                print(f"Skipping excluded folder: {client_folder.name}")
                file.write(f"Skipping excluded folder: {client_folder.name}\n")
                continue  # Move to the next folder

            client = client_folder.name  # Fix: Use current folder name directly
            folder_loc = Path(client_path) / client / "Source" / folder_date / the_folder
            print(f"Checking client folder: {folder_loc}")

            if not folder_loc.exists():
                warning_msg = f"Warning: Folder path '{folder_loc}' does not exist. Please investigate this!"
                print(warning_msg.strip())
                file.write("\n" + warning_msg + "\n")
                continue  # Skip if folder does not exist

            custom_fw_names = ["BRANCH", "CORPORATE", "CITYHALL", "CORP", "FIREDEPARTMENT",
                               "GUEST", "PCI", "REMOTE", "SCADA", "SCHOOLS", "SEWERPLANT", 
                               "STUDENT", "SYSMON"]
            regex_fw_pattern = "|".join(map(re.escape, custom_fw_names))
            patterns = [r"^\d{4}-\d{2}-\d{2}-\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}-Summary-firewall\.mdb$",
                        fr"^\d{{4}}-\d{{2}}-\d{{2}}-({regex_fw_pattern})-Summary-firewall\.mdb$"]

            file.write(f"\nProcessing: {folder_loc}\n")

            found_mdb_file = False
            if folder_loc.exists():  # Fix: Ensure folder exists before iterating
                for db_file in folder_loc.iterdir():
                    if any(re.search(pattern, db_file.name, re.IGNORECASE) for pattern in patterns):
                        found_mdb_file = True
                        db_path = folder_loc / db_file
                        
                        try:
                            print(f"Attempting to connect to: {db_file}")
                            conn = pyodbc.connect(rf"DRIVER={{Microsoft Access Driver (*.mdb, *.accdb)}};DBQ={db_path};")
                            cursor = conn.cursor()
                            print(f"Successfully connected to {folder_loc}")

                            query = f"""
                                SELECT 'Inbound Traffic' FROM {traffic_summary_table} WHERE Direction = 'I';
                                UNION
                                SELECT 'Outbound Traffic' FROM {traffic_summary_table} WHERE Direction = 'O';
                                UNION
                                SELECT 'Traffic Size' FROM {traffic_summary_table} WHERE Bytes >= 10;
                                UNION
                                SELECT 'Allowed Traffic' FROM {traffic_summary_table} WHERE Allowed = 'A';
                                UNION
                                SELECT 'Denied Traffic' FROM {traffic_summary_table} WHERE Allowed = 'D'
                            """

                            print(f"Executing query on {folder_loc}...")
                            cursor.execute(query)

                            matches = cursor.fetchall()

                            if matches:
                                conditions = [match[0] for match in matches]
                                results[db_file.name] = conditions

                                print(f"Conditions found for {db_file.name}: {', '.join(conditions)}")
                                missing_conditions = []
                                expected_conditions = ["Traffic Size", "Inbound Traffic", "Outbound Traffic", "Allowed Traffic", "Denied Traffic"]

                                for condition in expected_conditions:
                                    if condition not in conditions:
                                        missing_conditions.append(condition)

                                if missing_conditions:
                                    file.write(f"{db_file.name}: Missing Conditions: {', '.join(missing_conditions)}\n")
                                else:
                                    file.write(f"{db_file.name}: All expected logging conditions met!\n")

                            else:
                                results[db_file.name] = ["No Matching Condition"]
                                file.write(f"{db_file.name}: Review firewall logging! No traffic seen! \n")
                                print(f"No matching conditions found for {db_file.name}")

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
                file.write(f"No .mdb files found for {client}\n")

    print("\n Script has finished running! All client folders have been processed.")

check_fw_levels()