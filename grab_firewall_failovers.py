import json
import re
from pathlib import Path
from datetime import datetime, timedelta

# Define paths
failover_txt_file = Path("D:/Temp/Analysts/Cam/Threat Engineering/FW Settings/firewall-logging-status/firewall_failovers.txt")
client_path = Path("D:/Clients")

# Define folder date (yesterday)
folder_date = (datetime.now() - timedelta(days=1)).strftime("%Y%m%d")

# Dictionary to store failover FW mappings
failover_data = {}

# Regex pattern for matching format
failover_pattern = re.compile(r"FailoverFirewalls=\|([\d\.]+)\(([\d\.]+)\)\|")

# Go through each client folder
for client_folder in client_path.iterdir():
    if not client_folder.is_dir():
        continue

    # Construct expected file path -> nDiscovery.ini
    file_path = client_folder/"nDiscovery.ini"

    if file_path.exists():
        found_pair = False  # Track if a pair was found
        with file_path.open("r", encoding="utf-8", errors="ignore") as file:
            for line in file:
                pattern_match = failover_pattern.search(line)
                if pattern_match:
                    primary_fw = pattern_match.group(1)
                    secondary_fw = pattern_match.group(2)
                    
                    if primary_fw == "0.0.0.0" or secondary_fw == "0.0.0.0":
                        failover_data[client_folder.name] = "No pairs detected"
                    else:
                        failover_data[client_folder.name] = f"{primary_fw}, {secondary_fw}"
                        found_pair = True
        
        if not found_pair:
            failover_data[client_folder.name] = "No pairs detected"

# Save mappings to output file
with failover_txt_file.open("w", encoding="utf-8") as output_file:
    json.dump(failover_data, output_file, indent=4)


