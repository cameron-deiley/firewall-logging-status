import re
from pathlib import Path
from datetime import datetime

# Config
base_date = "2025-03-28"
hours_to_try = ["07", "08", "09", "10", "11", "12"]
outage_script_results_dir = Path("D:/Temp/Analysts/Julian/DataCollection/Outages")

# Regex patterns
ip_regex_pattern = re.compile(r"(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})")
ip_regex_with_firewall = re.compile(rf"{ip_regex_pattern.pattern}\s+Firewall", re.IGNORECASE)

# Locate the outage file based on known hour possibilities
def locate_outage_file():
    for hour in hours_to_try:
        pattern = f"{base_date}_{hour}-??_Syslog_Cloud_Outages.txt"
        matches = list(outage_script_results_dir.glob(pattern))
        if matches:
            print(f"Found outage file: {matches[0]}")
            return matches[0]
    print("No outage file found for the specified hours.")
    return None

# Parse the outage file
def find_outages(file_path):
    client_outages = {}

    if file_path and file_path.exists():
        with file_path.open("r", encoding="utf-8", errors="ignore") as file:
            lines = [line.strip() for line in file if line.strip()]
            line_index = 0

            while line_index < len(lines) - 1:
                client_name = lines[line_index]
                firewall_line = lines[line_index + 1]

                match = ip_regex_with_firewall.search(firewall_line)
                if match:
                    firewall_ip = match.group(1)
                    if client_name not in client_outages:
                        client_outages[client_name] = []
                    if firewall_ip not in client_outages[client_name]:
                        client_outages[client_name].append(firewall_ip)
                line_index += 2
    else:
        print("Outage file not found or not accessible.")
    return client_outages

# Run it
outage_file = locate_outage_file()
outages = find_outages(outage_file)
print(outages)
