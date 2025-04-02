import re
from pathlib import Path
from datetime import datetime

# Combined regex: matches "192.168.1.1 Firewall"
ip_with_firewall_pattern = re.compile(r"(\d{1,3}(?:\.\d{1,3}){3})\s+Firewall", re.IGNORECASE)


def get_outages(
    outage_dir: Path,
    timestamp: str = None,
    hours_to_try = ["07", "08", "09", "10", "11", "12"]
) -> dict:
    """
    Locates the most recent outage file and returns a dictionary of outages.

    Args:
        outage_dir (Path): Directory containing outage log files.
        timestamp (str): Optional timestamp string in format "YYYY-MM-DD-HH-MM".
                         If None, current time is used.
        hours_to_try (list): List of hour strings to search across.

    Returns:
        dict: { client_name: [list of firewall IPs with outages] }
    """
    if not timestamp:
        timestamp = datetime.now().strftime("%Y-%m-%d-%H-%M")

    base_date = timestamp[:10]
    outage_file = _locate_most_recent_outage_file(base_date, hours_to_try, outage_dir)
    return _parse_outage_file(outage_file)


def _locate_most_recent_outage_file(base_date, hours_to_try, outage_dir):
    most_recent_file = None
    latest_mtime = 0

    for hour in hours_to_try:
        pattern = f"{base_date}-{hour}-??_Syslog_Cloud_Outages.txt"
        for file in outage_dir.glob(pattern):
            mtime = file.stat().st_mtime
            if mtime > latest_mtime:
                most_recent_file = file
                latest_mtime = mtime

    return most_recent_file


def _parse_outage_file(file_path):
    client_outages = {}

    if file_path and file_path.exists():
        with file_path.open("r", encoding="utf-8", errors="ignore") as file:
            lines = [line.strip() for line in file if line.strip()]
            line_index = 0

            while line_index < len(lines) - 1:
                client_name = lines[line_index]
                firewall_line = lines[line_index + 1]

                match = ip_with_firewall_pattern.search(firewall_line)
                if match:
                    firewall_ip = match.group(1)
                    if client_name not in client_outages:
                        client_outages[client_name] = []
                    if firewall_ip not in client_outages[client_name]:
                        client_outages[client_name].append(firewall_ip)
                line_index += 2
    return client_outages

