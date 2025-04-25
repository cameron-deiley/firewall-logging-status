# Firewall Logging Script
##### This script has been developed with the purpose of keeping better track of the current status of our client's firewalls. The script has the following functionality:

Iterates through client folder and grabs all summary firewall database files and checks if any of them are missing any of the following conditions:
1. Traffic direction (Inbound + Outbound), size, permission (allowed/denied), debug events (too much info)
2. Prints out failover pairs for each client
3. Can be ran on one client or across all clients
4. Shows vendor of FW for easier troubleshooting

