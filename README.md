# Firewall Logging Script

#### This script has been developed with the purpose of keeping better track of the current status of our client's firewalls. As of right now, the script has the following functionality:

* Iterates through client folder and grabs all summary firewall database files and checks if any of them are missing any of the following conditions:
    1. Traffic direction (Inbound + Outbound)
    2. Traffic size
    3. Traffic permission (Are we logging both allowed/denied traffic?)
  
Features to come in the future:
1. Tracking and verification of client's failover FW pairs
2. Eliminating false positives due to outages by checking against the outage script
