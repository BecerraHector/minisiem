#!/usr/bin/env bash
# Stands in for journalctl run by a user who cannot read the system journal:
# it only warns and keeps following the user's own entries.
echo "Hint: You are currently not seeing messages from other users and the system." >&2
echo "      Users in groups 'adm', 'systemd-journal', 'wheel' can see all messages." >&2
exec sleep 600
