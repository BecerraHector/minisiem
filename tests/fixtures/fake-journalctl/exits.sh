#!/usr/bin/env bash
# Stands in for a journalctl that stops (e.g. journald restarted or crashed).
echo "Failed to iterate through journal: Bad message" >&2
exit 1
