#!/usr/bin/env bash
# Stands in for `journalctl --follow --output=json`: prints the journal
# fixture, then keeps following (waits) like the real command.
while IFS= read -r line; do
  printf '%s\n' "$line"
done < "$(dirname "$0")/../journal.json"
exec sleep 600
