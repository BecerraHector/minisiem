#!/usr/bin/env bash
# Stands in for a journalctl that exits with an error on Ctrl+C, and records
# in $FAKE_JOURNALCTL_MARKER that the interrupt reached it.
trap 'touch "$FAKE_JOURNALCTL_MARKER"; echo "interrupted" >&2; exit 1' INT
while :; do
  sleep 0.05
done
