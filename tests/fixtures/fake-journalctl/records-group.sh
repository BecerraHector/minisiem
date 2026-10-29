#!/usr/bin/env bash
# Stands in for a journalctl that exits with an error on Ctrl+C. Records its
# process group in $FAKE_JOURNALCTL_MARKER first, so a test can check which
# group a terminal's Ctrl+C would reach.
# Field index 4 of /proc/<pid>/stat (the 5th field) is the process group.
# Splitting on spaces is safe because the process name (bash) has none.
read -r -a stat < "/proc/$$/stat"
echo "${stat[4]}" > "$FAKE_JOURNALCTL_MARKER.tmp"
mv "$FAKE_JOURNALCTL_MARKER.tmp" "$FAKE_JOURNALCTL_MARKER"
trap 'echo "interrupted" >&2; exit 1' INT
while :; do
  sleep 0.05
done
