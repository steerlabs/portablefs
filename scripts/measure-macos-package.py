#!/usr/bin/env python3
"""Conservative logical-size bounds; excludes retained user-data growth."""
import json
import pathlib
import sys
archive, app = map(pathlib.Path, sys.argv[1:])
# Installation retains the extracted source app while staging a second new
# copy. Update additionally retains the displaced old app until activation.
expanded = sum(p.stat().st_size for p in app.rglob('*') if p.is_file())
compressed = archive.stat().st_size
print(json.dumps(dict(compressed_installer_bytes=compressed, expanded_app_bytes=expanded,
    peak_extraction_bytes=compressed + expanded,
    peak_initial_install_bytes=compressed + 2 * expanded,
    peak_same_size_update_bytes=compressed + 3 * expanded,
    additional_free_bytes=compressed + 2 * expanded + (2 << 30)), indent=2))
