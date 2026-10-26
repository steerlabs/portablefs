#!/usr/bin/env python3
"""Offline release coverage gate; source URLs do not satisfy this check."""
import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / 'deploy/linux-workspace'))
from redistribute import check

check(pathlib.Path(sys.argv[1]))
