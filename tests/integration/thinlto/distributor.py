"""Runs the ThinLTO backend jobs from lld's DTLTO description in parallel on the local host.

Usage: distributor.py [launcher...] <jobs.json>
The launcher (e.g. sccache) is put in front of every backend compile command.
"""

import json
import os
import subprocess
import sys
from concurrent.futures import ThreadPoolExecutor

launcher = sys.argv[1:-1]
with open(sys.argv[-1]) as f:
    data = json.load(f)

common = launcher + data["common"]["args"]
with ThreadPoolExecutor(max_workers=os.cpu_count()) as pool:
    results = list(pool.map(lambda job: subprocess.call(common + job["args"]), data["jobs"]))
sys.exit(max(results, default=0))
