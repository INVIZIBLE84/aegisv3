#!/usr/bin/env python3
"""
demo_ransomware.py - Safe ransomware simulation for testing Aegis-LX
======================================================================
Creates fake files in /tmp, "encrypts" them (writes random bytes),
then deletes originals. Mimics exactly what ransomware does.
Safe: only touches /tmp/aegis_ransom_test/ directory.

Usage: python3 demo_ransomware.py
"""

import os
import random
import time

TEST_DIR = "/tmp/aegis_ransom_test"

def setup():
    os.makedirs(TEST_DIR, exist_ok=True)
    print("[DEMO] Creating 30 fake victim files in " + TEST_DIR)
    for i in range(30):
        fp = os.path.join(TEST_DIR, "document_%03d.txt" % i)
        with open(fp, "w") as f:
            f.write("This is a normal document with readable text. " * 50)
    print("[DEMO] Files created. Starting encryption simulation in 3 seconds...")
    time.sleep(3)

def simulate_encryption():
    print("[DEMO] Simulating ransomware encryption...")
    files = [os.path.join(TEST_DIR, f) for f in os.listdir(TEST_DIR)]
    for fp in files:
        # Read original (triggers openat)
        with open(fp, "rb") as f:
            _ = f.read()
        # Write "encrypted" version (high entropy random bytes)
        enc_fp = fp + ".locked"
        with open(enc_fp, "wb") as f:
            f.write(bytes([random.randint(0, 255) for _ in range(4096)]))
        # Delete original
        os.remove(fp)
        print("[DEMO]   Encrypted: " + os.path.basename(fp))
        time.sleep(0.1)

def cleanup():
    print("\n[DEMO] Cleaning up test files...")
    import shutil
    shutil.rmtree(TEST_DIR, ignore_errors=True)
    print("[DEMO] Done. Check Aegis dashboard for alerts.")

if __name__ == "__main__":
    print("=" * 55)
    print("  Aegis-LX Ransomware Detection Demo")
    print("  Safe simulation — only touches /tmp/")
    print("=" * 55)
    setup()
    simulate_encryption()
    cleanup()
