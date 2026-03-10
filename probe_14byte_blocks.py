"""
Probe the 14-byte block structure in FES stream extraction.

Key finding: stream[11]==stream[12], stream[25]==stream[26] at intervals of 14.
This suggests 14-byte extraction blocks with 1-byte carry-over.

If the extraction produces 14-byte blocks:
  Block 0: stream[0:14]  (bytes 0-13)
  Block 1: stream[13:27] (bytes 13-26, with stream[13]=last byte of block 0)
  OR
  Block 0: stream[0:12]  → 12 unique bytes
  Block 1: stream[12:24] → but stream[11]==stream[12] means 1-byte overlap

Tests:
1. Precisely identify the block boundaries (is it 14-byte blocks or 12+2 overlap?)
2. Test with very long streams to verify the period
3. Check if dim=2 (1 pair) has same 14-byte period as dim=8 (4 pairs)
4. Analyze the relationship between the overlapping bytes
"""

import base64
import json
import urllib.request
import urllib.parse
import time
from collections import Counter

API_URL = "https://portalz.solutions/fes.dna"
HEADERS = {
    "Content-Type": "application/x-www-form-urlencoded",
    "Referer": "https://portalz.solutions/fractalTransform.html",
    "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36",
}


def fes_request(key, payload="", dimensions=8, scramble=""):
    data = urllib.parse.urlencode({
        "mode": "1", "key": key, "payload": payload, "trans": "",
        "dimensions": str(dimensions), "depth": "1", "scramble": scramble,
        "xor": "on", "whirl": "", "asciiRange": "256",
    }).encode()
    req = urllib.request.Request(API_URL, data=data, headers=HEADERS)
    with urllib.request.urlopen(req) as resp:
        return json.loads(resp.read())


def get_stream(key, length, dimensions=8):
    known = 'A' * length
    result = fes_request(key, payload=known, dimensions=dimensions)
    ct_b64 = result.get("trans", "")
    if not ct_b64:
        return None
    padded = ct_b64 + '=' * (4 - len(ct_b64) % 4) if len(ct_b64) % 4 else ct_b64
    ct = base64.b64decode(padded)
    stream_rev = bytes(c ^ 0x41 for c in ct)
    return list(reversed(list(stream_rev)))


def main():
    # =========================================================================
    print("=" * 80)
    print("TEST 1: PRECISELY MAP ALL EQUAL-ADJACENT-BYTE POSITIONS")
    print("=" * 80)

    # Use a long stream to see the full pattern
    keys_to_test = ["Secret99", "hello", "password123", "alpha", "gamma",
                     "testkey1", "xyz42", "longpass"]

    all_equal_positions = {}
    for key in keys_to_test:
        s = get_stream(key, 200, dimensions=8)
        if not s:
            continue
        equal_pos = []
        for i in range(len(s) - 1):
            if s[i] == s[i + 1]:
                equal_pos.append(i)
        all_equal_positions[key] = equal_pos
        print(f"  {key:16s}: equal pairs at {equal_pos}")
        time.sleep(0.3)

    # Find positions that appear in ALL keys
    if all_equal_positions:
        all_pos = set.intersection(*[set(v) for v in all_equal_positions.values()])
        print(f"\n  Positions present in ALL {len(all_equal_positions)} keys: "
              f"{sorted(all_pos)}")

        # Find positions in ≥75% of keys
        pos_count = Counter()
        for positions in all_equal_positions.values():
            for p in positions:
                pos_count[p] += 1
        threshold = len(all_equal_positions) * 0.75
        common_pos = sorted([p for p, c in pos_count.items() if c >= threshold])
        print(f"  Positions in ≥75% keys: {common_pos}")

        # Compute intervals
        if len(common_pos) >= 2:
            intervals = [common_pos[i+1] - common_pos[i]
                         for i in range(len(common_pos) - 1)]
            print(f"  Intervals between common positions: {intervals}")
            avg_interval = sum(intervals) / len(intervals) if intervals else 0
            print(f"  Average interval: {avg_interval:.1f}")

    # =========================================================================
    print(f"\n{'=' * 80}")
    print("TEST 2: DIM=2 (1 PAIR) — SAME 14-BYTE PERIOD?")
    print("=" * 80)

    for key in ["Secret99", "hello", "alpha"]:
        s = get_stream(key, 120, dimensions=2)
        if not s:
            continue
        equal_pos = [i for i in range(len(s) - 1) if s[i] == s[i + 1]]
        print(f"  {key} dim=2: equal pairs at {equal_pos}")
        if len(equal_pos) >= 2:
            intervals = [equal_pos[i+1] - equal_pos[i]
                         for i in range(len(equal_pos) - 1)]
            print(f"    Intervals: {intervals}")
        time.sleep(0.3)

    # =========================================================================
    print(f"\n{'=' * 80}")
    print("TEST 3: DIM COMPARISON — IS PERIOD DIM-DEPENDENT?")
    print("=" * 80)

    key = "Secret99"
    for dim in [2, 4, 6, 8, 10, 12]:
        s = get_stream(key, 120, dimensions=dim)
        if not s:
            continue
        equal_pos = [i for i in range(len(s) - 1) if s[i] == s[i + 1]]
        print(f"  dim={dim:2d}: equal pairs at {equal_pos}")
        time.sleep(0.3)

    # =========================================================================
    print(f"\n{'=' * 80}")
    print("TEST 4: DETAILED BLOCK BOUNDARY ANALYSIS")
    print("=" * 80)

    # If blocks are 14 bytes with 1-byte overlap:
    # Block 0: bytes 0-13 (14 bytes, 12 unique + 2 shared)
    # Block 1: bytes 13-26 (last byte of block 0 = first of block 1)
    # Actually: if stream[11]==stream[12], the boundary is BETWEEN 11 and 12
    # So block 0 = bytes 0-11 (12 bytes), with stream[11]=stream[12]
    # Then the NEXT boundary is at 25-26, which is 14 positions later
    # Block 1 = bytes 12-25 (14 bytes)

    # Alternative: maybe 14 bytes extracted, but only 12 unique after overlap
    # Block 0: positions 0-13 → 14 bytes, last 2 overlap with next
    # But the equality is at 11-12, not 13-14

    key = "Secret99"
    s = get_stream(key, 120, dimensions=8)
    if s:
        print(f"\n  Key '{key}', dim=8, 120-byte stream:")
        print(f"  First 42 bytes:")
        for i in range(0, 42, 14):
            block = s[i:i+14]
            label = ""
            for j in range(14):
                if i+j > 0 and s[i+j] == s[i+j-1]:
                    label += f" [{i+j}={i+j-1}]"
            print(f"    [{i:3d}:{i+14:3d}] = {block}{label}")

        # Show the overlap bytes
        print(f"\n  Overlap analysis:")
        for boundary in [11, 25, 39, 53, 67, 81, 95, 109]:
            if boundary + 1 < len(s):
                eq = "==" if s[boundary] == s[boundary+1] else "!="
                print(f"    stream[{boundary:3d}]={s[boundary]:3d}  "
                      f"{eq}  stream[{boundary+1:3d}]={s[boundary+1]:3d}")

    # =========================================================================
    print(f"\n{'=' * 80}")
    print("TEST 5: BLOCK STRUCTURE — 12+2 OR 14 UNIQUE?")
    print("=" * 80)

    # If we have 14-byte blocks with 1-byte overlap, then:
    # Block 0: stream[0:14], block 1: stream[14:28], but overlap at boundary
    # The question is: what are the "12 significant bytes"?
    # If block = 14 bytes, and boundaries overlap by 1, then 14-1 = 13 unique per block
    # But spec says 12...

    # Test: extract blocks and check for internal patterns
    key = "Secret99"
    s = get_stream(key, 120, dimensions=8)
    if s:
        # Split into 14-byte blocks starting at 0
        print(f"\n  14-byte blocks (offset 0):")
        for i in range(0, min(84, len(s)), 14):
            block = s[i:i+14]
            print(f"    Block {i//14}: [{i:3d}:{i+14:3d}] = {block}")

        # Split into 12-byte blocks
        print(f"\n  12-byte blocks:")
        for i in range(0, min(84, len(s)), 12):
            block = s[i:i+12]
            # Check: does this block end with the same byte as next block starts?
            next_start = s[i+12] if i+12 < len(s) else None
            overlap = f"  next[0]={next_start}" if next_start is not None else ""
            eq = f"  {'==' if block[-1] == next_start else '!='}" if next_start is not None else ""
            print(f"    Block {i//12}: [{i:3d}:{i+12:3d}] = {block}{overlap}{eq}")

    # =========================================================================
    print(f"\n{'=' * 80}")
    print("TEST 6: XOR BETWEEN ADJACENT 14-BYTE BLOCKS")
    print("=" * 80)

    # If the mixing function has a 14-byte state, XOR between consecutive
    # 14-byte blocks might reveal the mixing pattern

    for key in ["Secret99", "hello"]:
        s = get_stream(key, 120, dimensions=8)
        if not s or len(s) < 56:
            continue
        print(f"\n  Key '{key}':")

        # 14-byte blocks
        for offset in range(0, min(84, len(s) - 14), 14):
            block_a = s[offset:offset + 14]
            block_b = s[offset + 14:offset + 28]
            if len(block_b) < 14:
                break
            xor = [a ^ b for a, b in zip(block_a, block_b)]
            print(f"    XOR(block[{offset//14}], block[{offset//14 + 1}]): {xor}")

    # =========================================================================
    print(f"\n{'=' * 80}")
    print("TEST 7: LONGER STREAM — VERIFY 14-BYTE PERIOD PERSISTS")
    print("=" * 80)

    # Get a very long stream and check if the 14-byte boundary continues
    key = "Secret99"
    # Use max non-phase-transition length
    s = get_stream(key, 42, dimensions=8)  # Safe length within phase
    time.sleep(0.3)

    if s:
        print(f"  Stream (42 bytes):")
        equal_pos = [i for i in range(len(s) - 1) if s[i] == s[i + 1]]
        print(f"  Equal adjacent pairs at: {equal_pos}")
        if len(equal_pos) >= 2:
            intervals = [equal_pos[i+1] - equal_pos[i]
                         for i in range(len(equal_pos) - 1)]
            print(f"  Intervals: {intervals}")

    # Also test dim=2 at same length
    s2 = get_stream(key, 42, dimensions=2)
    time.sleep(0.3)
    if s2:
        print(f"\n  Dim=2 Stream (42 bytes):")
        equal_pos = [i for i in range(len(s2) - 1) if s2[i] == s2[i + 1]]
        print(f"  Equal adjacent pairs at: {equal_pos}")

    # =========================================================================
    print(f"\n{'=' * 80}")
    print("TEST 8: ACROSS PHASE TRANSITIONS")
    print("=" * 80)

    # Do the boundaries persist across phase transitions?
    key = "Secret99"
    for length in [40, 44, 48, 72, 100]:
        s = get_stream(key, length, dimensions=8)
        if not s:
            continue
        equal_pos = [i for i in range(min(len(s), 50) - 1)
                     if s[i] == s[i + 1]]
        print(f"  len={length:3d}: stream[:12]={s[:12]}, "
              f"equal pairs (first 50): {equal_pos}")
        time.sleep(0.3)


if __name__ == "__main__":
    main()
