"""
Deep analysis of recovered stream structure to find patterns in the mixing function.

Key insight: raw extraction gives ~215 for all positions (FV≈5874.727 for all).
The stream diversity MUST come from:
1. Nonlinear rolling transformation (inter-byte/inter-iteration dependencies)
2. Key/SHA byte mixing (V3 spec: "Key and/or SHA byte values can influence av and hv")

Strategy:
- Collect long streams for multiple keys
- Look for periodic patterns, byte-pair correlations
- Check if stream[i+12] relates to stream[i] (12 = bytes per dimension pair per iteration)
- Check if dim=2 stream has 12-byte periodicity structure
- Analyze byte transition matrix for Markov-like dependencies
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
    print("COLLECTING LONG STREAMS")
    print("=" * 80)

    streams = {}
    for key in ["Secret99", "Secret98", "abc"]:
        for dim in [2, 8]:
            s = get_stream(key, 48, dimensions=dim)
            if s:
                label = f"{key}_d{dim}"
                streams[label] = s
                print(f"  {label:20s}: {s[:24]}")
            time.sleep(0.3)

    # =========================================================================
    print(f"\n{'=' * 80}")
    print("TEST 1: 12-BYTE PERIODICITY (bytes per dim pair per iteration)")
    print("=" * 80)

    for label, stream in streams.items():
        print(f"\n  {label}:")
        # Split into 12-byte blocks
        for i in range(0, min(len(stream), 48), 12):
            block = stream[i:i+12]
            print(f"    [{i:2d}:{i+12:2d}] = {block}")

        # Check if stream[i] == stream[i+12] for any i
        matches_12 = sum(1 for i in range(min(36, len(stream)-12))
                        if stream[i] == stream[i+12])
        matches_24 = sum(1 for i in range(min(24, len(stream)-24))
                        if stream[i] == stream[i+24])
        print(f"    Period-12 matches: {matches_12}/{min(36, len(stream)-12)}")
        print(f"    Period-24 matches: {matches_24}/{min(24, len(stream)-24)}")

        # XOR between consecutive 12-byte blocks
        if len(stream) >= 24:
            xor_12 = [stream[i] ^ stream[i+12] for i in range(12)]
            print(f"    XOR(block0, block1): {xor_12}")

    # =========================================================================
    print(f"\n{'=' * 80}")
    print("TEST 2: CONSECUTIVE BYTE DIFFERENCES (ROLLING DEPENDENCY)")
    print("=" * 80)

    for label in ["Secret99_d2", "Secret99_d8"]:
        stream = streams.get(label)
        if not stream:
            continue
        print(f"\n  {label}:")
        diffs_xor = [stream[i] ^ stream[i+1] for i in range(min(23, len(stream)-1))]
        diffs_add = [(stream[i+1] - stream[i]) % 256 for i in range(min(23, len(stream)-1))]
        print(f"    XOR consecutive: {diffs_xor}")
        print(f"    ADD consecutive: {diffs_add}")

        # Check if consecutive XOR is constant (linear feedback)
        if len(set(diffs_xor)) < len(diffs_xor) // 2:
            print(f"    XOR consecutive has repeats: {Counter(diffs_xor).most_common(5)}")

    # =========================================================================
    print(f"\n{'=' * 80}")
    print("TEST 3: STREAM BYTE AT SAME POSITION, INCREASING LENGTHS")
    print("=" * 80)
    print("  (Does stream[i] change as length grows?)")

    key = "Secret99"
    for dim in [2, 8]:
        print(f"\n  dim={dim}:")
        prev_first_bytes = None
        for length in [12, 13, 14, 15, 16, 20, 24, 28, 32, 36, 40, 44, 48]:
            s = get_stream(key, length, dimensions=dim)
            if s:
                # Show first 8 bytes
                first8 = s[:8]
                changed = ""
                if prev_first_bytes and first8 != prev_first_bytes:
                    changed = " ← CHANGED!"
                print(f"    len={length:3d}: first8={first8}{changed}")
                prev_first_bytes = first8
            time.sleep(0.2)

    # =========================================================================
    print(f"\n{'=' * 80}")
    print("TEST 4: STREAM BYTE DISTRIBUTION")
    print("=" * 80)

    # Collect a large stream
    big_stream = get_stream("Secret99", 48, dimensions=8)
    if big_stream:
        freq = Counter(big_stream)
        print(f"  48-byte stream: min={min(big_stream)}, max={max(big_stream)}, "
              f"unique={len(set(big_stream))}")
        print(f"  Most common: {freq.most_common(5)}")
        print(f"  Least common: {freq.most_common()[-5:]}")

        # Check for byte value 0
        zeros = big_stream.count(0)
        print(f"  Zeros: {zeros}/48")

    # =========================================================================
    print(f"\n{'=' * 80}")
    print("TEST 5: CROSS-KEY STREAM CORRELATION AT dim=2")
    print("=" * 80)

    keys_dim2 = {}
    for key in ["Secret99", "Secret98", "Secret97", "Secret96",
                "abc", "def", "test", "key"]:
        s = get_stream(key, 24, dimensions=2)
        if s:
            keys_dim2[key] = s
            print(f"  {key:12s}: {s[:12]}")
        time.sleep(0.3)

    # Pairwise XOR
    key_list = list(keys_dim2.keys())
    for i in range(min(4, len(key_list))):
        for j in range(i+1, min(4, len(key_list))):
            k1, k2 = key_list[i], key_list[j]
            xor = [a ^ b for a, b in zip(keys_dim2[k1][:12], keys_dim2[k2][:12])]
            print(f"  XOR({k1}, {k2}): {xor}")

    # =========================================================================
    print(f"\n{'=' * 80}")
    print("TEST 6: dim=2 STREAM — IS IT A SINGLE PAIR'S OUTPUT?")
    print("=" * 80)

    # At dim=2, only 1 dimension pair is active
    # If each pair gives 12 bytes per iteration,
    # a 12-byte payload should need exactly 1 iteration,
    # and a 24-byte payload should need 2 iterations.
    # Check if stream[0:12] at len=12 == stream[0:12] at len=24

    key = "Secret99"
    s12 = get_stream(key, 12, dimensions=2)
    s24 = get_stream(key, 24, dimensions=2)
    time.sleep(0.3)
    s36 = get_stream(key, 36, dimensions=2)
    s48 = get_stream(key, 48, dimensions=2)

    if s12 and s24:
        print(f"  dim=2 len=12: {s12}")
        print(f"  dim=2 len=24: {s24[:12]} | {s24[12:]}")
        same = s12 == s24[:12]
        print(f"  First 12 bytes match: {same}")

    if s24 and s36:
        print(f"  dim=2 len=36: {s36[:12]} | {s36[12:24]} | {s36[24:]}")
        same_24_36 = s24 == s36[:24]
        print(f"  First 24 bytes match (len=24 vs len=36): {same_24_36}")

    if s48:
        print(f"  dim=2 len=48: blocks of 12:")
        for i in range(0, 48, 12):
            print(f"    [{i:2d}:{i+12:2d}] = {s48[i:i+12]}")

    # =========================================================================
    print(f"\n{'=' * 80}")
    print("TEST 7: STREAM BYTE[0] vs KEY — IS IT KEY-BYTE DEPENDENT?")
    print("=" * 80)

    # Test if stream[0] changes based on key bytes in a detectable pattern
    print(f"  Testing single-char keys (ASCII 33-90):")
    byte0_map = {}
    for ch in range(33, 91):
        key = chr(ch)
        s = get_stream(key, 4, dimensions=2)
        if s:
            byte0_map[ch] = s[0]
        time.sleep(0.15)

    # Show results
    for ch in sorted(byte0_map.keys()):
        print(f"    key='{chr(ch)}' ({ch:3d}): stream[0]={byte0_map[ch]:3d}")

    # Check if there's a simple relationship
    vals = list(byte0_map.values())
    if len(set(vals)) < len(vals) // 2:
        print(f"  MANY COLLISIONS: {Counter(vals).most_common(5)}")
    else:
        print(f"  {len(set(vals))}/{len(vals)} unique values")


if __name__ == "__main__":
    main()
