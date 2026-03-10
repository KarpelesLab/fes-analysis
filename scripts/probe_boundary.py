#!/usr/bin/env python3
"""
Deep investigation of the stream[11]==stream[12] boundary artifact in FES server.

The FES spec says "12 significant bytes per dimension per iteration", so the
equality at position 11-12 likely reflects an iteration boundary artifact.
This script systematically probes the server to characterize this phenomenon.
"""

import base64, json, urllib.request, urllib.parse, time, sys
from collections import Counter

API_URL = "https://portalz.solutions/fes.dna"
HEADERS = {
    "Content-Type": "application/x-www-form-urlencoded",
    "Referer": "https://portalz.solutions/fractalTransform.html",
    "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36",
}

DELAY = 0.3  # seconds between API calls


def fes_request(key, payload="", dimensions=8, scramble=""):
    data = urllib.parse.urlencode({
        "mode": "1", "key": key, "payload": payload, "trans": "",
        "dimensions": str(dimensions), "depth": "1", "scramble": scramble,
        "xor": "on", "whirl": "", "asciiRange": "256",
    }).encode()
    req = urllib.request.Request(API_URL, data=data, headers=HEADERS)
    with urllib.request.urlopen(req, timeout=15) as resp:
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


def fmt_hex(byte_list):
    return ' '.join(f'{b:02x}' for b in byte_list)


# ============================================================================
# TEST 1: Verify stream[11]==stream[12] across keys and dimensions
# ============================================================================
def test1_verify_boundary():
    print("=" * 70)
    print("TEST 1: Verify stream[11]==stream[12] across keys and dimensions")
    print("=" * 70)

    keys = [
        "Secret99", "hello", "password123", "FES_test", "alpha",
        "beta", "gamma", "key2024", "cryptokey", "testcase",
        "foo", "bar42", "longerpasswordhere"
    ]
    dims = [2, 4, 6, 8, 10, 12]

    results = []
    for key in keys:
        for dim in dims:
            time.sleep(DELAY)
            stream = get_stream(key, 48, dimensions=dim)
            if stream is None or len(stream) < 13:
                print(f"  key={key:20s} dim={dim:2d}  -> FAILED (no/short stream)")
                continue
            eq = stream[11] == stream[12]
            results.append((key, dim, eq, stream[11], stream[12]))
            marker = "OK" if eq else "MISMATCH!"
            print(f"  key={key:20s} dim={dim:2d}  stream[11]={stream[11]:3d}  "
                  f"stream[12]={stream[12]:3d}  [{marker}]")

    total = len(results)
    matches = sum(1 for _, _, eq, _, _ in results if eq)
    mismatches = sum(1 for _, _, eq, _, _ in results if not eq)
    print(f"\n  Summary: {matches}/{total} matched, {mismatches} mismatches\n")
    return results


# ============================================================================
# TEST 2: Check ALL adjacent pairs in a length-48 stream
# ============================================================================
def test2_all_adjacent_pairs():
    print("=" * 70)
    print("TEST 2: Check ALL adjacent pairs stream[i]==stream[i+1] (len=48)")
    print("=" * 70)

    keys = ["Secret99", "hello", "password123", "FES_test", "alpha",
            "beta", "gamma", "key2024"]

    # Count how often each position pair matches across keys
    pair_match_counts = Counter()
    total_keys_tested = 0

    for key in keys:
        time.sleep(DELAY)
        stream = get_stream(key, 48, dimensions=8)
        if stream is None or len(stream) < 48:
            print(f"  key={key}: FAILED")
            continue
        total_keys_tested += 1
        matches = []
        for i in range(len(stream) - 1):
            if stream[i] == stream[i + 1]:
                matches.append(i)
                pair_match_counts[i] += 1
        print(f"  key={key:20s}  matching pairs at positions: {matches}")

    print(f"\n  Position frequency (out of {total_keys_tested} keys):")
    for pos in sorted(pair_match_counts.keys()):
        count = pair_match_counts[pos]
        pct = 100 * count / total_keys_tested
        marker = " *** ALWAYS ***" if count == total_keys_tested else ""
        print(f"    stream[{pos:2d}]==stream[{pos+1:2d}]: "
              f"{count}/{total_keys_tested} ({pct:.0f}%){marker}")
    print()


# ============================================================================
# TEST 3: Longer streams - check every 12th boundary
# ============================================================================
def test3_longer_streams():
    print("=" * 70)
    print("TEST 3: Longer streams - check 12-byte boundary pattern")
    print("=" * 70)

    keys = ["Secret99", "hello", "password123", "FES_test", "alpha"]
    length = 120

    boundary_positions = [11, 23, 35, 47, 59, 71, 83, 95, 107]

    for key in keys:
        time.sleep(DELAY)
        stream = get_stream(key, length, dimensions=8)
        if stream is None:
            print(f"  key={key}: FAILED")
            continue
        slen = len(stream)
        print(f"  key={key:20s} (stream length={slen}):")
        for pos in boundary_positions:
            if pos + 1 >= slen:
                break
            eq = stream[pos] == stream[pos + 1]
            marker = "EQUAL" if eq else "differ"
            print(f"    stream[{pos:3d}]=={stream[pos]:3d}  "
                  f"stream[{pos+1:3d}]={stream[pos+1]:3d}  [{marker}]")

        # Also check ALL adjacent pairs for longer streams
        all_matches = [i for i in range(slen - 1) if stream[i] == stream[i + 1]]
        print(f"    All matching adjacent pairs: {all_matches}")
        print()


# ============================================================================
# TEST 4: Byte values at boundaries - same value or just equal?
# ============================================================================
def test4_boundary_values():
    print("=" * 70)
    print("TEST 4: Actual byte values at stream[11]/stream[12] across keys")
    print("=" * 70)

    keys = [
        "Secret99", "hello", "password123", "FES_test", "alpha",
        "beta", "gamma", "key2024", "cryptokey", "testcase",
        "foo", "bar42", "longerpasswordhere", "xyz", "aaa",
        "bbb", "ccc", "ddd", "eee", "fff",
        "ggg", "hhh", "iii", "jjj", "kkk"
    ]

    values_11 = []
    values_12 = []

    for key in keys:
        time.sleep(DELAY)
        stream = get_stream(key, 48, dimensions=8)
        if stream is None or len(stream) < 13:
            continue
        values_11.append(stream[11])
        values_12.append(stream[12])
        print(f"  key={key:20s}  stream[11]={stream[11]:3d} (0x{stream[11]:02x})  "
              f"stream[12]={stream[12]:3d} (0x{stream[12]:02x})  "
              f"{'EQUAL' if stream[11]==stream[12] else 'DIFFER'}")

    print(f"\n  Unique values at stream[11]: {sorted(set(values_11))}")
    print(f"  Unique values at stream[12]: {sorted(set(values_12))}")
    print(f"  Number of distinct values: {len(set(values_11))} (out of {len(values_11)} keys)")

    if len(set(values_11)) == 1:
        print(f"  ** ALL keys produce the SAME value ({values_11[0]}) at stream[11]! **")
    else:
        print(f"  ** Values VARY by key (not a fixed constant) **")
    print()

    return values_11


# ============================================================================
# TEST 5: Dimension influence on boundary position
# ============================================================================
def test5_dimension_influence():
    print("=" * 70)
    print("TEST 5: Does boundary position shift with dimensions?")
    print("=" * 70)

    key = "Secret99"
    length = 96

    for dim in [2, 4, 6, 8, 10, 12]:
        time.sleep(DELAY)
        stream = get_stream(key, length, dimensions=dim)
        if stream is None:
            print(f"  dim={dim:2d}: FAILED")
            continue
        slen = len(stream)
        # Check all adjacent pairs
        matches = [i for i in range(slen - 1) if stream[i] == stream[i + 1]]
        print(f"  dim={dim:2d} (stream len={slen}): "
              f"matching pairs at positions: {matches}")

        # Check specific boundaries based on dimension
        # dim=D means D/2 coordinate pairs, each producing 12 bytes
        bytes_per_iter = 12  # spec says 12 significant bytes
        expected_boundaries = []
        b = bytes_per_iter - 1  # 0-indexed position of last byte in first block
        while b + 1 < slen:
            expected_boundaries.append(b)
            b += bytes_per_iter
        print(f"         Expected 12-byte boundaries: {expected_boundaries}")

        # Also check dim-based boundaries
        dim_block = dim * 6  # each dimension pair = 6 bytes? or 12?
        print(f"         dim*6={dim_block}-byte boundaries: "
              f"{[dim_block * k - 1 for k in range(1, 5) if dim_block * k < slen]}")
    print()


# ============================================================================
# TEST 6: Near-boundary detailed analysis
# ============================================================================
def test6_near_boundary():
    print("=" * 70)
    print("TEST 6: Near-boundary detailed byte analysis (stream[8:16])")
    print("=" * 70)

    keys = ["Secret99", "hello", "password123", "FES_test", "alpha",
            "beta", "gamma", "key2024"]

    for key in keys:
        time.sleep(DELAY)
        stream = get_stream(key, 48, dimensions=8)
        if stream is None or len(stream) < 16:
            print(f"  key={key}: FAILED")
            continue
        segment = stream[8:16]
        print(f"  key={key:20s}  stream[8:16] = [{fmt_hex(segment)}]")
        print(f"  {'':24s}  indices:       "
              f"[ 8  9 10 11 12 13 14 15]")
        print(f"  {'':24s}  decimal:       "
              f"[{' '.join(f'{b:2d}' for b in segment)}]")

        # Show byte-to-byte differences
        diffs = [segment[i+1] - segment[i] for i in range(len(segment)-1)]
        print(f"  {'':24s}  deltas:         "
              f"[{' '.join(f'{d:+3d}' for d in diffs)}]")
        print()


# ============================================================================
# TEST 7: Check if stream[11]==stream[12] is dimension-dependent
# ============================================================================
def test7_per_dimension_boundary():
    print("=" * 70)
    print("TEST 7: Per-dimension boundary check with multiple keys")
    print("=" * 70)

    keys = ["Secret99", "hello", "password123", "FES_test", "alpha",
            "beta", "gamma"]
    dims = [2, 4, 6, 8, 10, 12, 14, 16]

    # For each dim, count how many keys have stream[11]==stream[12]
    dim_results = {}
    for dim in dims:
        match_count = 0
        total = 0
        for key in keys:
            time.sleep(DELAY)
            stream = get_stream(key, 48, dimensions=dim)
            if stream is None or len(stream) < 13:
                continue
            total += 1
            if stream[11] == stream[12]:
                match_count += 1
        dim_results[dim] = (match_count, total)
        pct = 100 * match_count / total if total > 0 else 0
        print(f"  dim={dim:2d}: stream[11]==stream[12] in "
              f"{match_count}/{total} keys ({pct:.0f}%)")
    print()


# ============================================================================
# TEST 8: Broader pattern - check multiples of 12 and other intervals
# ============================================================================
def test8_interval_analysis():
    print("=" * 70)
    print("TEST 8: Systematic interval analysis")
    print("=" * 70)

    keys = ["Secret99", "hello", "password123", "FES_test", "alpha"]
    length = 120

    # Collect all streams
    streams = {}
    for key in keys:
        time.sleep(DELAY)
        stream = get_stream(key, length, dimensions=8)
        if stream:
            streams[key] = stream

    # For each candidate interval, check if boundary exists at that interval
    print("  Checking if stream[k-1]==stream[k] holds for all keys at various k:")
    print()
    for k in range(1, min(len(s) for s in streams.values())):
        count = sum(1 for s in streams.values() if s[k-1] == s[k])
        if count == len(streams):
            print(f"    Position {k-1:3d}-{k:3d}: ALL {count} keys match  "
                  f"(k={k}, k%12={k%12}, k//12={k//12})")

    print()
    # Show which positions match for AT LEAST half the keys
    print("  Positions matching for >= half of keys:")
    threshold = len(streams) // 2
    for k in range(1, min(len(s) for s in streams.values())):
        count = sum(1 for s in streams.values() if s[k-1] == s[k])
        if count >= threshold:
            print(f"    stream[{k-1:3d}]==stream[{k:3d}]: "
                  f"{count}/{len(streams)} keys  (pos%12={k%12})")
    print()


# ============================================================================
# MAIN
# ============================================================================
def main():
    print("FES Stream Boundary Artifact Investigation")
    print("Investigating stream[11]==stream[12] and related patterns")
    print("Server: portalz.solutions/fes.dna")
    print()

    test1_verify_boundary()
    test2_all_adjacent_pairs()
    test3_longer_streams()
    test4_boundary_values()
    test5_dimension_influence()
    test6_near_boundary()
    test7_per_dimension_boundary()
    test8_interval_analysis()

    print("=" * 70)
    print("INVESTIGATION COMPLETE")
    print("=" * 70)


if __name__ == "__main__":
    main()
