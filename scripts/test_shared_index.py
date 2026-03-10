"""
Test keys that share the same SHA-512[0:2] mapping index.
If the index determines the Silo entry, these keys should share
the base portal coordinates but differ in fine offsets.

If they share the Silo entry:
- Their Mandelbrot orbits start from nearby points
- The XOR constant K might be similar
- Some stream bytes might be correlated
"""

import base64
import json
import urllib.request
import urllib.parse
import hashlib
import time

API_URL = "https://portalz.solutions/fes.dna"
HEADERS = {
    "Content-Type": "application/x-www-form-urlencoded",
    "Referer": "https://portalz.solutions/fractalTransform.html",
    "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36",
}


def get_stream(key, length, dimensions=8):
    data = urllib.parse.urlencode({
        "mode": "1", "key": key, "payload": 'A' * length, "trans": "",
        "dimensions": str(dimensions), "depth": "1", "scramble": "",
        "xor": "on", "whirl": "", "asciiRange": "256",
    }).encode()
    req = urllib.request.Request(API_URL, data=data, headers=HEADERS)
    with urllib.request.urlopen(req) as resp:
        result = json.loads(resp.read())
    ct_b64 = result.get("trans", "")
    if not ct_b64:
        return None
    padded = ct_b64 + '=' * (4 - len(ct_b64) % 4) if len(ct_b64) % 4 else ct_b64
    ct = base64.b64decode(padded)
    stream_rev = bytes(c ^ 0x41 for c in ct)
    return list(reversed(list(stream_rev)))


def get_xor_constant(stream):
    blocks = [stream[i:i+14] for i in range(0, len(stream) - 13, 14)]
    if len(blocks) < 2:
        return None
    xor_vals = [b[0] ^ b[13] for b in blocks]
    if len(set(xor_vals)) == 1:
        return xor_vals[0]
    return None


def main():
    # Load shared index groups
    with open("data/shared_index_groups.json") as f:
        groups = json.load(f)

    # =========================================================================
    print("=" * 80)
    print("TEST 1: SHARED INDEX GROUPS — XOR CONSTANT COMPARISON")
    print("=" * 80)

    for gi, group in enumerate(groups[:5]):
        idx = group["mapping_index"]
        keys = group["keys"]
        print(f"\n  Group {gi}: mapping_index={idx} ({len(keys)} keys)")

        k_values = {}
        streams = {}
        for key in keys:
            s = get_stream(key, 42, dimensions=2)
            if s:
                K = get_xor_constant(s)
                k_values[key] = K
                streams[key] = s
                sha = hashlib.sha512(key.encode()).digest()
                print(f"    {key}: K={K}  sha[0:4]={list(sha[:4])}"
                      f"  stream[:7]={s[:7]}")
            time.sleep(0.2)

        # Check if K values match within group
        unique_k = len(set(v for v in k_values.values() if v is not None))
        print(f"    K values: {list(k_values.values())} "
              f"({'SAME' if unique_k == 1 else f'{unique_k} different'})")

        # Compare streams pairwise
        key_list = [k for k in keys if k in streams]
        for i in range(len(key_list)):
            for j in range(i+1, len(key_list)):
                s1 = streams[key_list[i]]
                s2 = streams[key_list[j]]
                min_len = min(len(s1), len(s2))
                matches = sum(1 for k in range(min_len) if s1[k] == s2[k])
                xor = [s1[k] ^ s2[k] for k in range(min(14, min_len))]
                print(f"    {key_list[i]} vs {key_list[j]}: "
                      f"{matches}/{min_len} match  XOR[:14]={xor}")

    # =========================================================================
    print(f"\n{'=' * 80}")
    print("TEST 2: COMPARE WITH RANDOM (NON-SHARED INDEX) KEYS")
    print("=" * 80)

    # Get streams for keys from DIFFERENT groups as baseline
    baseline_keys = [groups[0]["keys"][0], groups[1]["keys"][0],
                     groups[2]["keys"][0], groups[3]["keys"][0]]
    baseline_streams = {}
    for key in baseline_keys:
        s = get_stream(key, 42, dimensions=2)
        if s:
            baseline_streams[key] = s
        time.sleep(0.2)

    print("\n  Cross-group comparison (should be ~random):")
    b_keys = list(baseline_streams.keys())
    for i in range(len(b_keys)):
        for j in range(i+1, len(b_keys)):
            s1 = baseline_streams[b_keys[i]]
            s2 = baseline_streams[b_keys[j]]
            min_len = min(len(s1), len(s2))
            matches = sum(1 for k in range(min_len) if s1[k] == s2[k])
            print(f"  {b_keys[i]} vs {b_keys[j]}: {matches}/{min_len} match")

    # =========================================================================
    print(f"\n{'=' * 80}")
    print("TEST 3: SAME GROUPS AT dim=8")
    print("=" * 80)

    for gi, group in enumerate(groups[:3]):
        idx = group["mapping_index"]
        keys = group["keys"][:3]
        print(f"\n  Group {gi}: mapping_index={idx}")

        streams8 = {}
        for key in keys:
            s = get_stream(key, 42, dimensions=8)
            if s:
                K = get_xor_constant(s)
                streams8[key] = s
                print(f"    {key}: K={K}  stream[:7]={s[:7]}")
            time.sleep(0.2)

        key_list = [k for k in keys if k in streams8]
        for i in range(len(key_list)):
            for j in range(i+1, len(key_list)):
                s1 = streams8[key_list[i]]
                s2 = streams8[key_list[j]]
                min_len = min(len(s1), len(s2))
                matches = sum(1 for k in range(min_len) if s1[k] == s2[k])
                print(f"    {key_list[i]} vs {key_list[j]}: {matches}/{min_len} match")

    # =========================================================================
    print(f"\n{'=' * 80}")
    print("TEST 4: DOES THE MAPPING INDEX ACTUALLY CORRELATE WITH ANYTHING?")
    print("=" * 80)

    # If the mapping index = SHA[0:2], test if keys with adjacent indices
    # have any stream similarity. Find 2 keys with consecutive indices.
    print("\n  Looking for keys with consecutive SHA[0:2] indices...")
    idx_to_key = {}
    for i in range(10000):
        key = f"idx_{i:05d}"
        sha = hashlib.sha512(key.encode()).digest()
        idx = (sha[0] << 8) | sha[1]
        if idx - 1 in idx_to_key:
            other = idx_to_key[idx - 1]
            print(f"  Found consecutive: '{key}' (idx={idx}) and '{other}' (idx={idx-1})")
            s1 = get_stream(key, 42, dimensions=2)
            time.sleep(0.15)
            s2 = get_stream(other, 42, dimensions=2)
            time.sleep(0.15)
            if s1 and s2:
                matches = sum(1 for k in range(min(len(s1), len(s2)))
                              if s1[k] == s2[k])
                K1 = get_xor_constant(s1)
                K2 = get_xor_constant(s2)
                print(f"    Stream match: {matches}/{min(len(s1), len(s2))}"
                      f"  K1={K1}  K2={K2}")
            break
        idx_to_key[idx] = key


if __name__ == "__main__":
    main()
