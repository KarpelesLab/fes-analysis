"""
Investigate key expansion: how does password → stream?

Tests:
1. Keys that differ only in last byte — avalanche check
2. SHA-512 prefix collision — do same-hash-prefix keys share streams?
3. Context binding (asciiRange, ms params)
4. Timing analysis for hash iterations
5. Pair isolation at dim=2
6. Case sensitivity
7. Numeric key treatment
"""

import base64
import json
import urllib.request
import urllib.parse
import hashlib
import time as time_mod

API_URL = "https://portalz.solutions/fes.dna"
HEADERS = {
    "Content-Type": "application/x-www-form-urlencoded",
    "Referer": "https://portalz.solutions/fractalTransform.html",
    "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36",
}


def fes_request(key, payload="", dimensions=8, scramble="", extra_params=None):
    params = {
        "mode": "1", "key": key, "payload": payload, "trans": "",
        "dimensions": str(dimensions), "depth": "1", "scramble": scramble,
        "xor": "on", "whirl": "", "asciiRange": "256",
    }
    if extra_params:
        params.update(extra_params)
    data = urllib.parse.urlencode(params).encode()
    req = urllib.request.Request(API_URL, data=data, headers=HEADERS)
    with urllib.request.urlopen(req) as resp:
        return json.loads(resp.read())


def get_stream(key, length, dimensions=8, extra_params=None):
    known = 'A' * length
    result = fes_request(key, payload=known, dimensions=dimensions,
                         extra_params=extra_params)
    ct_b64 = result.get("trans", "")
    if not ct_b64:
        return None
    padded = ct_b64 + '=' * (4 - len(ct_b64) % 4) if len(ct_b64) % 4 else ct_b64
    ct = base64.b64decode(padded)
    stream_rev = bytes(c ^ 0x41 for c in ct)
    return list(reversed(list(stream_rev)))


def stream_distance(s1, s2):
    min_len = min(len(s1), len(s2))
    matches = sum(1 for i in range(min_len) if s1[i] == s2[i])
    return matches, min_len


def main():
    # =========================================================================
    print("=" * 80)
    print("TEST 1: KEYS DIFFERING IN LAST BYTE ONLY")
    print("=" * 80)

    for base in ["Secret9", "hello"]:
        streams = {}
        for suffix in ['A', 'B', '1', '9']:
            key = base + suffix
            s = get_stream(key, 42, dimensions=8)
            if s:
                streams[key] = s
            time_mod.sleep(0.15)

        keys = list(streams.keys())
        for i in range(len(keys)):
            for j in range(i+1, len(keys)):
                matches, total = stream_distance(streams[keys[i]], streams[keys[j]])
                print(f"  {keys[i]:12s} vs {keys[j]:12s}: {matches}/{total} match")

    # =========================================================================
    print(f"\n{'=' * 80}")
    print("TEST 2: SHA-512 PREFIX COLLISION — dim=2")
    print("=" * 80)

    sha_map = {}
    found = 0
    for i in range(50000):
        key = f"s{i:06d}"
        sha = hashlib.sha512(key.encode()).digest()
        prefix = (sha[0], sha[1])
        if prefix in sha_map and found < 3:
            other_key = sha_map[prefix]
            s1 = get_stream(key, 42, dimensions=2)
            time_mod.sleep(0.15)
            s2 = get_stream(other_key, 42, dimensions=2)
            time_mod.sleep(0.15)

            if s1 and s2:
                matches, total = stream_distance(s1, s2)
                sha_k = hashlib.sha512(key.encode()).digest()
                sha_o = hashlib.sha512(other_key.encode()).digest()
                print(f"  '{key}' vs '{other_key}': SHA[0:2]={list(sha_k[:2])}"
                      f"  stream match: {matches}/{total}")
            found += 1
        sha_map[prefix] = key

    # =========================================================================
    print(f"\n{'=' * 80}")
    print("TEST 3: CONTEXT BINDING — asciiRange AND ms")
    print("=" * 80)

    key = "Secret99"
    base_stream = get_stream(key, 42, dimensions=8)
    time_mod.sleep(0.2)

    for arange in ["128", "256", "512"]:
        s = get_stream(key, 42, dimensions=8, extra_params={"asciiRange": arange})
        if s and base_stream:
            matches, total = stream_distance(s, base_stream)
            print(f"  asciiRange={arange:3s}: {matches}/{total} match")
        time_mod.sleep(0.2)

    for ms in ["0.001", "0.01", "0.1", "1.0"]:
        s = get_stream(key, 42, dimensions=8, extra_params={"ms": ms})
        if s and base_stream:
            matches, total = stream_distance(s, base_stream)
            print(f"  ms={ms:5s}: {matches}/{total} match")
        time_mod.sleep(0.2)

    # =========================================================================
    print(f"\n{'=' * 80}")
    print("TEST 4: TIMING BY KEY LENGTH AND DIMENSION")
    print("=" * 80)

    print("\n  By key length:")
    for key_len in [1, 4, 8, 16, 32, 64, 128, 256]:
        key = 'X' * key_len
        times = []
        for _ in range(3):
            start = time_mod.time()
            get_stream(key, 14, dimensions=2)
            elapsed = time_mod.time() - start
            times.append(elapsed)
            time_mod.sleep(0.05)
        avg = sum(times) / len(times)
        print(f"    key_len={key_len:3d}: avg={avg*1000:.0f}ms")

    print("\n  By dimension:")
    key = "Secret99"
    for dim in [2, 4, 8, 16, 32, 64]:
        times = []
        for _ in range(3):
            start = time_mod.time()
            get_stream(key, 14, dimensions=dim)
            elapsed = time_mod.time() - start
            times.append(elapsed)
            time_mod.sleep(0.05)
        avg = sum(times) / len(times)
        print(f"    dim={dim:2d}: avg={avg*1000:.0f}ms")

    # =========================================================================
    print(f"\n{'=' * 80}")
    print("TEST 5: CASE SENSITIVITY")
    print("=" * 80)

    pairs = [("secret99", "Secret99"), ("SECRET99", "Secret99"),
             ("Hello", "hello"), ("ABC", "abc")]
    for k1, k2 in pairs:
        s1 = get_stream(k1, 42, dimensions=8)
        time_mod.sleep(0.15)
        s2 = get_stream(k2, 42, dimensions=8)
        time_mod.sleep(0.15)
        if s1 and s2:
            matches, total = stream_distance(s1, s2)
            print(f"  '{k1}' vs '{k2}': "
                  f"{'SAME' if matches == total else f'{matches}/{total} DIFFERENT'}")

    # =========================================================================
    print(f"\n{'=' * 80}")
    print("TEST 6: NUMERIC VS STRING TREATMENT")
    print("=" * 80)

    ref = get_stream("99", 42, dimensions=8)
    time_mod.sleep(0.15)
    for k in ["099", "99.0", " 99", "99 "]:
        s = get_stream(k, 42, dimensions=8)
        time_mod.sleep(0.15)
        if s and ref:
            matches, total = stream_distance(s, ref)
            print(f"  '99' vs '{k}': "
                  f"{'SAME' if matches == total else f'{matches}/{total} DIFFERENT'}")

    # =========================================================================
    print(f"\n{'=' * 80}")
    print("TEST 7: EXTENDED KEY MATERIAL — DOES dim=16 NEED MORE KEY?")
    print("=" * 80)

    # dim=16 needs 8 pairs. If SHA-512 (64 bytes) provides 4 pairs × 16 bytes,
    # then dim=16 needs 128 bytes — more than one SHA-512 output.
    # Does the server iterate SHA-512 to get more material?
    # Test: do dim=8 and dim=16 share ANY blocks?

    key = "Secret99"
    s8 = get_stream(key, 70, dimensions=8)
    time_mod.sleep(0.2)
    s16 = get_stream(key, 70, dimensions=16)
    time_mod.sleep(0.2)

    if s8 and s16:
        min_len = min(len(s8), len(s16))
        matches, total = stream_distance(s8, s16)
        print(f"  dim=8 vs dim=16: {matches}/{total} matching bytes")

        # Check block-by-block
        for b in range(0, min(min_len, 70) - 13, 14):
            b8 = s8[b:b+14]
            b16 = s16[b:b+14]
            bmatch = sum(1 for k in range(14) if b8[k] == b16[k])
            xor = [b8[k] ^ b16[k] for k in range(14)]
            print(f"    Block {b//14}: {bmatch}/14 match  XOR={xor}")

    # =========================================================================
    print(f"\n{'=' * 80}")
    print("TEST 8: WHIRL PARAMETER EFFECT")
    print("=" * 80)

    key = "Secret99"
    base = get_stream(key, 42, dimensions=8)
    time_mod.sleep(0.15)

    for whirl in ["", "on", "1", "test"]:
        s = get_stream(key, 42, dimensions=8,
                       extra_params={"whirl": whirl})
        if s and base:
            matches, total = stream_distance(s, base)
            print(f"  whirl='{whirl}': {matches}/{total} match"
                  f"  {'SAME' if matches == total else 'DIFFERENT'}")
        time_mod.sleep(0.15)


if __name__ == "__main__":
    main()
