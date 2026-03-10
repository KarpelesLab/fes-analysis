"""
Test if key bytes are used for sequential navigation (FT-Explained model)
or if the entire key is hashed at once.

FT-Explained model:
  1. Hash key → Silo index → base portal
  2. For each byte b in key: navigate from current position using b

If this is correct, then:
- "AB" stream should be derivable from "A" stream + one extra navigation step using 'B'
- But since the hash in step 1 uses the FULL key, "AB" starts at a different base portal

Alternative model:
  1. Hash key → all portal coordinates directly (no per-byte navigation)

Tests:
1. Do "A"+"B" combined relate to "AB" in any way?
2. Does appending bytes change stream incrementally or completely?
3. Test per-byte influence by comparing keys that share prefixes
4. Check if the number of navigation steps equals key length
5. Probe the FOTP mechanism more (it sets K=0)
6. Test what happens with very long identical keys (AAAA...) at different lengths
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


def get_stream(key, length=42, dimensions=2, extra_params=None):
    params = {
        "mode": "1", "key": key, "payload": 'A' * length, "trans": "",
        "dimensions": str(dimensions), "depth": "1", "scramble": "",
        "xor": "on", "whirl": "", "asciiRange": "256",
    }
    if extra_params:
        params.update(extra_params)
    data = urllib.parse.urlencode(params).encode()
    req = urllib.request.Request(API_URL, data=data, headers=HEADERS)
    with urllib.request.urlopen(req, timeout=30) as resp:
        result = json.loads(resp.read())
    ct_b64 = result.get("trans", "")
    if not ct_b64:
        return None
    padded = ct_b64 + '=' * (4 - len(ct_b64) % 4) if len(ct_b64) % 4 else ct_b64
    ct = base64.b64decode(padded)
    stream_rev = bytes(c ^ 0x41 for c in ct)
    return list(reversed(list(stream_rev)))


def stream_dist(s1, s2):
    if not s1 or not s2:
        return None, None
    min_len = min(len(s1), len(s2))
    matches = sum(1 for i in range(min_len) if s1[i] == s2[i])
    return matches, min_len


def get_k(s):
    if not s or len(s) < 28:
        return None
    return s[0] ^ s[13]


def main():
    # =========================================================================
    print("=" * 80)
    print("TEST 1: INCREMENTAL KEY EXTENSION — DOES APPENDING CHANGE GRADUALLY?")
    print("=" * 80)

    # If key navigation uses per-byte steps, extending the key should produce
    # a stream that's "one step further" from the previous
    base = "Sec"
    print(f"\n  Base key: '{base}'")
    prev_s = get_stream(base)
    time_mod.sleep(0.15)

    for ext in "ret99!XY":
        key = base + ext
        base = key
        s = get_stream(key)
        if prev_s and s:
            matches, total = stream_dist(prev_s, s)
            K = get_k(s)
            # XOR first block
            xor_block = [s[i] ^ prev_s[i] for i in range(min(14, total))]
            print(f"    '{key:12s}': K={K:3d}  match={matches}/{total}  "
                  f"block0_xor={xor_block}")
        prev_s = s
        time_mod.sleep(0.15)

    # =========================================================================
    print(f"\n{'=' * 80}")
    print("TEST 2: KEY PREFIX SHARING — DO SHARED PREFIXES PRODUCE CORRELATED STREAMS?")
    print("=" * 80)

    # If the key is hashed wholesale, shared prefix = no correlation
    # If per-byte navigation, shared prefix = shared initial navigation
    prefixes = ["Se", "Sec", "Secr", "Secre", "Secret"]
    print(f"\n  Keys with shared prefix 'Secret99' at different truncations:")
    streams = {}
    for prefix in prefixes:
        s = get_stream(prefix)
        streams[prefix] = s
        K = get_k(s)
        print(f"    '{prefix:8s}': K={K}  first4={s[:4] if s else 'None'}")
        time_mod.sleep(0.15)

    # And the full key
    s_full = get_stream("Secret99")
    streams["Secret99"] = s_full
    time_mod.sleep(0.15)

    # Compare all pairs
    print(f"\n  Pairwise comparison:")
    keys = list(streams.keys())
    for i in range(len(keys)):
        for j in range(i+1, len(keys)):
            matches, total = stream_dist(streams[keys[i]], streams[keys[j]])
            if matches is not None:
                pct = 100 * matches / total
                print(f"    '{keys[i]:8s}' vs '{keys[j]:8s}': {matches}/{total} match ({pct:.1f}%)")

    # =========================================================================
    print(f"\n{'=' * 80}")
    print("TEST 3: SINGLE-CHAR KEY b[0] VALUES — SYSTEMATIC ANALYSIS")
    print("=" * 80)

    # For single-char keys, K=0 so b[0]==b[13]. The b[0] value is the
    # final output of the key derivation pipeline. Can we reverse-engineer
    # the hash by comparing b[0] values?

    # Collect b[0] for all printable ASCII single-char keys
    b0_vals = {}
    for c in range(32, 127):
        key = chr(c)
        s = get_stream(key)
        if s:
            b0_vals[c] = s[0]
        time_mod.sleep(0.08)

    print(f"\n  b[0] values for single-char keys (K=0 for all):")
    # Print in groups of 16
    for row_start in range(32, 127, 16):
        chars = range(row_start, min(row_start + 16, 127))
        line = []
        for c in chars:
            if c in b0_vals:
                line.append(f"{b0_vals[c]:3d}")
            else:
                line.append("  -")
        print(f"  {row_start:3d}-{min(row_start+15, 126):3d}: {' '.join(line)}")

    # Check correlation with SHA-256
    print(f"\n  b[0] vs SHA-256[0] correlation:")
    sha256_matches = sum(1 for c in b0_vals if b0_vals[c] == hashlib.sha256(chr(c).encode()).digest()[0])
    print(f"    SHA-256[0] matches: {sha256_matches}/{len(b0_vals)}")

    # Check correlation with SHA-384
    sha384_matches = sum(1 for c in b0_vals if b0_vals[c] == hashlib.sha384(chr(c).encode()).digest()[0])
    print(f"    SHA-384[0] matches: {sha384_matches}/{len(b0_vals)}")

    # Check if b[0] is a simple function of the char code
    print(f"\n  b[0] XOR char_code (constant if b[0] = char XOR k):")
    xor_vals = [b0_vals[c] ^ c for c in sorted(b0_vals.keys())]
    print(f"    {len(set(xor_vals))} unique XOR values (out of {len(xor_vals)})")
    if len(set(xor_vals)) < 10:
        print(f"    XOR values: {sorted(set(xor_vals))}")

    # b[0] + char_code mod 256
    add_vals = [(b0_vals[c] + c) % 256 for c in sorted(b0_vals.keys())]
    print(f"    {len(set(add_vals))} unique (b[0]+char) mod 256 values")

    # =========================================================================
    print(f"\n{'=' * 80}")
    print("TEST 4: FOTP DEEP DIVE — WHAT DOES K=0 MEAN?")
    print("=" * 80)

    # FOTP changes the stream and sets K=0. Does it produce the same b[0] values
    # as single-char keys? Or different K=0 streams?

    print("\n  With FOTP='test', comparing different keys:")
    fotp_streams = {}
    for key in ["Secret99", "hello", "AB", "x"]:
        s = get_stream(key, extra_params={"fotp": "test"})
        K = get_k(s)
        fotp_streams[key] = s
        print(f"    key='{key:12s}': K={K}  b[0]={s[0] if s else 'N/A'}  first4={s[:4] if s else 'None'}")
        time_mod.sleep(0.15)

    # Compare FOTP streams with non-FOTP streams
    print(f"\n  FOTP='test' vs no-FOTP comparison:")
    for key in ["Secret99", "hello"]:
        s_no_fotp = get_stream(key)
        time_mod.sleep(0.15)
        s_fotp = fotp_streams.get(key)
        if s_no_fotp and s_fotp:
            matches, total = stream_dist(s_no_fotp, s_fotp)
            K_no = get_k(s_no_fotp)
            K_fotp = get_k(s_fotp)
            print(f"    '{key:12s}': K_no={K_no}  K_fotp={K_fotp}  "
                  f"match={matches}/{total}")

    # Are FOTP streams the same as single-char key streams?
    print(f"\n  FOTP='test',key='A' vs key='A' (no FOTP):")
    s_a_fotp = get_stream("A", extra_params={"fotp": "test"})
    time_mod.sleep(0.15)
    s_a = get_stream("A")
    time_mod.sleep(0.15)
    matches, total = stream_dist(s_a, s_a_fotp)
    print(f"    match={matches}/{total} {'SAME' if matches == total else 'DIFFERENT'}")

    # =========================================================================
    print(f"\n{'=' * 80}")
    print("TEST 5: REPEATED KEY 'A' — K VALUE BY LENGTH")
    print("=" * 80)

    # For 'A'×N keys, does K follow any pattern?
    print("\n  K values for 'A'*N:")
    k_by_len = {}
    for n in range(1, 33):
        key = 'A' * n
        s = get_stream(key)
        K = get_k(s)
        k_by_len[n] = K
        print(f"    N={n:2d}: K={K:3d}  ({K:08b})")
        time_mod.sleep(0.1)

    # Check for patterns in K
    # K XOR between consecutive lengths
    print(f"\n  K(N) XOR K(N+1):")
    for n in range(1, 32):
        if k_by_len.get(n) is not None and k_by_len.get(n+1) is not None:
            xor_val = k_by_len[n] ^ k_by_len[n+1]
            print(f"    K({n:2d}) ^ K({n+1:2d}) = {k_by_len[n]:3d} ^ {k_by_len[n+1]:3d} = {xor_val:3d}")

    # =========================================================================
    print(f"\n{'=' * 80}")
    print("TEST 6: KEY AS MANDELBROT COORDINATE — DIRECT PORTAL?")
    print("=" * 80)

    # What if very short keys (1-2 chars) are used directly as Mandelbrot coordinates?
    # For key='A' (0x41 = 65), could the portal be at (65/256, 0) or similar?
    # The stream would then come from iterating z²+c at that point.

    # We can test this by computing the Mandelbrot orbit at various potential
    # portal locations and checking if the orbit produces b[0] values matching
    # the observed single-char key b[0] values.

    # For now, just print the b[0] vs char code relationship
    print("\n  b[0] values and their relationship to char codes:")
    for c in [48, 49, 50, 65, 66, 67, 97, 98, 99]:  # '0','1','2','A','B','C','a','b','c'
        if c in b0_vals:
            # Check: b[0] mod various primes
            b0 = b0_vals[c]
            print(f"    '{chr(c)}' ({c}): b[0]={b0}  "
                  f"b0 mod 2={b0%2}  b0 mod 3={b0%3}  b0 mod 7={b0%7}  "
                  f"b0 mod 13={b0%13}  b0 mod 17={b0%17}")


if __name__ == "__main__":
    main()
