"""
Probe the key derivation function more directly.

Strategy: instead of trying to match hash outputs to stream bytes (which the
mixing function blocks), focus on BEHAVIORAL clues:

1. Does the server hash the key or use it raw? (test binary/unicode keys)
2. Is the key truncated at some length? (test very long keys with shared prefix)
3. Does the server normalize the key? (whitespace, encoding)
4. Timing analysis with controlled server load (multiple calls, different key sizes)
5. Does the server concatenate key+config before hashing? (test config sensitivity)
6. Does the stream depend on the key STRING or its SHA-512? (compare key="A" vs key=SHA512("A"))
7. Test FOTP interaction with key derivation
8. Test if key is used directly as Mandelbrot coordinates for short keys
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
    start = time_mod.time()
    with urllib.request.urlopen(req, timeout=30) as resp:
        result = json.loads(resp.read())
    elapsed = time_mod.time() - start
    ct_b64 = result.get("trans", "")
    if not ct_b64:
        return None, elapsed
    padded = ct_b64 + '=' * (4 - len(ct_b64) % 4) if len(ct_b64) % 4 else ct_b64
    ct = base64.b64decode(padded)
    stream_rev = bytes(c ^ 0x41 for c in ct)
    return list(reversed(list(stream_rev))), elapsed


def stream_eq(s1, s2):
    if s1 is None or s2 is None:
        return False
    return s1 == s2


def main():
    # =========================================================================
    print("=" * 80)
    print("TEST 1: KEY TRUNCATION — AT WHAT LENGTH DO KEYS STOP MATTERING?")
    print("=" * 80)

    # If the key is hashed, ALL bytes should matter. If truncated at N bytes,
    # keys longer than N with the same prefix should produce identical streams.
    base = "A" * 100
    print(f"\n  Testing key lengths with same base character 'A':")
    prev_s = None
    for length in [1, 2, 4, 8, 16, 32, 48, 64, 80, 96, 100, 128, 200, 256, 500]:
        key = 'A' * length
        s, elapsed = get_stream(key, 42, 2)
        same_as_prev = stream_eq(s, prev_s) if prev_s else False
        K = (s[0] ^ s[13]) if s and len(s) >= 14 else None
        print(f"    len={length:4d}: K={K:3d}  time={elapsed*1000:.0f}ms  "
              f"{'SAME AS PREV' if same_as_prev else 'DIFFERENT'}"
              f"  first3={s[:3] if s else 'None'}")
        prev_s = s
        time_mod.sleep(0.15)

    # Test with different suffix but same prefix
    print(f"\n  Same 64-char prefix, different suffix:")
    prefix = "X" * 64
    ref_s, _ = get_stream(prefix + "Y", 42, 2)
    time_mod.sleep(0.15)
    for suffix in ["Z", "YY", "YZ", "1234"]:
        s, _ = get_stream(prefix + suffix, 42, 2)
        same = stream_eq(s, ref_s)
        print(f"    '{prefix[:4]}...'+'{suffix}': {'SAME' if same else 'DIFFERENT'}")
        time_mod.sleep(0.15)

    # =========================================================================
    print(f"\n{'=' * 80}")
    print("TEST 2: KEY NORMALIZATION — WHITESPACE, NULL BYTES, ENCODING")
    print("=" * 80)

    ref, _ = get_stream("test", 42, 2)
    time_mod.sleep(0.15)

    tests = [
        ("test ", "trailing space"),
        (" test", "leading space"),
        ("test\t", "trailing tab"),
        ("test\n", "trailing newline"),
        ("test\x00", "trailing null"),
        ("TEST", "uppercase"),
        ("Test", "mixed case"),
    ]
    for key, desc in tests:
        s, _ = get_stream(key, 42, 2)
        same = stream_eq(s, ref)
        print(f"  '{desc:20s}': {'SAME as \"test\"' if same else 'DIFFERENT'}")
        time_mod.sleep(0.15)

    # =========================================================================
    print(f"\n{'=' * 80}")
    print("TEST 3: IS KEY USED RAW OR HASHED?")
    print("=" * 80)

    # If key is used raw, SHA-512("A") (64 bytes) as key should differ from "A" (1 byte)
    # If key is first hashed with SHA-512, then SHA-512(SHA-512("A")) would be used
    # for the 64-byte key, vs SHA-512("A") for the 1-byte key

    print("\n  Comparing key='A' vs key=hex(SHA-512('A')):")
    s_a, _ = get_stream("A", 42, 2)
    time_mod.sleep(0.15)
    sha_a = hashlib.sha512(b"A").hexdigest()
    s_sha, _ = get_stream(sha_a, 42, 2)
    time_mod.sleep(0.15)
    print(f"    key='A':         first3={s_a[:3] if s_a else 'None'}")
    print(f"    key=SHA512('A'): first3={s_sha[:3] if s_sha else 'None'}")
    print(f"    Same: {stream_eq(s_a, s_sha)}")

    # Try raw SHA-512 bytes as key (may not work due to encoding)
    sha_a_bytes = hashlib.sha512(b"A").digest()
    sha_a_latin1 = sha_a_bytes.decode('latin-1')
    s_sha_raw, _ = get_stream(sha_a_latin1, 42, 2)
    time_mod.sleep(0.15)
    print(f"    key=SHA512('A') raw bytes (latin1): "
          f"{'SAME as A' if stream_eq(s_a, s_sha_raw) else 'DIFFERENT from A'}")

    # =========================================================================
    print(f"\n{'=' * 80}")
    print("TEST 4: EMPTY KEY AND MINIMAL KEYS")
    print("=" * 80)

    for key in ["", " ", "\x00", "0", "1", "\x01", "\xff"]:
        s, _ = get_stream(key, 42, 2)
        K = (s[0] ^ s[13]) if s and len(s) >= 14 else None
        repr_key = repr(key)
        print(f"  key={repr_key:10s}: K={K}  first3={s[:3] if s else 'None'}")
        time_mod.sleep(0.15)

    # =========================================================================
    print(f"\n{'=' * 80}")
    print("TEST 5: DIMENSION SENSITIVITY — DOES dim AFFECT KEY EXPANSION?")
    print("=" * 80)

    # If key expansion produces different material per dim, the per-pair portals
    # change with dim. If expansion is dim-independent, per-pair portals are fixed.
    key = "Secret99"
    print(f"\n  Key '{key}': block 0 at different dims")
    for dim in [2, 4, 6, 8, 10, 12]:
        s, _ = get_stream(key, 42, dim)
        if s:
            K = s[0] ^ s[13]
            print(f"    dim={dim:2d}: K={K:3d}  block0[:7]={s[:7]}")
        time_mod.sleep(0.15)

    # =========================================================================
    print(f"\n{'=' * 80}")
    print("TEST 6: FOTP EFFECT ON KEY DERIVATION")
    print("=" * 80)

    key = "Secret99"
    ref, _ = get_stream(key, 42, 2)
    time_mod.sleep(0.15)

    print(f"\n  Key '{key}', dim=2:")
    for fotp in ["", "x", "xx", "abc", "def", "test123"]:
        s, _ = get_stream(key, 42, 2, extra_params={"fotp": fotp})
        same = stream_eq(s, ref)
        K = (s[0] ^ s[13]) if s and len(s) >= 14 else None
        print(f"    FOTP='{fotp:8s}': K={K}  {'SAME as empty' if same else 'DIFFERENT'}")
        time_mod.sleep(0.15)

    # Compare two non-empty FOTPs
    s_abc, _ = get_stream(key, 42, 2, extra_params={"fotp": "abc"})
    time_mod.sleep(0.15)
    s_def, _ = get_stream(key, 42, 2, extra_params={"fotp": "def"})
    print(f"    FOTP 'abc' vs 'def': {'SAME' if stream_eq(s_abc, s_def) else 'DIFFERENT'}")

    # =========================================================================
    print(f"\n{'=' * 80}")
    print("TEST 7: KEY BYTE ORDER — IS IT COMMUTATIVE?")
    print("=" * 80)

    # If key derivation is hash-based, key byte order matters.
    # If it's some symmetric function (e.g., XOR of bytes), order wouldn't matter.
    pairs = [("AB", "BA"), ("12", "21"), ("abc", "cba"),
             ("test", "tset"), ("xy", "yx")]
    for k1, k2 in pairs:
        s1, _ = get_stream(k1, 42, 2)
        time_mod.sleep(0.15)
        s2, _ = get_stream(k2, 42, 2)
        time_mod.sleep(0.15)
        same = stream_eq(s1, s2)
        print(f"  '{k1}' vs '{k2}': {'SAME (commutative!)' if same else 'DIFFERENT (order matters)'}")

    # =========================================================================
    print(f"\n{'=' * 80}")
    print("TEST 8: PRECISE TIMING ANALYSIS")
    print("=" * 80)

    # If KDF uses iterative hashing (PBKDF2-style), timing should scale with
    # iteration count. Test multiple rounds of timing.
    print("\n  Precise timing (5 rounds each):")
    for key_len in [1, 8, 32, 128, 512]:
        key = "X" * key_len
        times = []
        for _ in range(5):
            _, elapsed = get_stream(key, 14, 2)
            times.append(elapsed)
            time_mod.sleep(0.05)
        avg = sum(times) / len(times)
        std = (sum((t - avg)**2 for t in times) / len(times)) ** 0.5
        min_t = min(times)
        max_t = max(times)
        print(f"    key_len={key_len:4d}: avg={avg*1000:.0f}ms  "
              f"std={std*1000:.0f}ms  min={min_t*1000:.0f}ms  max={max_t*1000:.0f}ms")

    # =========================================================================
    print(f"\n{'=' * 80}")
    print("TEST 9: KEY MATERIAL — COMPLETE FIRST BLOCK FOR SYSTEMATIC KEYS")
    print("=" * 80)

    # Get the complete first block for keys "00" through "09" and "A0" through "A9"
    # and look for ANY pattern in the raw byte values
    print("\n  First block (14 bytes) for sequential 2-digit keys:")
    for prefix in ["", "A"]:
        print(f"\n  Prefix='{prefix}':")
        blocks = {}
        for d in range(10):
            key = f"{prefix}{d}"
            s, _ = get_stream(key, 42, 2)
            if s:
                blocks[d] = s[:14]
                K = s[0] ^ s[13]
                print(f"    '{key}': K={K:3d}  block={s[:14]}")
            time_mod.sleep(0.1)

        # For each byte position, check if the value is related to the digit
        if len(blocks) >= 10:
            print(f"\n  Position-wise analysis:")
            for pos in range(14):
                vals = [blocks[d][pos] for d in range(10)]
                diffs = [vals[i+1] - vals[i] for i in range(9)]
                print(f"    pos={pos:2d}: vals={vals}  diffs={diffs}")


if __name__ == "__main__":
    main()
