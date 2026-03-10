"""
Probe the FES server to understand the key expansion mechanism.

Strategy:
1. Test SHA-512 based key expansion hypotheses
2. Analyze related keys (differ by 1 char) for stream correlation
3. Test if key length affects the stream in predictable ways
4. Test context binding (which parameters change the portal/stream)
5. Compare phase transition boundaries across keys for patterns
"""

import base64
import hashlib
import json
import urllib.request
import urllib.parse
import time

API_URL = "https://portalz.solutions/fes.dna"
HEADERS = {
    "Content-Type": "application/x-www-form-urlencoded",
    "Referer": "https://portalz.solutions/fractalTransform.html",
    "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36",
}


def fes_request(key, payload="", dimensions=8, scramble="", depth="1", fotp=""):
    data = urllib.parse.urlencode({
        "mode": "1", "key": key, "payload": payload, "trans": "",
        "dimensions": str(dimensions), "depth": depth, "scramble": scramble,
        "xor": "on", "whirl": "", "asciiRange": "256", "FOTP": fotp,
    }).encode()
    req = urllib.request.Request(API_URL, data=data, headers=HEADERS)
    with urllib.request.urlopen(req) as resp:
        return json.loads(resp.read())


def b64_decode(s):
    padded = s + '=' * (4 - len(s) % 4) if len(s) % 4 else s
    return base64.b64decode(padded)


def get_stream(key, length, dimensions=8, fotp=""):
    known = 'A' * length
    result = fes_request(key, payload=known, dimensions=dimensions, fotp=fotp)
    ct_b64 = result.get("trans", "")
    if not ct_b64:
        return None
    ct = b64_decode(ct_b64)
    stream_rev = bytes(c ^ 0x41 for c in ct)
    return list(reversed(list(stream_rev)))


def sha512_hex(s):
    return hashlib.sha512(s.encode('utf-8')).hexdigest()


def sha512_bytes(s):
    return hashlib.sha512(s.encode('utf-8')).digest()


def main():
    # =========================================================================
    # TEST 1: SHA-512 output vs stream bytes — check for direct correlation
    # =========================================================================
    print("=" * 80)
    print("TEST 1: SHA-512 OUTPUT vs STREAM BYTES")
    print("=" * 80)

    test_keys = ["Secret99", "Secret98", "TestKey1", "abc", "password", "a"]

    for key in test_keys:
        sha = sha512_bytes(key)
        stream = get_stream(key, 12, dimensions=8)
        if not stream:
            continue

        # Check various SHA-512 derived values
        sha_first_12 = list(sha[:12])
        sha_xor = [(sha[i] ^ sha[i + 32]) for i in range(12)]
        sha_mod = [sha[i] % 256 for i in range(12)]  # trivially same as sha[i]

        # Silo index from first 2 bytes
        silo_idx = (sha[0] << 8) | sha[1]

        print(f"\n  Key: '{key}'")
        print(f"    SHA-512[:12]:  {sha_first_12}")
        print(f"    Stream[:12]:   {stream[:12]}")
        print(f"    SHA XOR half:  {sha_xor}")
        print(f"    Silo index:    {silo_idx} (0x{silo_idx:04x})")

        # Check for byte-level matches
        matches = sum(1 for a, b in zip(sha_first_12, stream) if a == b)
        xor_matches = sum(1 for a, b in zip(sha_xor, stream) if a == b)
        print(f"    Direct matches: {matches}/12, XOR-half matches: {xor_matches}/12")

        # Check for XOR relationship
        diff = [a ^ b for a, b in zip(sha_first_12, stream)]
        print(f"    SHA⊕Stream:    {diff}")

        time.sleep(0.3)

    # =========================================================================
    # TEST 2: Related keys — do similar keys produce related streams?
    # =========================================================================
    print(f"\n{'=' * 80}")
    print("TEST 2: RELATED KEY ANALYSIS")
    print("=" * 80)

    base_key = "Secret99"
    base_stream = get_stream(base_key, 24, dimensions=8)
    base_sha = sha512_bytes(base_key)
    print(f"\n  Base key: '{base_key}'")
    print(f"    Stream: {base_stream[:16]}")

    # Test keys that differ by 1 character
    related_keys = [
        "Secret98",  # last digit
        "Secret90",  # last digit
        "Secret00",  # last 2 digits
        "Tecret99",  # first char
        "secret99",  # case change
        "Secret9",   # shorter
        "Secret999", # longer
        "Secret99 ", # trailing space
    ]

    for rkey in related_keys:
        rstream = get_stream(rkey, 24, dimensions=8)
        if not rstream:
            continue

        # Hamming distance (byte-level)
        xor_dist = sum(1 for a, b in zip(base_stream[:16], rstream[:16]) if a != b)
        xor_sum = sum(bin(a ^ b).count('1') for a, b in zip(base_stream[:16], rstream[:16]))

        print(f"\n  Key: '{rkey}'")
        print(f"    Stream: {rstream[:16]}")
        print(f"    Byte differences: {xor_dist}/16, Bit differences: {xor_sum}/128")

        time.sleep(0.3)

    # =========================================================================
    # TEST 3: Key length sensitivity — empty key, 1-char, long keys
    # =========================================================================
    print(f"\n{'=' * 80}")
    print("TEST 3: KEY LENGTH SENSITIVITY")
    print("=" * 80)

    length_keys = ["", "a", "ab", "abc", "abcd", "abcde", "abcdef",
                   "a" * 16, "a" * 32, "a" * 64, "a" * 128]

    for key in length_keys:
        try:
            stream = get_stream(key, 12, dimensions=8)
            if stream:
                sha = sha512_bytes(key) if key else sha512_bytes("")
                print(f"  len={len(key):3d} key='{key[:20]}{'...' if len(key) > 20 else ''}': "
                      f"stream={stream[:8]}  sha[:4]={list(sha[:4])}")
        except Exception as e:
            print(f"  len={len(key):3d}: ERROR {e}")
        time.sleep(0.3)

    # =========================================================================
    # TEST 4: Iterated SHA-512 — does key expansion use multiple rounds?
    # =========================================================================
    print(f"\n{'=' * 80}")
    print("TEST 4: ITERATED SHA-512 ANALYSIS")
    print("=" * 80)

    key = "Secret99"
    stream = get_stream(key, 64, dimensions=8)
    print(f"  Key: '{key}', stream (64 bytes): {stream[:24]}...")

    # Compute iterated SHA-512
    h = hashlib.sha512(key.encode()).digest()
    for iteration in range(20):
        # Check if any 12-byte window of the hash matches any 12-byte window of stream
        h_list = list(h)

        # Simple check: does the hash (or a portion) appear in the stream?
        for offset in range(0, min(52, len(stream) - 12)):
            window = stream[offset:offset + 12]
            for h_offset in range(0, 52):
                h_window = h_list[h_offset:h_offset + 12]
                if len(h_window) == 12:
                    matches = sum(1 for a, b in zip(window, h_window) if a == b)
                    if matches >= 6:
                        print(f"    iter={iteration}, hash_off={h_offset}, "
                              f"stream_off={offset}: {matches}/12 matches")

        # Various SHA-512 chaining modes
        h = hashlib.sha512(h).digest()

    # =========================================================================
    # TEST 5: Context binding — which parameters affect the stream?
    # =========================================================================
    print(f"\n{'=' * 80}")
    print("TEST 5: CONTEXT BINDING — PARAMETER SENSITIVITY")
    print("=" * 80)

    key = "Secret99"
    ref_stream = get_stream(key, 12, dimensions=8)
    print(f"  Reference (dim=8): {ref_stream}")

    # Test: same key, different dimensions → different stream (already known)
    for dim in [2, 4, 6, 10, 12]:
        s = get_stream(key, 12, dimensions=dim)
        same = sum(1 for a, b in zip(ref_stream, s) if a == b)
        print(f"  dim={dim:2d}: {s}  (same={same}/12)")
        time.sleep(0.2)

    # Test: FOTP parameter
    for fotp_val in ["", "x", "ab", "test", "file.txt", "session123"]:
        s = get_stream(key, 12, dimensions=8, fotp=fotp_val)
        same = sum(1 for a, b in zip(ref_stream, s) if a == b)
        print(f"  fotp='{fotp_val:12s}': {s}  (same={same}/12)")
        time.sleep(0.2)

    # =========================================================================
    # TEST 6: SHA-512 with context strings — test plausible expansion formulas
    # =========================================================================
    print(f"\n{'=' * 80}")
    print("TEST 6: SHA-512 WITH CONTEXT STRINGS")
    print("=" * 80)

    key = "Secret99"
    stream = get_stream(key, 12, dimensions=8)
    print(f"  Target stream: {stream}")

    # Test various context-binding formulas
    formulas = [
        ("SHA512(key)", lambda k: hashlib.sha512(k.encode()).digest()),
        ("SHA512(key+dim)", lambda k: hashlib.sha512((k + "8").encode()).digest()),
        ("SHA512(key+'|8')", lambda k: hashlib.sha512((k + "|8").encode()).digest()),
        ("SHA512(key+chr(8))", lambda k: hashlib.sha512((k + chr(8)).encode()).digest()),
        ("SHA512('8'+key)", lambda k: hashlib.sha512(("8" + k).encode()).digest()),
        ("SHA512(key+b'\\x08')", lambda k: hashlib.sha512(k.encode() + b'\x08').digest()),
        ("SHA512(key+b'\\x00\\x08')", lambda k: hashlib.sha512(k.encode() + b'\x00\x08').digest()),
        ("HMAC-SHA512(key,'FES')", lambda k: __import__('hmac').new(k.encode(), b'FES', hashlib.sha512).digest()),
        ("HMAC-SHA512('FES',key)", lambda k: __import__('hmac').new(b'FES', k.encode(), hashlib.sha512).digest()),
        ("SHA512(key+key)", lambda k: hashlib.sha512((k + k).encode()).digest()),
        ("SHA512(SHA512(key))", lambda k: hashlib.sha512(hashlib.sha512(k.encode()).digest()).digest()),
        ("MD5(key)", lambda k: hashlib.md5(k.encode()).digest()),
    ]

    for name, func in formulas:
        try:
            h = func(key)
            h_list = list(h[:12])
            matches = sum(1 for a, b in zip(h_list, stream) if a == b)
            xor = [a ^ b for a, b in zip(h_list, stream)]
            print(f"  {name:35s}: {h_list}  matches={matches}")
            if matches >= 3:
                print(f"    {'':35s}  xor={xor}")
        except Exception as e:
            print(f"  {name:35s}: ERROR {e}")

    # =========================================================================
    # TEST 7: Phase transition boundary analysis across many keys
    # =========================================================================
    print(f"\n{'=' * 80}")
    print("TEST 7: PHASE TRANSITION BOUNDARIES vs SHA-512")
    print("=" * 80)

    # For each key, find the first phase transition in dim=2
    # (dim=2 is simplest — only 1 dimension pair)
    for key in ["Secret99", "Secret98", "abc", "test", "password", "key1"]:
        sha = sha512_bytes(key)
        # Get streams at increasing lengths to find first transition
        prev_stream_0 = None
        transitions = []

        for length in range(10, 120, 2):
            try:
                s = get_stream(key, length, dimensions=2)
                if s and prev_stream_0 is not None:
                    if s[0] != prev_stream_0:
                        transitions.append(length)
                if s:
                    prev_stream_0 = s[0]
            except Exception:
                pass
            time.sleep(0.15)

        # Also check dim=8
        prev_stream_0 = None
        transitions_d8 = []
        for length in range(10, 120, 2):
            try:
                s = get_stream(key, length, dimensions=8)
                if s and prev_stream_0 is not None:
                    if s[0] != prev_stream_0:
                        transitions_d8.append(length)
                if s:
                    prev_stream_0 = s[0]
            except Exception:
                pass
            time.sleep(0.15)

        sha_val = int.from_bytes(sha[:4], 'big')
        print(f"  Key '{key:12s}': sha[:4]=0x{sha[:4].hex()}={sha_val}")
        print(f"    dim=2 transitions: {transitions}")
        print(f"    dim=8 transitions: {transitions_d8}")

        # Check if transitions correlate with SHA values
        if transitions:
            for t in transitions:
                print(f"    t={t}: t mod 28 = {t % 28}, t mod 12 = {t % 12}, "
                      f"sha[0] mod t = {sha[0] % t if t > 0 else 'N/A'}")


if __name__ == "__main__":
    main()
