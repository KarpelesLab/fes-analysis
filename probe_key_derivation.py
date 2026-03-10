"""
Probe FES key derivation to determine how password → portal mapping works.

Known from docs:
1. Key is hashed (algorithm unknown, "iterations of SHA512" claimed)
2. Hash split: 16-bit silo index + xm offset + ym offset
3. Silo lookup: index → base (x, y) from 65,536 entries
4. Offsets scaled to 0.01 and added → Entry Portal
5. Navigation using original key bytes → Fractal Portal

Known test vector (from FT-Explained.pdf):
  Key: "Secret99"
  Portal: x = -2.0890747618095770104082504287
          y = -0.0868059720835475839205932798

Strategy:
- Test hash algorithm (SHA-512, SHA-256, etc.)
- Test context binding (does dimension param affect key expansion?)
- Test key-byte navigation hypothesis
- Try to compute stream from known portal
"""

import base64
import hashlib
import json
import math
import struct
import sys
import time
import urllib.request
import urllib.parse
from decimal import Decimal, getcontext

# High precision for Mandelbrot computations
getcontext().prec = 60

API_URL = "https://portalz.solutions/fes.dna"
HEADERS = {
    "Content-Type": "application/x-www-form-urlencoded",
    "Referer": "https://portalz.solutions/fractalTransform.html",
    "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36",
}


def fes_request(key, payload="", trans="", dimensions=8, scramble=False,
                mode=1, depth=3):
    data = urllib.parse.urlencode({
        "mode": str(mode),
        "key": key,
        "payload": payload,
        "trans": trans,
        "dimensions": str(dimensions),
        "depth": str(depth),
        "scramble": "on" if scramble else "",
        "xor": "on",
        "whirl": "",
        "asciiRange": "256",
    }).encode()
    req = urllib.request.Request(API_URL, data=data, headers=HEADERS)
    with urllib.request.urlopen(req) as resp:
        return json.loads(resp.read())


def b64_decode(s):
    padded = s + '=' * (4 - len(s) % 4) if len(s) % 4 else s
    return base64.b64decode(padded)


def extract_stream(key, length, dimensions=8):
    """Extract keystream by encrypting known plaintext."""
    known = 'A' * length
    result = fes_request(key, payload=known, dimensions=dimensions)
    ct_b64 = result.get("trans", "")
    if not ct_b64:
        return None
    ct = b64_decode(ct_b64)
    stream_rev = bytes(c ^ 0x41 for c in ct)
    return bytes(reversed(stream_rev))


# ============================================================
# EXPERIMENT 1: Hash algorithm identification
# ============================================================

def experiment_hash_algorithms():
    """Compute various hashes of test keys to see which produces
    consistent mapping indices."""
    print("=" * 70)
    print("EXPERIMENT 1: Hash Algorithm Identification")
    print("=" * 70)

    key = "Secret99"
    key_bytes = key.encode('utf-8')

    hashes = {
        "SHA-512": hashlib.sha512(key_bytes).digest(),
        "SHA-256": hashlib.sha256(key_bytes).digest(),
        "SHA-384": hashlib.sha384(key_bytes).digest(),
        "SHA3-256": hashlib.sha3_256(key_bytes).digest(),
        "SHA3-512": hashlib.sha3_512(key_bytes).digest(),
        "MD5": hashlib.md5(key_bytes).digest(),
        "BLAKE2b": hashlib.blake2b(key_bytes).digest(),
        "BLAKE2s": hashlib.blake2s(key_bytes).digest(),
        "SHA-512(2x)": hashlib.sha512(hashlib.sha512(key_bytes).digest()).digest(),
    }

    print(f"\n  Key: '{key}' ({list(key_bytes)})")
    for name, h in hashes.items():
        idx = (h[0] << 8) | h[1]
        print(f"  {name:15s}: first_16_bits={idx:5d} (0x{h[0]:02x}{h[1]:02x})  "
              f"hex={h[:8].hex()}")

    # Also try with different key encodings
    print(f"\n  Alternate encodings:")
    for desc, kb in [
        ("utf-8", key.encode('utf-8')),
        ("ascii", key.encode('ascii')),
        ("utf-16", key.encode('utf-16')),
        ("utf-16-le", key.encode('utf-16-le')),
        ("latin-1", key.encode('latin-1')),
    ]:
        h = hashlib.sha512(kb).digest()
        idx = (h[0] << 8) | h[1]
        print(f"  SHA-512({desc:10s}): first_16_bits={idx:5d}  hex={h[:8].hex()}")


# ============================================================
# EXPERIMENT 2: Context binding - does dimensions affect key?
# ============================================================

def experiment_context_binding():
    """Test if changing dimensions/depth/other params changes the keystream
    in a way consistent with context binding vs separate code paths."""
    print("\n" + "=" * 70)
    print("EXPERIMENT 2: Context Binding Detection")
    print("=" * 70)

    # If context binding: same key + different config → completely different stream
    # If no context binding: same key → same portal → stream differs only due to
    #   how many dimension pairs contribute

    keys = ["Secret99", "TestKey1", "probe_0001"]

    for key in keys:
        print(f"\n  Key: '{key}'")
        streams = {}
        for dim in [8, 10, 12, 14, 16]:
            stream = extract_stream(key, 20, dimensions=dim)
            if stream:
                streams[dim] = stream
                print(f"    dim={dim:2d}: {list(stream[:12])}")
            time.sleep(0.1)

        # Check: is dim=8 stream a subset/superset of dim=16?
        # If no context binding, the first 4 dimension pairs should produce
        # the same bytes regardless of total dimensions
        if 8 in streams and 16 in streams:
            s8 = streams[8]
            s16 = streams[16]
            matching = sum(1 for a, b in zip(s8, s16) if a == b)
            print(f"    dim=8 vs dim=16: {matching}/20 bytes match")

        # Check odd dimensions (9, 11) - if supported
        for dim in [9, 11]:
            stream = extract_stream(key, 20, dimensions=dim)
            if stream:
                streams[dim] = stream
                print(f"    dim={dim:2d}: {list(stream[:12])}")
                if 8 in streams:
                    matching = sum(1 for a, b in zip(streams[8], stream) if a == b)
                    print(f"    dim=8 vs dim={dim}: {matching}/20 match")
            time.sleep(0.1)


# ============================================================
# EXPERIMENT 3: Key-byte navigation verification
# ============================================================

def experiment_key_navigation():
    """Test if the original key bytes affect the stream (beyond the hash).

    Strategy: Find keys where the hash (first N bits) is identical but
    the raw key bytes differ. If navigation uses raw key bytes, streams differ.

    We can't find SHA-512 collisions, but we can test:
    - Keys of different lengths that happen to share expanded key prefix
    - Whether key length itself affects the stream
    """
    print("\n" + "=" * 70)
    print("EXPERIMENT 3: Key-Byte Navigation Effect")
    print("=" * 70)

    # Test: Does appending null-like characters change the stream?
    # If navigation iterates over each byte, longer keys navigate further
    base_keys = ["Secret99", "TestKey1"]
    for base in base_keys:
        print(f"\n  Base key: '{base}'")
        streams = {}
        for suffix in ["", " ", "  ", "   ", "a", "aa", "aaa"]:
            key = base + suffix
            stream = extract_stream(key, 20)
            if stream:
                streams[key] = stream
                print(f"    '{key:20s}': {list(stream[:10])}")
            time.sleep(0.1)

        # All should be completely different (hash changes with any suffix)
        # This doesn't isolate the navigation effect from the hash change
        # But it confirms the server handles key variations

    # Better test: Find two keys with VERY similar SHA-512 hashes
    # (matching in first 2 bytes = same silo index)
    print("\n  Looking for same-silo-index key pairs with different lengths...")
    from collections import defaultdict
    index_map = defaultdict(list)
    for i in range(20000):
        for prefix in ["k", "kk", "kkk"]:
            key = f"{prefix}{i}"
            h = hashlib.sha512(key.encode()).digest()
            idx = (h[0] << 8) | h[1]
            index_map[idx].append(key)

    # Find indices with keys of different lengths
    found = 0
    for idx, keys in index_map.items():
        lengths = set(len(k) for k in keys)
        if len(lengths) >= 2:
            # Pick one key of each length
            by_len = {}
            for k in keys:
                by_len.setdefault(len(k), k)
            if len(by_len) >= 2:
                test_keys = list(by_len.values())[:3]
                print(f"\n  Silo index {idx}: testing keys of different lengths")
                for k in test_keys:
                    h = hashlib.sha512(k.encode()).digest()
                    stream = extract_stream(k, 20)
                    if stream:
                        print(f"    '{k}' (len={len(k)}) sha512[:4]={h[:4].hex()} "
                              f"stream[:8]={list(stream[:8])}")
                    time.sleep(0.1)
                found += 1
                if found >= 3:
                    break


# ============================================================
# EXPERIMENT 4: Verify stream generation from known portal
# ============================================================

def experiment_portal_to_stream():
    """Try to compute the keystream from the known Secret99 portal.

    Known: portal at (-2.0890747618095770104082504287, -0.0868059720835475839205932798)
    Known: fractal value ≈ 5874.727 for first iteration

    Test: What formula produces 5874.727 from this portal?
    """
    print("\n" + "=" * 70)
    print("EXPERIMENT 4: Portal → Stream Computation")
    print("=" * 70)

    cx = Decimal("-2.0890747618095770104082504287")
    cy = Decimal("-0.0868059720835475839205932798")

    print(f"  Portal: ({cx}, {cy})")

    # Standard Mandelbrot: z = z² + c, starting from z = 0
    zx = Decimal(0)
    zy = Decimal(0)

    for i in range(10):
        # z = z² + c
        new_zx = zx * zx - zy * zy + cx
        new_zy = 2 * zx * zy + cy
        zx, zy = new_zx, new_zy

        mag_sq = zx * zx + zy * zy
        mag = mag_sq.sqrt()
        angle = None
        if float(zx) != 0 or float(zy) != 0:
            angle = math.atan2(float(zy), float(zx)) * 180 / math.pi
            if angle < 0:
                angle += 360

        print(f"  iter {i+1}: z=({zx:.20f}, {zy:.20f})")
        print(f"           |z|²={mag_sq:.10f}  |z|={mag:.10f}  "
              f"angle={angle:.5f}°" if angle else "")

        # Check various "fractal value" definitions
        fv_candidates = {
            "|z|²": float(mag_sq),
            "|z|": float(mag),
            "zx": float(zx),
            "|zx|+|zy|": abs(float(zx)) + abs(float(zy)),
            "zx²": float(zx * zx),
        }

        for name, val in fv_candidates.items():
            if 5870 < val < 5880:
                print(f"           *** MATCH candidate: {name} = {val:.6f} "
                      f"(target: 5874.727)")

    # Get actual server stream for comparison
    print("\n  Getting server stream for Secret99...")
    stream = extract_stream("Secret99", 20)
    if stream:
        print(f"  Server stream (20 bytes): {list(stream)}")
        print(f"  stream[0] = {stream[0]} (= 5874 mod 256 = {5874 % 256}? "
              f"{'YES!' if stream[0] == 5874 % 256 else 'No'})")

        # FT-Explained shows fractal value 5874.7274351297
        # stream byte = int(fractal_value) mod 256
        fv = 5874
        print(f"  5874 mod 256 = {fv % 256}")
        # Try other extractions
        print(f"  5874 mod 256 = {5874 % 256} (= {5874 % 256})")
        print(f"  5875 mod 256 = {5875 % 256}")

    # Now try with the portal from Secret98 (also from FT-Explained)
    print("\n  Getting server stream for Secret98...")
    stream98 = extract_stream("Secret98", 20)
    if stream98:
        print(f"  Server stream: {list(stream98)}")


# ============================================================
# EXPERIMENT 5: Hash iteration count
# ============================================================

def experiment_hash_iterations():
    """Test if the key expansion uses multiple rounds of hashing.

    If the server uses SHA-512(SHA-512(...(key)...)) N times,
    we can try to identify N by looking for patterns.
    """
    print("\n" + "=" * 70)
    print("EXPERIMENT 5: Hash Iteration Count")
    print("=" * 70)

    # For key "Secret99", compute iterated SHA-512
    key = b"Secret99"
    h = key
    print(f"  Key: 'Secret99'")
    for i in range(10):
        h = hashlib.sha512(h).digest()
        idx = (h[0] << 8) | h[1]
        print(f"  SHA-512 round {i+1}: idx={idx:5d}  first_bytes={h[:6].hex()}")


# ============================================================
# EXPERIMENT 6: Test if FOTP is part of key expansion
# ============================================================

def experiment_fotp_context():
    """Test how FOTP affects key expansion.

    We know FOTP acts as boolean. But does it change the hash input
    or just flip a bit somewhere?
    """
    print("\n" + "=" * 70)
    print("EXPERIMENT 6: FOTP Effect on Key Expansion")
    print("=" * 70)

    key = "Secret99"
    length = 20

    # Get stream without FOTP
    stream_base = extract_stream(key, length)
    print(f"  No FOTP:     {list(stream_base[:12])}")

    # Get stream with FOTP
    known = 'A' * length
    for fotp_val in ["test", "abc", "xyz", "12345"]:
        data = urllib.parse.urlencode({
            "mode": "1",
            "key": key,
            "payload": known,
            "trans": "",
            "dimensions": "8",
            "depth": "3",
            "scramble": "",
            "xor": "on",
            "whirl": "",
            "asciiRange": "256",
            "fotp": fotp_val,
        }).encode()
        req = urllib.request.Request(API_URL, data=data, headers=HEADERS)
        with urllib.request.urlopen(req) as resp:
            result = json.loads(resp.read())
        ct = b64_decode(result.get("trans", ""))
        stream_rev = bytes(c ^ 0x41 for c in ct)
        stream = bytes(reversed(stream_rev))
        matching = sum(1 for a, b in zip(stream_base, stream) if a == b)
        print(f"  FOTP='{fotp_val}': {list(stream[:12])}  ({matching}/20 match base)")
        time.sleep(0.1)

    # All FOTP values should produce identical streams (boolean behavior)
    # But different from no-FOTP


# ============================================================
# EXPERIMENT 7: Expanded key bytes → stream bytes relationship
# ============================================================

def experiment_key_to_stream_mapping():
    """Look for direct mathematical relationship between expanded key and stream.

    The spec says the expanded key is split per dimension pair into:
    - 16-bit silo index (for the pair)
    - x offset bytes
    - y offset bytes

    With 8 dimensions (4 pairs), the first pair uses the first chunk of
    expanded key. If we can find keys where only specific chunks change,
    we can isolate which part of the expanded key affects which stream bytes.
    """
    print("\n" + "=" * 70)
    print("EXPERIMENT 7: Key Chunk → Stream Byte Isolation")
    print("=" * 70)

    # Load existing data
    try:
        with open("data/stream_data.json") as f:
            data = json.load(f)
        entries = data["keys"]
        print(f"  Loaded {len(entries)} existing entries")
    except FileNotFoundError:
        print("  No existing data found, skipping")
        return

    # For each pair of entries with same first 4 expanded key bytes but different
    # subsequent bytes, check if streams share any prefix
    from collections import defaultdict
    by_prefix = defaultdict(list)
    for e in entries:
        prefix = tuple(e["expanded_key"][:4])  # first 4 bytes
        by_prefix[prefix].append(e)

    shared = {k: v for k, v in by_prefix.items() if len(v) >= 2}
    print(f"  Groups sharing first 4 expanded key bytes: {len(shared)}")

    for prefix, group in list(shared.items())[:5]:
        print(f"\n  Prefix {list(prefix)}:")
        for e in group[:3]:
            print(f"    key='{e['key']}' exp[4:10]={e['expanded_key'][4:10]} "
                  f"stream[:8]={e['stream'][:8]}")


# ============================================================
# EXPERIMENT 8: Single-byte keys (minimal navigation)
# ============================================================

def experiment_single_byte_keys():
    """Test single-character keys to minimize the navigation step.

    If navigation uses original key bytes, a 1-byte key has only 1
    navigation step. An empty key might have 0 navigation steps,
    giving us the raw Entry Portal.
    """
    print("\n" + "=" * 70)
    print("EXPERIMENT 8: Minimal Keys (Short Navigation)")
    print("=" * 70)

    test_keys = [
        "",           # empty - might skip navigation entirely
        "A",          # 1 byte
        "AA",         # 2 bytes (same byte repeated)
        "AB",         # 2 bytes (different)
        "AAA",        # 3 bytes
        "AAAA",       # 4 bytes
        "AAAAA",      # 5 bytes
        "AAAAAA",     # 6 bytes
        "AAAAAAA",    # 7 bytes
        "AAAAAAAA",   # 8 bytes
        "B",          # different single byte
        "C",
        "a",
        "b",
    ]

    results = {}
    for key in test_keys:
        stream = extract_stream(key, 20)
        if stream:
            results[key] = stream
            h = hashlib.sha512(key.encode()).digest()
            idx = (h[0] << 8) | h[1]
            print(f"  key='{key:10s}' (len={len(key)}) sha512_idx={idx:5d} "
                  f"stream[:10]={list(stream[:10])}")
        else:
            print(f"  key='{key:10s}' (len={len(key)}) — empty response")
        time.sleep(0.1)

    # Check if "A" and "AA" streams are related
    # If navigation adds a step, the streams should be completely different
    if "A" in results and "AA" in results:
        matching = sum(1 for a, b in zip(results["A"], results["AA"]) if a == b)
        print(f"\n  'A' vs 'AA': {matching}/20 bytes match")
    if "A" in results and "B" in results:
        matching = sum(1 for a, b in zip(results["A"], results["B"]) if a == b)
        print(f"  'A' vs 'B': {matching}/20 bytes match")


# ============================================================
# EXPERIMENT 9: Key = hash input vs. hash output
# ============================================================

def experiment_hash_input_format():
    """Test if the server hashes the key as-is or does preprocessing.

    Compare: key "Secret99" vs key that IS the SHA-512 of "Secret99".
    If the server just hashes whatever you send, these should produce
    completely different streams. If the server checks for pre-hashed
    input, they might be related.
    """
    print("\n" + "=" * 70)
    print("EXPERIMENT 9: Key Input Preprocessing")
    print("=" * 70)

    key1 = "Secret99"
    h1 = hashlib.sha512(key1.encode()).hexdigest()
    key2 = h1  # Use the hex-encoded hash as a key

    s1 = extract_stream(key1, 20)
    time.sleep(0.1)
    s2 = extract_stream(key2, 20)

    if s1 and s2:
        print(f"  key='Secret99':     stream[:10]={list(s1[:10])}")
        print(f"  key=sha512(above):  stream[:10]={list(s2[:10])}")
        matching = sum(1 for a, b in zip(s1, s2) if a == b)
        print(f"  Match: {matching}/20 bytes (0 expected if server hashes input)")


# ============================================================
# EXPERIMENT 10: Dimension pair isolation
# ============================================================

def experiment_dimension_pair_isolation():
    """With dim=2 (1 pair), the stream comes from a single dimension pair.
    With dim=4 (2 pairs), it comes from 2 pairs. Does the dim=2 stream
    appear as a subsequence of the dim=4 stream?

    This tests whether dimension pairs generate stream bytes independently
    and whether the silo index is per-pair or global.
    """
    print("\n" + "=" * 70)
    print("EXPERIMENT 10: Dimension Pair Isolation")
    print("=" * 70)

    keys = ["Secret99", "TestKey1", "probe_0001"]
    for key in keys:
        print(f"\n  Key: '{key}'")
        streams = {}
        for dim in [2, 4, 6, 8]:
            stream = extract_stream(key, 20, dimensions=dim)
            if stream:
                streams[dim] = stream
                print(f"    dim={dim}: {list(stream[:16])}")
            time.sleep(0.15)

        # Check interleaving patterns
        if 2 in streams and 4 in streams:
            s2 = streams[2]
            s4 = streams[4]
            # Test: are even positions of dim=4 the same as dim=2?
            even_match = sum(1 for i in range(0, 20, 2)
                            if i < len(s4) and i//2 < len(s2) and s4[i] == s2[i//2])
            # Test: are odd positions of dim=4 from the second pair?
            print(f"    dim=2 vs dim=4 even positions: {even_match} matches")

            # Or maybe the bytes are just concatenated per iteration
            # dim=2 gives B bytes/iter, dim=4 gives 2B bytes/iter
            # and the first B bytes of dim=4 might match dim=2
            prefix_match = sum(1 for a, b in zip(s2, s4) if a == b)
            print(f"    dim=2 vs dim=4 prefix: {prefix_match}/20 match")


def main():
    tests = {
        "hash": experiment_hash_algorithms,
        "context": experiment_context_binding,
        "nav": experiment_key_navigation,
        "portal": experiment_portal_to_stream,
        "iterations": experiment_hash_iterations,
        "fotp": experiment_fotp_context,
        "mapping": experiment_key_to_stream_mapping,
        "minkey": experiment_single_byte_keys,
        "hashinput": experiment_hash_input_format,
        "dimpair": experiment_dimension_pair_isolation,
    }

    if len(sys.argv) > 1:
        selected = sys.argv[1:]
        if selected == ["all"]:
            selected = list(tests.keys())
    else:
        # Default: run offline experiments first
        selected = ["hash", "iterations", "mapping"]

    for name in selected:
        if name not in tests:
            print(f"Unknown test: {name}")
            print(f"Available: {', '.join(tests.keys())}")
            sys.exit(1)
        try:
            tests[name]()
        except Exception as e:
            print(f"\n  ERROR in {name}: {e}")
            import traceback
            traceback.print_exc()
        print()


if __name__ == "__main__":
    main()
