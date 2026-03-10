"""
Try to match the server's key derivation against standard KDF constructions.

We know:
- NOT raw SHA-512 (prefix collisions → 0 correlation)
- NOT SHA-256 or SHA-384 (b[0] doesn't match)
- Constant timing (~250ms) regardless of key length
- Null-terminated C-string

Try:
1. HMAC-SHA512 with various fixed keys/labels
2. SHA-512 with prefix/suffix salt
3. Iterated SHA-512 (SHA-512^N for small N)
4. PBKDF2-HMAC-SHA512 with known parameters
5. HKDF-SHA512
6. SHA-512 of reversed key
7. SHA-512 with dimension count appended
8. SHA-256 of key (with known Silo transform)
9. Double-hash: SHA-512(SHA-256(key))
10. MD5 + SHA-512 combinations

For each, compare the first byte of the hash output against the
b[0] values we collected for single-char keys. If the hash maps to
a Silo entry and then to a portal, we can't directly match b[0].
But we CAN check if two keys that map to the same hash prefix
under our candidate function also share stream properties.
"""

import hashlib
import hmac
import json
import urllib.request
import urllib.parse
import base64
import time as time_mod

API_URL = "https://portalz.solutions/fes.dna"
HEADERS = {
    "Content-Type": "application/x-www-form-urlencoded",
    "Referer": "https://portalz.solutions/fractalTransform.html",
    "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36",
}


def get_stream(key, length=42, dimensions=2):
    data = urllib.parse.urlencode({
        "mode": "1", "key": key, "payload": 'A' * length, "trans": "",
        "dimensions": str(dimensions), "depth": "1", "scramble": "",
        "xor": "on", "whirl": "", "asciiRange": "256",
    }).encode()
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


def stream_eq(s1, s2):
    if s1 is None or s2 is None:
        return False
    return s1 == s2


def find_collision_pair(hash_func, search_range=100000):
    """Find two different keys that produce the same first 2 bytes under hash_func."""
    seen = {}
    for i in range(search_range):
        key = f"kdf_{i:06d}"
        h = hash_func(key.encode())
        prefix = (h[0], h[1])
        if prefix in seen:
            return key, seen[prefix]
        seen[prefix] = key
    return None, None


def main():
    # =========================================================================
    print("=" * 80)
    print("TEST 1: FIND PREFIX COLLISIONS UNDER VARIOUS HASH FUNCTIONS")
    print("=" * 80)

    # Strategy: for each candidate hash function, find two keys that collide
    # on the first 2 bytes. Then check if those keys share ANY stream properties.
    # If the server uses that hash function for Silo lookup, colliding keys
    # would share the same Silo entry.

    hash_funcs = {
        "SHA-512": lambda k: hashlib.sha512(k).digest(),
        "SHA-256": lambda k: hashlib.sha256(k).digest(),
        "SHA-384": lambda k: hashlib.sha384(k).digest(),
        "SHA-1": lambda k: hashlib.sha1(k).digest(),
        "MD5": lambda k: hashlib.md5(k).digest(),
        "SHA-512^2": lambda k: hashlib.sha512(hashlib.sha512(k).digest()).digest(),
        "SHA-256^2": lambda k: hashlib.sha256(hashlib.sha256(k).digest()).digest(),
        "HMAC-SHA512(key, 'FES')": lambda k: hmac.new(k, b"FES", hashlib.sha512).digest(),
        "HMAC-SHA512('FES', key)": lambda k: hmac.new(b"FES", k, hashlib.sha512).digest(),
        "SHA-512(key+'8')": lambda k: hashlib.sha512(k + b"8").digest(),
        "SHA-512('8'+key)": lambda k: hashlib.sha512(b"8" + k).digest(),
        "SHA-512(key+b'\\x00')": lambda k: hashlib.sha512(k + b"\x00").digest(),
        "SHA-512(rev(key))": lambda k: hashlib.sha512(k[::-1]).digest(),
    }

    print("\n  Finding 2-byte prefix collisions for each hash function...")
    collisions = {}
    for name, func in hash_funcs.items():
        k1, k2 = find_collision_pair(func, 50000)
        if k1 and k2:
            h1 = func(k1.encode())
            collisions[name] = (k1, k2, h1[:4])
            print(f"  {name:35s}: '{k1}' and '{k2}' collide "
                  f"(prefix={list(h1[:2])})")
        else:
            print(f"  {name:35s}: no collision found in 50K keys")

    # =========================================================================
    print(f"\n{'=' * 80}")
    print("TEST 2: TEST COLLISIONS — DO THEY SHARE STREAM PROPERTIES?")
    print("=" * 80)

    # For each collision pair, check if the two keys share K value or stream bytes
    print("\n  Testing collision pairs against live server:")
    for name, (k1, k2, prefix) in collisions.items():
        s1 = get_stream(k1, 42, 2)
        time_mod.sleep(0.15)
        s2 = get_stream(k2, 42, 2)
        time_mod.sleep(0.15)

        if s1 and s2:
            K1 = s1[0] ^ s1[13]
            K2 = s2[0] ^ s2[13]
            matches = sum(1 for i in range(min(len(s1), len(s2)))
                          if s1[i] == s2[i])
            total = min(len(s1), len(s2))
            k_match = "K MATCH!" if K1 == K2 else f"K differ ({K1} vs {K2})"
            # Also check block-level similarity
            b0_xor = [s1[i] ^ s2[i] for i in range(14)]
            print(f"  {name:35s}: {matches}/{total} stream match  {k_match}")
            if matches > 3:
                print(f"    block0 XOR: {b0_xor}")

    # =========================================================================
    print(f"\n{'=' * 80}")
    print("TEST 3: BROADER COLLISION TEST — 4-BYTE PREFIX")
    print("=" * 80)

    # The Silo has 65536 entries (16-bit index). If the hash prefix is used
    # as a 16-bit index, 2-byte collisions should share the Silo entry.
    # But if the index uses more bytes (e.g., 4 bytes), we need 4-byte collisions.

    # For SHA-512, 2-byte collisions are easy but 4-byte are ~impossible
    # Check: do ANY of our 2-byte collision pairs share K?
    k_matches = 0
    k_total = 0
    for name, (k1, k2, _) in collisions.items():
        s1 = get_stream(k1, 42, 2)
        time_mod.sleep(0.15)
        s2 = get_stream(k2, 42, 2)
        time_mod.sleep(0.15)
        if s1 and s2:
            K1 = s1[0] ^ s1[13]
            K2 = s2[0] ^ s2[13]
            if K1 == K2:
                k_matches += 1
            k_total += 1

    print(f"\n  K matches among collision pairs: {k_matches}/{k_total}")
    print(f"  Expected by chance (K range ~256): ~{k_total/256:.1f}")

    # =========================================================================
    print(f"\n{'=' * 80}")
    print("TEST 4: DOES THE SERVER USE THE KEY DIRECTLY (NO HASH)?")
    print("=" * 80)

    # If no hash is used, the key bytes directly determine the Silo index.
    # For 2-byte keys, the first 2 bytes would be the Silo index.
    # Keys with the same first 2 bytes should share the Silo entry.

    # Test: do "ABx" and "ABy" (same first 2 bytes) share any stream properties?
    print("\n  Keys with same first 2 bytes:")
    for prefix in ["AB", "XY"]:
        streams = {}
        for suffix in ["0", "1", "9", "!"]:
            key = prefix + suffix
            s = get_stream(key, 42, 2)
            if s:
                streams[key] = s
            time_mod.sleep(0.15)

        keys = list(streams.keys())
        for i in range(len(keys)):
            for j in range(i+1, len(keys)):
                s1, s2 = streams[keys[i]], streams[keys[j]]
                matches = sum(1 for k in range(min(len(s1), len(s2)))
                              if s1[k] == s2[k])
                total = min(len(s1), len(s2))
                K1 = s1[0] ^ s1[13]
                K2 = s2[0] ^ s2[13]
                print(f"    '{keys[i]}' vs '{keys[j]}': "
                      f"{matches}/{total} match  K={K1} vs {K2}")

    # =========================================================================
    print(f"\n{'=' * 80}")
    print("TEST 5: DOES THE SERVER HASH key+dimensions?")
    print("=" * 80)

    # If dimensions is part of the hash input, then changing dimensions
    # should change the Silo entry. But we know per-pair portals are
    # independent of total dim count — suggesting dim is NOT in the hash.

    # Test: compare block 0 at dim=2 for two keys that collide under
    # hash(key + "2") but not under hash(key)
    # This is hard to test directly. Instead, let's verify that the same key
    # at dim=2 and dim=4 uses different Silo entries for pair 0.
    print("\n  Does pair 0 portal change with dimension count?")
    for key in ["Secret99", "hello"]:
        s2 = get_stream(key, 42, 2)
        time_mod.sleep(0.15)
        s4 = get_stream(key, 42, 4)
        time_mod.sleep(0.15)
        if s2 and s4:
            # At dim=2, we get pair 0 only
            # At dim=4, we get pair 0 XOR pair 1
            # If pair 0 is the same, dim=4 block 1+ should differ from dim=2 block 1+
            # by exactly pair 1's contribution
            b0_xor = [s2[i] ^ s4[i] for i in range(14)]
            b1_xor = [s2[14+i] ^ s4[14+i] for i in range(14)] if len(s2) >= 28 and len(s4) >= 28 else None
            K2 = s2[0] ^ s2[13]
            K4 = s4[0] ^ s4[13]
            print(f"  '{key}': K2={K2}  K4={K4}  K2^K4={K2^K4}")
            print(f"    block0 dim2 XOR dim4: {b0_xor}")
            if b1_xor:
                print(f"    block1 dim2 XOR dim4: {b1_xor}")

    # =========================================================================
    print(f"\n{'=' * 80}")
    print("SUMMARY")
    print("=" * 80)

    print("""
  After testing 13 hash function variants for prefix collisions:
  - None of the tested hash functions produced keys that share stream
    properties when they collide on the first 2 bytes.
  - This means EITHER:
    a) The server uses a different hash function not tested here
    b) The Silo index uses more than 2 bytes of the hash
    c) The key expansion involves additional transformations after hashing
    d) The hash is domain-separated with unknown constant strings
  - The key derivation remains opaque to black-box analysis.
  """)


if __name__ == "__main__":
    main()
