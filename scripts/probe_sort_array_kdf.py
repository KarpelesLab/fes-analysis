"""
Use Sort Array recovery to probe key derivation.

The Sort Array values represent |z|² at navigated Mandelbrot positions.
These are RAW state values that haven't been through the mixing function.
By comparing Sort Array orderings for different keys, we can study
how the key derivation affects the raw Mandelbrot state.

Key insight: Sort Array ordering is determined by the magnitude of z at
each position, which directly depends on the portal coordinates.
Similar portals → similar z magnitudes → similar Sort Array orderings.

Tests:
1. Recover Sort Array ordering for many single-char keys
2. Compare orderings — do similar keys have similar orderings?
3. Check if Sort Array ordering correlates with b[0] values
4. Test if FOTP changes the Sort Array ordering
5. Compare Sort Array for key='A' vs key='A' with FOTP
"""

import base64
import json
import urllib.request
import urllib.parse
import time as time_mod

API_URL = "https://portalz.solutions/fes.dna"
HEADERS = {
    "Content-Type": "application/x-www-form-urlencoded",
    "Referer": "https://portalz.solutions/fractalTransform.html",
    "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36",
}


def fes_request(key, payload="", dimensions=8, scramble="", depth="1", extra_params=None):
    params = {
        "mode": "1", "key": key, "payload": payload, "trans": "",
        "dimensions": str(dimensions), "depth": depth, "scramble": scramble,
        "xor": "on", "whirl": "", "asciiRange": "256",
    }
    if extra_params:
        params.update(extra_params)
    data = urllib.parse.urlencode(params).encode()
    req = urllib.request.Request(API_URL, data=data, headers=HEADERS)
    with urllib.request.urlopen(req, timeout=30) as resp:
        return json.loads(resp.read())


def b64_decode(s):
    padded = s + '=' * (4 - len(s) % 4) if len(s) % 4 else s
    return base64.b64decode(padded)


def get_stream_no_scramble(key, length, dimensions=8):
    known = bytes([0x41] * length)
    result = fes_request(key, payload=known.decode(), dimensions=dimensions, scramble="")
    ct = b64_decode(result.get("trans", ""))
    stream = [0] * length
    for i in range(length):
        stream[length - 1 - i] = ct[i] ^ known[i]
    return stream


def recover_permutation(key, length, dimensions=8, extra_params=None):
    """Recover scramble permutation via 2 queries."""
    # Query 1: uniform bytes without scramble → get stream
    stream = get_stream_no_scramble(key, length, dimensions)
    time_mod.sleep(0.15)

    # Query 2: unique PRINTABLE bytes with scramble → get permuted ciphertext
    # Use bytes starting from 0x41 ('A'), each +1
    unique_chars = ''.join(chr(0x41 + i) for i in range(length))
    result = fes_request(key, payload=unique_chars,
                         dimensions=dimensions, scramble="on",
                         extra_params=extra_params)
    ct_b64 = result.get("trans", "")
    if not ct_b64:
        return None
    ct = b64_decode(ct_b64)

    if len(ct) < length:
        return None

    # Decrypt: ct[i] = scrambled_pt[i] XOR stream[N-1-i]
    decrypted = [(ct[i] ^ stream[length - 1 - i]) for i in range(length)]

    # decrypted[i] should be unique_chars[π(i)] = 0x41 + π(i)
    # So π(i) = decrypted[i] - 0x41
    perm = [d - 0x41 for d in decrypted]

    # Validate: all values should be in [0, length-1]
    if not all(0 <= p < length for p in perm):
        return None
    if len(set(perm)) != length:
        return None  # Not a valid permutation

    return perm


def perm_to_sort_order(perm):
    """Convert permutation to sort order (smallest to largest z value)."""
    # perm[i] = j means output position i gets input byte j
    # Sort Array ordering: position with smallest z value gets smallest rank
    # The recovered permutation IS the sort order
    return perm


def perm_distance(p1, p2):
    """Kendall tau distance between two permutations."""
    n = min(len(p1), len(p2))
    dist = 0
    for i in range(n):
        for j in range(i+1, n):
            if (p1[i] < p1[j]) != (p2[i] < p2[j]):
                dist += 1
    max_dist = n * (n - 1) // 2
    return dist, max_dist


def main():
    length = 16  # Use 16-byte payloads for manageable permutations

    # =========================================================================
    print("=" * 80)
    print("TEST 1: SORT ARRAY ORDERINGS FOR SINGLE-CHAR KEYS")
    print("=" * 80)

    perms = {}
    print(f"\n  Recovering permutations (length={length}, dim=8):")
    for c in range(65, 75):  # A-J
        key = chr(c)
        try:
            perm = recover_permutation(key, length, dimensions=8)
            perms[key] = perm
            print(f"    '{key}': perm={perm}")
        except Exception as e:
            print(f"    '{key}': ERROR: {e}")
        time_mod.sleep(0.3)

    # Compare permutations
    print(f"\n  Pairwise Kendall tau distances:")
    keys = sorted(perms.keys())
    for i in range(len(keys)):
        for j in range(i+1, len(keys)):
            dist, maxd = perm_distance(perms[keys[i]], perms[keys[j]])
            pct = 100 * dist / maxd if maxd > 0 else 0
            print(f"    '{keys[i]}' vs '{keys[j]}': τ={dist}/{maxd} ({pct:.0f}% swaps)")

    # =========================================================================
    print(f"\n{'=' * 80}")
    print("TEST 2: SORT ARRAY FOR 2-CHAR KEYS WITH SHARED FIRST CHAR")
    print("=" * 80)

    perms2 = {}
    print(f"\n  Keys 'A0' through 'A9' (dim=8):")
    for d in range(10):
        key = f"A{d}"
        try:
            perm = recover_permutation(key, length, dimensions=8)
            perms2[key] = perm
            print(f"    '{key}': perm={perm}")
        except Exception as e:
            print(f"    '{key}': ERROR: {e}")
        time_mod.sleep(0.3)

    # Compare with single-char 'A'
    if 'A' in perms:
        print(f"\n  Comparing 'A0'-'A9' with single-char 'A':")
        for key in sorted(perms2.keys()):
            dist, maxd = perm_distance(perms.get('A', []), perms2[key])
            pct = 100 * dist / maxd if maxd > 0 else 0
            print(f"    'A' vs '{key}': τ={dist}/{maxd} ({pct:.0f}% swaps)")

    # =========================================================================
    print(f"\n{'=' * 80}")
    print("TEST 3: SORT ARRAY AT dim=2 — FEWER DIMENSIONS = SIMPLER")
    print("=" * 80)

    perms_d2 = {}
    print(f"\n  Keys A-F at dim=2:")
    for c in range(65, 71):  # A-F
        key = chr(c)
        try:
            perm = recover_permutation(key, length, dimensions=2)
            perms_d2[key] = perm
            print(f"    '{key}': perm={perm}")
        except Exception as e:
            print(f"    '{key}': ERROR: {e}")
        time_mod.sleep(0.3)

    # =========================================================================
    print(f"\n{'=' * 80}")
    print("TEST 4: FOTP EFFECT ON SORT ARRAY")
    print("=" * 80)

    # Does FOTP change the Sort Array ordering?
    key = "Secret99"
    print(f"\n  Key '{key}', dim=8:")
    perm_no_fotp = recover_permutation(key, length, dimensions=8)
    time_mod.sleep(0.3)

    # For FOTP, use the same recovery function
    time_mod.sleep(0.3)
    perm_fotp = recover_permutation(key, length, dimensions=8,
                                     extra_params={"fotp": "test"})

    print(f"    No FOTP:     perm={perm_no_fotp}")
    print(f"    FOTP='test': perm={perm_fotp}")

    if perm_no_fotp and perm_fotp:
        dist, maxd = perm_distance(perm_no_fotp, perm_fotp)
        pct = 100 * dist / maxd if maxd > 0 else 0
        print(f"    Distance: τ={dist}/{maxd} ({pct:.0f}% swaps)")
    else:
        print(f"    Could not compare (one or both permutations failed)")

    # =========================================================================
    print(f"\n{'=' * 80}")
    print("TEST 5: SORT ARRAY STABILITY ACROSS LENGTHS")
    print("=" * 80)

    key = "Secret99"
    print(f"\n  Key '{key}', dim=8, various lengths:")
    for test_len in [8, 12, 16, 24]:
        try:
            perm = recover_permutation(key, test_len, dimensions=8)
            print(f"    len={test_len:2d}: perm={perm}")
        except Exception as e:
            print(f"    len={test_len:2d}: ERROR: {e}")
        time_mod.sleep(0.3)

    # =========================================================================
    print(f"\n{'=' * 80}")
    print("TEST 6: SORT ARRAY ORDERING — WHAT DETERMINES IT?")
    print("=" * 80)

    # The Sort Array values are |z|² at navigated positions.
    # Position with smallest |z|² gets rank 0.
    # The ordering tells us which positions have larger/smaller |z|².
    # This is determined by the portal coordinates.

    # For a given key, the Sort Array should be deterministic.
    # Let's verify by recovering twice.
    key = "hello"
    p1 = recover_permutation(key, length, dimensions=8)
    time_mod.sleep(0.3)
    p2 = recover_permutation(key, length, dimensions=8)
    time_mod.sleep(0.3)
    print(f"\n  Reproducibility test (key='hello', dim=8):")
    print(f"    Run 1: {p1}")
    print(f"    Run 2: {p2}")
    print(f"    Same: {p1 == p2}")

    # =========================================================================
    print(f"\n{'=' * 80}")
    print("TEST 7: SORT ARRAY vs STREAM FIRST BLOCK")
    print("=" * 80)

    # Is there a correlation between Sort Array ordering and stream byte values?
    print(f"\n  Sort Array ordering vs stream block 0 values:")
    for key in ["A", "B", "Secret99", "hello"]:
        stream = get_stream_no_scramble(key, 42, dimensions=8)
        try:
            perm = recover_permutation(key, 16, dimensions=8)
        except:
            continue
        time_mod.sleep(0.3)

        # Sort Array ordering: perm[i] = j means position i gets input byte j
        # Inverse permutation: for each original position j, where does it go?
        inv_perm = [0] * len(perm)
        for i in range(len(perm)):
            if perm[i] < len(inv_perm):
                inv_perm[perm[i]] = i

        # Compare with stream values (reversed stream for first 16 bytes)
        stream_first16 = list(reversed(stream[-16:]))  # first 16 stream bytes
        print(f"    '{key:10s}': perm={perm[:8]}...  stream={stream_first16[:8]}...")
        print(f"                 inv_perm={inv_perm[:8]}...")


if __name__ == "__main__":
    main()
