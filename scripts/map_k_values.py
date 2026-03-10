"""
Systematic K value mapping to reverse-engineer key derivation.

K = block[0] XOR block[13] is the simplest key-derived observable.
By mapping K for systematically chosen keys, we can look for structure
in the key derivation function.

Tests:
1. K for all single-byte keys (0-255 as characters)
2. K for 2-byte keys with fixed first byte, varying second
3. K for all printable ASCII 2-char keys (matrix)
4. K vs SHA-512 bits — any correlation at all?
5. K for incrementing numeric keys
6. K for keys that are binary/hex representations
7. Does K have any arithmetic relationship to key bytes?
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


def get_stream(key, length, dimensions=2):
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


def get_k(key, dimensions=2, length=42):
    s = get_stream(key, length, dimensions)
    if not s or len(s) < 28:
        return None
    # Check consistency across first 2 blocks
    b0 = s[0] ^ s[13]
    b1 = s[14] ^ s[27]
    if b0 != b1:
        return None  # Not consistent
    return b0


def main():
    # =========================================================================
    print("=" * 80)
    print("TEST 1: K FOR ALL PRINTABLE SINGLE-CHAR KEYS")
    print("=" * 80)

    k_single = {}
    print("\n  Char  Ord   K    K_bin          SHA[0]  SHA[1]")
    for c in range(32, 127):
        key = chr(c)
        K = get_k(key)
        if K is not None:
            k_single[c] = K
            sha = hashlib.sha512(key.encode()).digest()
            print(f"  '{chr(c):s}'   {c:3d}   {K:3d}  {K:08b}  {sha[0]:3d}    {sha[1]:3d}")
        time_mod.sleep(0.1)

    # Analyze K distribution for single-char keys
    k_vals = list(k_single.values())
    print(f"\n  Summary: {len(set(k_vals))} unique K values out of {len(k_vals)} keys")
    all_zero = all(k == 0 for k in k_vals)
    print(f"  All zero: {all_zero}")

    if not all_zero:
        from collections import Counter
        c = Counter(k_vals)
        print(f"  K distribution: {c.most_common(10)}")

    # =========================================================================
    print(f"\n{'=' * 80}")
    print("TEST 2: K FOR 2-CHAR KEYS 'A'+chr(x)")
    print("=" * 80)

    print("\n  Fixed first='A', varying second byte:")
    k_ax = {}
    for c in range(32, 127):
        key = 'A' + chr(c)
        K = get_k(key)
        if K is not None:
            k_ax[c] = K
        time_mod.sleep(0.1)

    # Print in a compact grid
    print(f"\n  K values (second char ASCII 32-126):")
    for row_start in range(32, 127, 16):
        chars = range(row_start, min(row_start + 16, 127))
        vals = [f"{k_ax.get(c, -1):3d}" for c in chars]
        print(f"  {row_start:3d}-{min(row_start+15, 126):3d}: {' '.join(vals)}")

    # Check for patterns
    k_list = [(c, k_ax[c]) for c in sorted(k_ax.keys())]
    # Arithmetic differences between consecutive keys
    diffs = [k_list[i+1][1] - k_list[i][1] for i in range(len(k_list)-1)]
    print(f"\n  Consecutive K differences: {diffs[:30]}")

    # Check K vs second byte value
    print(f"\n  K vs (second_byte mod N) for various N:")
    for n in [2, 3, 4, 8, 16, 32, 64, 128, 256]:
        matches = sum(1 for c, k in k_list if k == c % n)
        print(f"    K == chr mod {n:3d}: {matches}/{len(k_list)}")

    # Check K XOR with byte value
    xor_vals = [c ^ k for c, k in k_list]
    print(f"\n  K XOR second_byte: {len(set(xor_vals))} unique values")
    print(f"  First 20: {xor_vals[:20]}")

    # =========================================================================
    print(f"\n{'=' * 80}")
    print("TEST 3: K FOR NUMERIC KEYS 0-99")
    print("=" * 80)

    k_numeric = {}
    for n in range(100):
        key = str(n)
        K = get_k(key)
        if K is not None:
            k_numeric[n] = K
        time_mod.sleep(0.1)

    print(f"\n  K values for '0' through '99':")
    for row_start in range(0, 100, 10):
        nums = range(row_start, min(row_start + 10, 100))
        vals = [f"{k_numeric.get(n, -1):3d}" for n in nums]
        print(f"  {row_start:3d}-{min(row_start+9, 99):3d}: {' '.join(vals)}")

    # Single digit keys should all be K=0 (from earlier finding)
    single_digit_k = [k_numeric.get(n) for n in range(10)]
    print(f"\n  Single-digit keys (0-9) K values: {single_digit_k}")

    # Two-digit keys
    two_digit_k = [k_numeric.get(n) for n in range(10, 100)]
    print(f"  Two-digit keys K values unique: {len(set(k for k in two_digit_k if k is not None))}")

    # =========================================================================
    print(f"\n{'=' * 80}")
    print("TEST 4: K RELATIONSHIP TO SHA-512")
    print("=" * 80)

    # For the 2-char keys, check if K has any bit-level correlation with SHA-512
    print("\n  Checking K vs SHA-512 byte correlations:")
    for sha_byte_idx in range(8):
        matches = 0
        total = 0
        for c, K in k_list:
            key = 'A' + chr(c)
            sha = hashlib.sha512(key.encode()).digest()
            if K == sha[sha_byte_idx]:
                matches += 1
            total += 1
        print(f"    K == SHA[{sha_byte_idx}]: {matches}/{total}")

    # Check K == SHA[i] mod 256, SHA[i] XOR SHA[j], etc.
    print(f"\n  K vs SHA operations:")
    for op_name, op in [
        ("SHA[0] XOR SHA[1]", lambda sha: sha[0] ^ sha[1]),
        ("SHA[0] XOR SHA[63]", lambda sha: sha[0] ^ sha[63]),
        ("SHA[0] + SHA[1] mod 256", lambda sha: (sha[0] + sha[1]) % 256),
        ("SHA XOR fold (8 bytes)", lambda sha: sha[0]^sha[1]^sha[2]^sha[3]^sha[4]^sha[5]^sha[6]^sha[7]),
        ("SHA[0:2] mod 256", lambda sha: ((sha[0] << 8) | sha[1]) % 256),
        ("sum(SHA) mod 256", lambda sha: sum(sha) % 256),
    ]:
        matches = sum(1 for c, K in k_list
                      if K == op(hashlib.sha512(('A' + chr(c)).encode()).digest()))
        print(f"    K == {op_name}: {matches}/{len(k_list)}")

    # Check if K has any correlation with DOUBLE SHA-512
    double_sha_matches = sum(1 for c, K in k_list
                              if K == hashlib.sha512(hashlib.sha512(('A' + chr(c)).encode()).digest()).digest()[0])
    print(f"    K == SHA512(SHA512(key))[0]: {double_sha_matches}/{len(k_list)}")

    # =========================================================================
    print(f"\n{'=' * 80}")
    print("TEST 5: K AT dim=2 vs dim=4 vs dim=8")
    print("=" * 80)

    print("\n  Comparing K across dimensions for same keys:")
    print(f"  {'Key':>12s}  {'K_d2':>5s}  {'K_d4':>5s}  {'K_d8':>5s}  {'d2^d4':>5s}  {'d2^d8':>5s}  {'d4^d8':>5s}")
    for key in ["Secret99", "hello", "AB", "test", "1234", "aa", "zz", "XY"]:
        k2 = get_k(key, dimensions=2)
        time_mod.sleep(0.1)
        k4 = get_k(key, dimensions=4)
        time_mod.sleep(0.1)
        k8 = get_k(key, dimensions=8)
        time_mod.sleep(0.1)

        if k2 is not None and k4 is not None and k8 is not None:
            print(f"  {key:>12s}  {k2:5d}  {k4:5d}  {k8:5d}  {k2^k4:5d}  {k2^k8:5d}  {k4^k8:5d}")

    # =========================================================================
    print(f"\n{'=' * 80}")
    print("TEST 6: FULL STREAM FIRST 14 BYTES FOR STRUCTURED KEYS")
    print("=" * 80)

    # Get full first block for keys that differ by one character
    print("\n  First block bytes for incrementing keys:")
    prev_block = None
    for key in ["A0", "A1", "A2", "A3", "A4", "A5", "A6", "A7", "A8", "A9"]:
        s = get_stream(key, 42, dimensions=2)
        if not s:
            continue
        block = s[:14]
        xor_prev = ""
        if prev_block:
            xor = [block[i] ^ prev_block[i] for i in range(14)]
            xor_prev = f"  XOR_prev={xor}"
        print(f"  {key}: {block}{xor_prev}")
        prev_block = block
        time_mod.sleep(0.1)

    # =========================================================================
    print(f"\n{'=' * 80}")
    print("TEST 7: K VALUE ARITHMETIC ANALYSIS")
    print("=" * 80)

    # For 2-char keys, check if K = f(ord(c1), ord(c2)) for some function f
    # Already have k_ax for 'A' + chr(c). Now get 'B' + chr(c)
    k_bx = {}
    for c in range(48, 58):  # Just digits for efficiency
        key = 'B' + chr(c)
        K = get_k(key)
        if K is not None:
            k_bx[c] = K
        time_mod.sleep(0.1)

    k_cx = {}
    for c in range(48, 58):
        key = 'C' + chr(c)
        K = get_k(key)
        if K is not None:
            k_cx[c] = K
        time_mod.sleep(0.1)

    print(f"\n  K values for first_byte × digit:")
    print(f"  {'Digit':>6s}  {'A+':>4s}  {'B+':>4s}  {'C+':>4s}")
    for c in range(48, 58):
        a = k_ax.get(c, -1)
        b = k_bx.get(c, -1)
        cx = k_cx.get(c, -1)
        print(f"  {chr(c):>6s}  {a:4d}  {b:4d}  {cx:4d}")

    # Check if K(Ax) XOR K(Bx) is constant
    ab_xors = [k_ax.get(c, 0) ^ k_bx.get(c, 0) for c in range(48, 58) if c in k_ax and c in k_bx]
    print(f"\n  K(A+digit) XOR K(B+digit): {ab_xors}")
    print(f"  All same? {len(set(ab_xors)) == 1}")

    bc_xors = [k_bx.get(c, 0) ^ k_cx.get(c, 0) for c in range(48, 58) if c in k_bx and c in k_cx]
    print(f"  K(B+digit) XOR K(C+digit): {bc_xors}")
    print(f"  All same? {len(set(bc_xors)) == 1}")

    # =========================================================================
    print(f"\n{'=' * 80}")
    print("TEST 8: BLOCK[0] AND BLOCK[13] INDIVIDUALLY")
    print("=" * 80)

    # K = block[0] XOR block[13]. But what are block[0] and block[13] individually?
    print("\n  First block's byte[0] and byte[13] for structured keys:")
    print(f"  {'Key':>12s}  {'b[0]':>5s}  {'b[13]':>6s}  {'K':>4s}")
    for key in [chr(c) for c in range(65, 75)] + ["AA", "AB", "AC", "BA", "BB"]:
        s = get_stream(key, 42, dimensions=2)
        if not s:
            continue
        print(f"  {key:>12s}  {s[0]:5d}  {s[13]:6d}  {s[0]^s[13]:4d}")
        time_mod.sleep(0.1)

    # For single-char keys, K=0 means block[0]==block[13]
    print("\n  Single-char keys: block[0] should equal block[13]:")
    for c in range(65, 75):
        key = chr(c)
        s = get_stream(key, 42, dimensions=2)
        if s:
            print(f"    '{key}': b[0]={s[0]:3d}  b[13]={s[13]:3d}  equal={s[0]==s[13]}")
        time_mod.sleep(0.1)


if __name__ == "__main__":
    main()
