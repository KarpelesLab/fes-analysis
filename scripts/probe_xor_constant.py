"""
Probe the XOR constant K = block[0] XOR block[13] to understand its origin.

KEY FINDING: All single-character keys have K=0.
This means K is derived from key byte interactions (not the mixing function alone).

Tests:
1. Two-character keys: is K = f(key[0], key[1])?
2. Does K = key[0] XOR key[1]? Or SHA(key)[0] XOR SHA(key)[1]?
3. Three-char keys: is K = key[0] XOR key[1] XOR key[2]?
4. Does key LENGTH affect K independently?
5. Systematic scan of 2-char keys to find the formula
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


def fes_request(key, payload="", dimensions=8, scramble=""):
    data = urllib.parse.urlencode({
        "mode": "1", "key": key, "payload": payload, "trans": "",
        "dimensions": str(dimensions), "depth": "1", "scramble": scramble,
        "xor": "on", "whirl": "", "asciiRange": "256",
    }).encode()
    req = urllib.request.Request(API_URL, data=data, headers=HEADERS)
    with urllib.request.urlopen(req) as resp:
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


def get_xor_constant(key, dimensions=8, length=42):
    s = get_stream(key, length, dimensions=dimensions)
    if not s or len(s) < 28:
        return None
    # Get 14-byte blocks
    blocks = [s[i:i+14] for i in range(0, len(s) - 13, 14)]
    if len(blocks) < 2:
        return None
    xor_vals = [b[0] ^ b[13] for b in blocks]
    if len(set(xor_vals)) == 1:
        return xor_vals[0]
    return None  # Not constant (shouldn't happen)


def main():
    # =========================================================================
    print("=" * 80)
    print("TEST 1: TWO-CHARACTER KEYS — FIXED FIRST CHAR, VARYING SECOND")
    print("=" * 80)

    print("\n  Key 'A?' where ? varies:")
    results = {}
    for ch2 in range(65, 91):  # A-Z
        key = 'A' + chr(ch2)
        K = get_xor_constant(key)
        if K is not None:
            xor_bytes = ord('A') ^ ch2
            sha = hashlib.sha512(key.encode()).digest()
            results[key] = K
            print(f"    'A{chr(ch2)}': K={K:3d} (0x{K:02x})"
                  f"  'A'^'{chr(ch2)}'={xor_bytes:3d} (0x{xor_bytes:02x})"
                  f"  sha[0]^sha[1]={sha[0]^sha[1]:3d}")
        time.sleep(0.2)

    # =========================================================================
    print(f"\n{'=' * 80}")
    print("TEST 2: TWO-CHARACTER KEYS — VARYING FIRST CHAR, FIXED SECOND")
    print("=" * 80)

    print("\n  Key '?A' where ? varies:")
    for ch1 in range(65, 75):  # A-J
        key = chr(ch1) + 'A'
        K = get_xor_constant(key)
        if K is not None:
            # Compare with first test: 'A'+chr(ch1) vs chr(ch1)+'A'
            K_rev = results.get('A' + chr(ch1))
            sha = hashlib.sha512(key.encode()).digest()
            print(f"    '{chr(ch1)}A': K={K:3d} (0x{K:02x})"
                  f"  vs 'A{chr(ch1)}': K={K_rev}"
                  f"  sha[0]^sha[1]={sha[0]^sha[1]:3d}")
        time.sleep(0.2)

    # =========================================================================
    print(f"\n{'=' * 80}")
    print("TEST 3: IS K SAME FOR ANAGRAMS? (Order-dependent?)")
    print("=" * 80)

    pairs = [("AB", "BA"), ("AC", "CA"), ("XY", "YX"), ("12", "21"), ("ab", "ba")]
    for k1, k2 in pairs:
        K1 = get_xor_constant(k1)
        K2 = get_xor_constant(k2)
        print(f"    '{k1}': K={K1}  '{k2}': K={K2}  Same? {K1 == K2}")
        time.sleep(0.3)

    # =========================================================================
    print(f"\n{'=' * 80}")
    print("TEST 4: THREE-CHARACTER KEYS — IS K CUMULATIVE?")
    print("=" * 80)

    print("\n  Testing if K('ABC') relates to K('AB'), K('BC'), K('AC'):")
    three_char = ["ABC", "ABD", "ABE", "ABA", "AAA", "AAB", "BAA"]
    for key in three_char:
        K = get_xor_constant(key)
        sub_keys = {}
        for i in range(len(key)):
            for j in range(i+1, len(key)):
                sub = key[i] + key[j]
                sub_K = get_xor_constant(sub)
                sub_keys[sub] = sub_K
                time.sleep(0.15)

        xor_all = 0
        for c in key:
            xor_all ^= ord(c)

        sha = hashlib.sha512(key.encode()).digest()
        sha_xor = sha[0] ^ sha[1] ^ sha[2]

        print(f"    '{key}': K={K}  subs={sub_keys}  "
              f"xor_all_ascii={xor_all}  sha_xor_012={sha_xor}")
        time.sleep(0.2)

    # =========================================================================
    print(f"\n{'=' * 80}")
    print("TEST 5: SAME CHARS REPEATED — K('AA'), K('AAA'), K('AAAA'), ...")
    print("=" * 80)

    print("\n  Repeated 'A':")
    for n in range(1, 9):
        key = 'A' * n
        K = get_xor_constant(key)
        sha = hashlib.sha512(key.encode()).digest()
        print(f"    'A'*{n}: K={K}  sha[0]={sha[0]}")
        time.sleep(0.2)

    print("\n  Repeated 'B':")
    for n in range(1, 6):
        key = 'B' * n
        K = get_xor_constant(key)
        print(f"    'B'*{n}: K={K}")
        time.sleep(0.2)

    # =========================================================================
    print(f"\n{'=' * 80}")
    print("TEST 6: SYSTEMATIC 2-CHAR KEYS — SEARCH FOR FORMULA")
    print("=" * 80)

    # Collect K for many 2-char keys and try to find f(a,b) = K
    print("\n  Collecting K for 2-char keys 'XY' where X,Y in {A,B,C,...,H}:")
    k_matrix = {}
    for c1 in range(65, 73):  # A-H
        for c2 in range(65, 73):
            key = chr(c1) + chr(c2)
            K = get_xor_constant(key)
            k_matrix[(c1, c2)] = K
            time.sleep(0.15)

    # Print as matrix
    print("\n       ", end="")
    for c2 in range(65, 73):
        print(f"  {chr(c2):>4s}", end="")
    print()

    for c1 in range(65, 73):
        print(f"    {chr(c1)}: ", end="")
        for c2 in range(65, 73):
            K = k_matrix.get((c1, c2))
            if K is not None:
                print(f"  {K:4d}", end="")
            else:
                print(f"     ?", end="")
        print()

    # Check various hypotheses
    print("\n  Checking hypotheses:")

    # H1: K = (c1 XOR c2) mod 256
    h1_match = 0
    for (c1, c2), K in k_matrix.items():
        if K is not None and K == (c1 ^ c2):
            h1_match += 1
    print(f"    H1 (K = c1 XOR c2): {h1_match}/{len(k_matrix)} match")

    # H2: K = (c1 + c2) mod 256
    h2_match = 0
    for (c1, c2), K in k_matrix.items():
        if K is not None and K == (c1 + c2) % 256:
            h2_match += 1
    print(f"    H2 (K = (c1+c2) mod 256): {h2_match}/{len(k_matrix)} match")

    # H3: K = (c1 - c2) mod 256
    h3_match = 0
    for (c1, c2), K in k_matrix.items():
        if K is not None and K == (c1 - c2) % 256:
            h3_match += 1
    print(f"    H3 (K = (c1-c2) mod 256): {h3_match}/{len(k_matrix)} match")

    # H4: K = (c1 * c2) mod 256
    h4_match = 0
    for (c1, c2), K in k_matrix.items():
        if K is not None and K == (c1 * c2) % 256:
            h4_match += 1
    print(f"    H4 (K = c1*c2 mod 256): {h4_match}/{len(k_matrix)} match")

    # H5: K depends only on |c1 - c2|
    diffs = {}
    for (c1, c2), K in k_matrix.items():
        if K is not None:
            d = abs(c1 - c2)
            if d not in diffs:
                diffs[d] = set()
            diffs[d].add(K)
    all_unique = all(len(v) == 1 for v in diffs.values())
    print(f"    H5 (K depends only on |c1-c2|): {all_unique}")
    if all_unique:
        for d in sorted(diffs.keys()):
            print(f"      |c1-c2|={d}: K={list(diffs[d])[0]}")

    # H6: K symmetric? K(a,b) == K(b,a)?
    sym_count = 0
    asym_count = 0
    for c1 in range(65, 73):
        for c2 in range(c1+1, 73):
            K1 = k_matrix.get((c1, c2))
            K2 = k_matrix.get((c2, c1))
            if K1 is not None and K2 is not None:
                if K1 == K2:
                    sym_count += 1
                else:
                    asym_count += 1
                    print(f"      ASYM: ({chr(c1)},{chr(c2)})={K1} vs ({chr(c2)},{chr(c1)})={K2}")
    print(f"    H6 (K symmetric): {sym_count} sym, {asym_count} asym")

    # H7: K = SHA-512(key)[some_position]
    for pos in range(64):
        match = 0
        for (c1, c2), K in k_matrix.items():
            if K is not None:
                sha = hashlib.sha512((chr(c1) + chr(c2)).encode()).digest()
                if sha[pos] == K:
                    match += 1
        if match > len(k_matrix) * 0.8:
            print(f"    H7 (K = SHA[{pos}]): {match}/{len(k_matrix)} match!")

    # H7b: K = SHA[i] XOR SHA[j]
    for i in range(16):
        for j in range(i+1, 16):
            match = 0
            for (c1, c2), K in k_matrix.items():
                if K is not None:
                    sha = hashlib.sha512((chr(c1) + chr(c2)).encode()).digest()
                    if (sha[i] ^ sha[j]) == K:
                        match += 1
            if match > len(k_matrix) * 0.8:
                print(f"    H7b (K = SHA[{i}] XOR SHA[{j}]): "
                      f"{match}/{len(k_matrix)} match!")

    # =========================================================================
    print(f"\n{'=' * 80}")
    print("TEST 7: DIM=2 — SAME PATTERN FOR SINGLE-CHAR KEYS?")
    print("=" * 80)

    print("\n  Single-char keys at dim=2:")
    for ch in range(65, 76):  # A-K
        key = chr(ch)
        K = get_xor_constant(key, dimensions=2)
        print(f"    '{chr(ch)}': K={K}")
        time.sleep(0.2)

    print("\n  2-char keys at dim=2:")
    for key in ["AB", "AC", "AD", "BA", "CA"]:
        K = get_xor_constant(key, dimensions=2)
        print(f"    '{key}': K={K}")
        time.sleep(0.2)


if __name__ == "__main__":
    main()
