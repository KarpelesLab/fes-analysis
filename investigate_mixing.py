"""
Investigate the mixing function structure based on the XOR invariant discovery.

The XOR invariant: block[0] XOR block[13] = CONSTANT for all 14-byte blocks.
This means the mixing function preserves a linear relationship between its
first and last output bytes.

Tests:
1. Does the XOR constant relate to the key's SHA-512 hash?
2. Are there OTHER invariants (additive, multiplicative) within blocks?
3. What's the relationship between block bytes? (byte-to-byte correlation)
4. Does the constant change across phase transitions?
5. Does the mixing function appear to be an affine transformation?
6. Can we determine the mixing function by providing controlled inputs?
"""

import base64
import json
import urllib.request
import urllib.parse
import hashlib
import time
from collections import Counter

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


def get_blocks(stream, block_size=14):
    """Split stream into block_size-byte blocks."""
    blocks = []
    for i in range(0, len(stream) - block_size + 1, block_size):
        blocks.append(stream[i:i + block_size])
    return blocks


def main():
    # =========================================================================
    print("=" * 80)
    print("TEST 1: XOR CONSTANT vs SHA-512 HASH OF KEY")
    print("=" * 80)

    keys = ["Secret99", "hello", "password123", "alpha", "gamma",
            "testkey1", "xyz42", "FES_test", "abc", "beta"]

    print("\n  Key → XOR constant → SHA-512 bytes → relationship?")
    for key in keys:
        s = get_stream(key, 70, dimensions=8)
        if not s:
            continue
        blocks = get_blocks(s)
        if len(blocks) < 2:
            continue
        xor_const = blocks[0][0] ^ blocks[0][13]

        # SHA-512 of key
        sha = hashlib.sha512(key.encode()).digest()
        sha_bytes = list(sha[:16])

        # Check if XOR constant appears in SHA-512
        sha_match = [i for i in range(64) if sha[i] == xor_const]

        # Check various transformations
        sha_xor_0_13 = sha[0] ^ sha[13]
        sha_xor_0_63 = sha[0] ^ sha[63]
        sha_first = sha[0]
        sha_last = sha[63]

        print(f"  {key:16s}: K={xor_const:3d} (0x{xor_const:02x})"
              f"  sha[0]^sha[13]={sha_xor_0_13:3d}"
              f"  sha[0]={sha_first:3d}"
              f"  sha[63]={sha_last:3d}"
              f"  K in SHA at: {sha_match if sha_match else 'nowhere'}")
        time.sleep(0.3)

    # =========================================================================
    print(f"\n{'=' * 80}")
    print("TEST 2: ADDITIVE AND MULTIPLICATIVE INVARIANTS WITHIN BLOCKS")
    print("=" * 80)

    key = "Secret99"
    s = get_stream(key, 120, dimensions=8)
    time.sleep(0.3)

    if s:
        blocks = get_blocks(s)
        print(f"\n  Key '{key}', dim=8, {len(blocks)} blocks:")

        # Show blocks
        for bi, b in enumerate(blocks):
            print(f"    Block {bi}: {b}")

        # Check additive invariant: (block[i] + block[j]) mod 256
        print(f"\n  Additive invariants (block[i]+block[j]) mod 256 = const:")
        for i in range(14):
            for j in range(i + 1, 14):
                add_vals = [(b[i] + b[j]) % 256 for b in blocks]
                if len(set(add_vals)) == 1:
                    print(f"    ({i:2d}+{j:2d}) mod 256 = {add_vals[0]:3d}")

        # Check if any single position is constant
        print(f"\n  Constant positions across blocks:")
        for i in range(14):
            vals = [b[i] for b in blocks]
            if len(set(vals)) == 1:
                print(f"    block[*][{i}] = {vals[0]}")

        # Check if any position pair has constant ratio
        print(f"\n  Positions with low entropy across blocks:")
        for i in range(14):
            vals = [b[i] for b in blocks]
            entropy = len(set(vals))
            if entropy <= 2:
                print(f"    block[*][{i}]: {entropy} unique values: {sorted(set(vals))}")

    # =========================================================================
    print(f"\n{'=' * 80}")
    print("TEST 3: XOR CONSTANT ACROSS PHASE TRANSITIONS")
    print("=" * 80)

    key = "Secret99"
    print(f"\n  Key '{key}', dim=8:")
    for length in [42, 44, 70, 72, 98, 100, 120]:
        s = get_stream(key, length, dimensions=8)
        if not s or len(s) < 28:
            print(f"    len={length:3d}: stream too short")
            continue
        blocks = get_blocks(s)
        if len(blocks) < 2:
            print(f"    len={length:3d}: only {len(blocks)} block(s)")
            continue
        xor_vals = [b[0] ^ b[13] for b in blocks]
        all_same = len(set(xor_vals)) == 1
        const = xor_vals[0] if all_same else "VARIES"
        print(f"    len={length:3d}: {len(blocks)} blocks, XOR[0,13]={const}"
              f" {'✓' if all_same else '✗'}")
        time.sleep(0.3)

    # =========================================================================
    print(f"\n{'=' * 80}")
    print("TEST 4: BLOCK-TO-BLOCK BYTE DIFFERENCES (MIXING STATE EVOLUTION)")
    print("=" * 80)

    key = "Secret99"
    s = get_stream(key, 120, dimensions=8)
    if s:
        blocks = get_blocks(s)
        print(f"\n  Block-to-block XOR (how does each position change between blocks?):")
        for bi in range(len(blocks) - 1):
            xor = [blocks[bi][j] ^ blocks[bi + 1][j] for j in range(14)]
            print(f"    Block {bi}→{bi+1}: {xor}")

        print(f"\n  Block-to-block ADD diff:")
        for bi in range(len(blocks) - 1):
            diff = [(blocks[bi + 1][j] - blocks[bi][j]) % 256 for j in range(14)]
            print(f"    Block {bi}→{bi+1}: {diff}")

        # Check if block-to-block XOR is itself constant (linear recurrence)
        if len(blocks) >= 3:
            print(f"\n  Is block-to-block XOR constant (linear recurrence)?")
            xor_01 = [blocks[0][j] ^ blocks[1][j] for j in range(14)]
            xor_12 = [blocks[1][j] ^ blocks[2][j] for j in range(14)]
            print(f"    XOR(B0,B1): {xor_01}")
            print(f"    XOR(B1,B2): {xor_12}")
            print(f"    Same? {xor_01 == xor_12}")

    # =========================================================================
    print(f"\n{'=' * 80}")
    print("TEST 5: INTER-BLOCK POSITION CORRELATIONS")
    print("=" * 80)

    # For each pair of positions (i,j), compute correlation across blocks
    key = "Secret99"
    s = get_stream(key, 120, dimensions=8)
    if s:
        blocks = get_blocks(s)
        if len(blocks) >= 4:
            print(f"\n  Linear correlation between positions (across {len(blocks)} blocks):")
            # Simple check: does block[n][i] predict block[n][j] via XOR with constant?
            for i in range(14):
                for j in range(i + 1, 14):
                    # Check if block[n][i] XOR block[n][j] has few unique values
                    xor_vals = [b[i] ^ b[j] for b in blocks]
                    unique = len(set(xor_vals))
                    if unique <= 2:
                        print(f"    pos[{i:2d}] XOR pos[{j:2d}]: {unique} unique vals: "
                              f"{sorted(set(xor_vals))}")

    # =========================================================================
    print(f"\n{'=' * 80}")
    print("TEST 6: IS THE MIXING FUNCTION BYTE-WISE AFFINE?")
    print("=" * 80)

    # If mixing is affine: mix(x)[i] = sum(A[i][j]*x[j]) + b[i] (mod 256)
    # Then: mix(x1)[i] XOR mix(x2)[i] = sum(A[i][j]*(x1[j] XOR x2[j]))
    # For position 0 and 13 to always XOR to constant K:
    #   A[0][j]*x[j] + b[0] XOR A[13][j]*x[j] + b[13] = K for all inputs x
    # This constrains A[0] and A[13] heavily.

    # Test: do different keys give us enough constraints?
    # If we collect (block[0], block[13]) pairs from many keys/blocks,
    # and they ALL satisfy block[0] XOR block[13] = K (key-dependent),
    # then within a key the function is constrained.

    # Collect many block pairs from different keys
    print("\n  Collecting (block[0], block[13]) pairs from multiple keys:")
    all_pairs = {}
    for key in keys[:8]:
        s = get_stream(key, 120, dimensions=8)
        if not s:
            continue
        blocks = get_blocks(s)
        pairs = [(b[0], b[13]) for b in blocks]
        xor_const = pairs[0][0] ^ pairs[0][1]
        all_pairs[key] = {"pairs": pairs, "xor_const": xor_const}
        b0_vals = [p[0] for p in pairs]
        b13_vals = [p[1] for p in pairs]
        print(f"    {key:16s}: K=0x{xor_const:02x}  "
              f"b0={b0_vals}  b13={b13_vals}")
        time.sleep(0.3)

    # =========================================================================
    print(f"\n{'=' * 80}")
    print("TEST 7: SINGLE-BYTE KEY SWEEP — XOR CONSTANT PATTERN")
    print("=" * 80)

    # Map key → XOR constant to find if there's a simple relationship
    print("\n  Single-char keys (ASCII 33-122) → XOR constant (dim=8):")
    xor_constants = {}
    for ch in range(33, 123, 3):  # sample every 3rd char for speed
        key = chr(ch)
        s = get_stream(key, 42, dimensions=8)
        if not s:
            continue
        blocks = get_blocks(s)
        if len(blocks) >= 2:
            xor_vals = [b[0] ^ b[13] for b in blocks]
            if len(set(xor_vals)) == 1:
                xor_constants[ch] = xor_vals[0]
                sha_byte0 = hashlib.sha512(key.encode()).digest()[0]
                print(f"    '{chr(ch)}' ({ch:3d}): K={xor_vals[0]:3d} (0x{xor_vals[0]:02x})"
                      f"  sha[0]={sha_byte0:3d} (0x{sha_byte0:02x})")
        time.sleep(0.2)

    # Check if K values cluster or have structure
    if xor_constants:
        vals = list(xor_constants.values())
        print(f"\n  {len(set(vals))}/{len(vals)} unique K values")
        print(f"  K value distribution: {Counter(vals).most_common(10)}")

    # =========================================================================
    print(f"\n{'=' * 80}")
    print("TEST 8: WITHIN-BLOCK BYTE RELATIONSHIPS — GF(256) ANALYSIS")
    print("=" * 80)

    # In GF(256), check if block bytes satisfy polynomial relationships
    # Specifically: does block[i] = block[0] * alpha^i for some generator alpha?
    # Or: are consecutive bytes related by a fixed transformation?

    key = "Secret99"
    s = get_stream(key, 120, dimensions=8)
    if s:
        blocks = get_blocks(s)
        print(f"\n  Key '{key}', {len(blocks)} blocks:")

        # Check consecutive byte XOR within each block
        for bi, block in enumerate(blocks[:4]):
            consec_xor = [block[j] ^ block[j+1] for j in range(13)]
            print(f"    Block {bi} consecutive XOR: {consec_xor}")

        # Check if there's a "step" pattern
        # i.e., block[i+1] = f(block[i]) for some fixed f
        print(f"\n  Is block[i+1] = block[i] XOR delta for constant delta?")
        for bi, block in enumerate(blocks[:3]):
            deltas = [block[j+1] ^ block[j] for j in range(13)]
            print(f"    Block {bi}: deltas = {deltas} (unique: {len(set(deltas))})")


if __name__ == "__main__":
    main()
