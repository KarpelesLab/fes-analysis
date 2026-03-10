"""
Deeper analysis of the XOR constant K = block[0] XOR block[13].

Key findings so far:
- K=0 for ALL single-char keys (any dimension)
- K is order-dependent (not symmetric)
- K is stable across phase transitions
- Secret99: dim=2→162, dim=4/6/8→81 (162 = 81<<1!)
- No simple ASCII or SHA-512 relationship

Tests:
1. Verify the dim=2 → dim=4 doubling for multiple keys
2. Check if K relates to block[11] (the duplicate position)
3. Examine K in binary — is there a bit pattern?
4. Test if K depends on the number of unique chars in key
5. Check if the K=0 property extends to all "simple" keys
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
    blocks = [s[i:i+14] for i in range(0, len(s) - 13, 14)]
    if len(blocks) < 2:
        return None
    xor_vals = [b[0] ^ b[13] for b in blocks]
    if len(set(xor_vals)) == 1:
        return xor_vals[0]
    return None


def get_full_block_info(key, dimensions=8, length=42):
    """Return stream, blocks, and K."""
    s = get_stream(key, length, dimensions=dimensions)
    if not s or len(s) < 28:
        return None, None, None
    blocks = [s[i:i+14] for i in range(0, len(s) - 13, 14)]
    if len(blocks) < 2:
        return s, blocks, None
    xor_vals = [b[0] ^ b[13] for b in blocks]
    K = xor_vals[0] if len(set(xor_vals)) == 1 else None
    return s, blocks, K


def main():
    # =========================================================================
    print("=" * 80)
    print("TEST 1: DIM=2 vs DIM=4/8 K RELATIONSHIP FOR MULTIPLE KEYS")
    print("=" * 80)

    keys = ["Secret99", "hello", "password123", "alpha", "gamma",
            "testkey1", "xyz42", "FES_test", "abc", "beta",
            "AB", "AC", "BA", "CD", "EF"]

    print("\n  Key → K by dimension:")
    print(f"  {'Key':16s}  dim2   dim4   dim6   dim8  dim10  dim12  | d2/d8  d2 XOR d8  d2=d8<<1?")
    for key in keys:
        k_by_dim = {}
        for dim in [2, 4, 6, 8, 10, 12]:
            K = get_xor_constant(key, dimensions=dim)
            k_by_dim[dim] = K
            time.sleep(0.15)

        d2 = k_by_dim.get(2)
        d8 = k_by_dim.get(8)
        ratio = f"{d2/d8:.2f}" if d2 and d8 and d8 != 0 else "N/A"
        xor_28 = f"{d2 ^ d8}" if d2 is not None and d8 is not None else "N/A"
        shift = (d2 == (d8 << 1) % 256) if d2 is not None and d8 is not None else "N/A"

        vals = [f"{k_by_dim.get(d, '?'):>5}" for d in [2, 4, 6, 8, 10, 12]]
        print(f"  {key:16s}  {'  '.join(vals)}  | {ratio:>5}  {xor_28:>10}  {shift}")

    # =========================================================================
    print(f"\n{'=' * 80}")
    print("TEST 2: BLOCK[0] AND BLOCK[13] VALUES — INDIVIDUAL ANALYSIS")
    print("=" * 80)

    # For single-char keys, block[0]==block[13] (K=0)
    # For multi-char keys, what are the actual values?
    print("\n  Single-char keys — actual block[0] and block[13] values:")
    for ch in range(65, 73):  # A-H
        key = chr(ch)
        s, blocks, K = get_full_block_info(key, dimensions=8)
        if blocks and len(blocks) >= 2:
            b0_vals = [b[0] for b in blocks[:4]]
            b13_vals = [b[13] for b in blocks[:4]]
            print(f"    '{chr(ch)}': b[0]={b0_vals}  b[13]={b13_vals}  K={K}")
        time.sleep(0.2)

    print("\n  Two-char keys — block[0] and block[13] values:")
    for key in ["AB", "BA", "AA", "BB"]:
        s, blocks, K = get_full_block_info(key, dimensions=8)
        if blocks and len(blocks) >= 2:
            b0_vals = [b[0] for b in blocks[:4]]
            b13_vals = [b[13] for b in blocks[:4]]
            print(f"    '{key}': b[0]={b0_vals}  b[13]={b13_vals}  K={K}")
        time.sleep(0.2)

    # =========================================================================
    print(f"\n{'=' * 80}")
    print("TEST 3: K IN BINARY — BIT PATTERN ANALYSIS")
    print("=" * 80)

    keys2 = ["AA", "AB", "AC", "AD", "AE", "AF", "AG", "AH",
             "BA", "CA", "DA", "EA", "FA", "GA", "HA"]
    print("\n  Key → K (binary):")
    for key in keys2:
        K = get_xor_constant(key, dimensions=8)
        if K is not None:
            print(f"    '{key}': K={K:3d}  0x{K:02x}  {K:08b}")
        time.sleep(0.15)

    # =========================================================================
    print(f"\n{'=' * 80}")
    print("TEST 4: FULL BLOCK STRUCTURE — ALL 14 POSITIONS ACROSS BLOCKS")
    print("=" * 80)

    # For a single-char key (K=0), examine full block structure
    print("\n  Single-char key 'A' (K=0), dim=8:")
    s, blocks, K = get_full_block_info('A', dimensions=8, length=70)
    if blocks:
        for bi, b in enumerate(blocks[:5]):
            print(f"    Block {bi}: {b}")
        # Check all position-pair XOR within blocks
        print("\n  Position-pair XOR analysis (all pairs):")
        for i in range(14):
            for j in range(i+1, 14):
                xor_vals = [b[i] ^ b[j] for b in blocks]
                unique = len(set(xor_vals))
                if unique <= 2:
                    print(f"    pos[{i:2d}] XOR pos[{j:2d}]: {unique} unique, vals={sorted(set(xor_vals))}")
    time.sleep(0.3)

    # Same for 2-char key
    print("\n  Two-char key 'AB' (K=227), dim=8:")
    s, blocks, K = get_full_block_info('AB', dimensions=8, length=70)
    if blocks:
        for bi, b in enumerate(blocks[:5]):
            print(f"    Block {bi}: {b}")
        print("\n  Position-pair XOR analysis:")
        for i in range(14):
            for j in range(i+1, 14):
                xor_vals = [b[i] ^ b[j] for b in blocks]
                unique = len(set(xor_vals))
                if unique <= 2:
                    print(f"    pos[{i:2d}] XOR pos[{j:2d}]: {unique} unique, vals={sorted(set(xor_vals))}")
    time.sleep(0.3)

    # =========================================================================
    print(f"\n{'=' * 80}")
    print("TEST 5: BLOCK BYTE SUM/XOR INVARIANTS")
    print("=" * 80)

    # Check if the XOR or SUM of all 14 bytes in a block is constant
    for key in ["A", "AB", "Secret99"]:
        s, blocks, K = get_full_block_info(key, dimensions=8, length=70)
        if not blocks:
            continue
        print(f"\n  Key '{key}' (K={K}):")

        # XOR of all 14 bytes
        block_xors = []
        for b in blocks:
            xor_all = 0
            for byte in b:
                xor_all ^= byte
            block_xors.append(xor_all)
        print(f"    XOR(all 14 bytes): {block_xors}"
              f" ({'CONSTANT' if len(set(block_xors))==1 else 'varies'})")

        # SUM mod 256
        block_sums = [(sum(b) % 256) for b in blocks]
        print(f"    SUM mod 256:       {block_sums}"
              f" ({'CONSTANT' if len(set(block_sums))==1 else 'varies'})")

        # First 7 bytes XOR last 7 bytes
        half_xors = []
        for b in blocks:
            first_half = 0
            second_half = 0
            for i in range(7):
                first_half ^= b[i]
                second_half ^= b[i+7]
            half_xors.append(first_half ^ second_half)
        print(f"    XOR(first7) XOR XOR(last7): {half_xors}"
              f" ({'CONSTANT' if len(set(half_xors))==1 else 'varies'})")

        # Even positions XOR odd positions
        even_odd_xors = []
        for b in blocks:
            even_xor = 0
            odd_xor = 0
            for i in range(14):
                if i % 2 == 0:
                    even_xor ^= b[i]
                else:
                    odd_xor ^= b[i]
            even_odd_xors.append(even_xor ^ odd_xor)
        print(f"    XOR(even pos) XOR XOR(odd pos): {even_odd_xors}"
              f" ({'CONSTANT' if len(set(even_odd_xors))==1 else 'varies'})")
        time.sleep(0.3)

    # =========================================================================
    print(f"\n{'=' * 80}")
    print("TEST 6: POSITION-PAIR ANALYSIS FOR K=0 KEY")
    print("=" * 80)

    # For K=0 key, block[0]==block[13]. What about other weak invariants?
    key = "A"
    s = get_stream(key, 120, dimensions=8)
    if s:
        blocks = [s[i:i+14] for i in range(0, len(s) - 13, 14)]
        print(f"\n  Key 'A', {len(blocks)} blocks:")

        # For each position, what's the value distribution?
        for pos in range(14):
            vals = [b[pos] for b in blocks]
            unique = len(set(vals))
            if unique <= 3:
                print(f"    pos[{pos:2d}]: {unique} unique values: {sorted(set(vals))}")

        # Check: is block[i] a function of block[0]?
        # Since block[0]==block[13] for K=0, test if other positions correlate
        print(f"\n  Correlation between block[0] and other positions:")
        for pos in range(1, 14):
            # Check if block[0] XOR block[pos] is constant
            xor_vals = [b[0] ^ b[pos] for b in blocks]
            unique = len(set(xor_vals))
            # Check if block[0] + block[pos] mod 256 is constant
            add_vals = [(b[0] + b[pos]) % 256 for b in blocks]
            add_unique = len(set(add_vals))

            if unique <= 2 or add_unique <= 2:
                print(f"    pos[0] vs pos[{pos:2d}]: "
                      f"XOR unique={unique}, ADD unique={add_unique}")

    # =========================================================================
    print(f"\n{'=' * 80}")
    print("TEST 7: IS K RELATED TO PORTAL COORDINATES?")
    print("=" * 80)

    # We know Secret99's portal: (-2.0890747618..., -0.0868059720...)
    # K(Secret99, dim=8) = 81
    # Check if K relates to the portal's decimal digits

    portal_x = -2.0890747618
    portal_y = -0.0868059720

    # Various extractions from portal
    frac_x = abs(portal_x) - int(abs(portal_x))  # 0.0890747618
    frac_y = abs(portal_y) - int(abs(portal_y))  # 0.0868059720

    print(f"\n  Secret99 portal: x={portal_x}, y={portal_y}")
    print(f"  K(dim=8) = 81 = 0x51 = 0b01010001")
    print(f"  Fractional parts: x={frac_x}, y={frac_y}")

    # Try various computations
    tests = [
        ("int(frac_x * 256)", int(frac_x * 256)),
        ("int(frac_y * 256)", int(frac_y * 256)),
        ("int(frac_x*256) XOR int(frac_y*256)", int(frac_x*256) ^ int(frac_y*256)),
        ("int(abs(x)*100) mod 256", int(abs(portal_x)*100) % 256),
        ("int(abs(y)*100) mod 256", int(abs(portal_y)*100) % 256),
        ("int(abs(x)*1000) XOR int(abs(y)*1000) mod 256",
         (int(abs(portal_x)*1000) ^ int(abs(portal_y)*1000)) % 256),
    ]
    for desc, val in tests:
        match = "✓ MATCH!" if val == 81 else ""
        print(f"    {desc} = {val} {match}")

    # =========================================================================
    print(f"\n{'=' * 80}")
    print("TEST 8: BLOCK-LEVEL BYTE REUSE PATTERNS")
    print("=" * 80)

    # Check if bytes from one block appear in the next block
    # This could reveal how the mixing state carries over
    for key in ["A", "Secret99"]:
        s, blocks, K = get_full_block_info(key, dimensions=8, length=70)
        if not blocks or len(blocks) < 3:
            continue

        print(f"\n  Key '{key}' (K={K}):")
        for bi in range(len(blocks) - 1):
            b_curr = blocks[bi]
            b_next = blocks[bi + 1]

            # Which bytes from current block appear in next block?
            shared = []
            for i in range(14):
                for j in range(14):
                    if b_curr[i] == b_next[j]:
                        shared.append((i, j, b_curr[i]))

            # The carry-over: block[n][13] should relate to block[n+1][0]
            carry = f"b[{bi}][13]={b_curr[13]} → b[{bi+1}][0]={b_next[0]}"
            carry_xor = b_curr[13] ^ b_next[0]

            print(f"    {carry}  XOR={carry_xor}")
        time.sleep(0.3)

    # =========================================================================
    print(f"\n{'=' * 80}")
    print("TEST 9: SCRAMBLE PARAMETER EFFECT ON K")
    print("=" * 80)

    # Does K change with scramble=on?
    for key in ["Secret99", "hello", "AB"]:
        K_no_scr = get_xor_constant(key, dimensions=8)
        time.sleep(0.2)

        # With scramble
        known = 'A' * 42
        result = fes_request(key, payload=known, dimensions=8, scramble="on")
        ct_b64 = result.get("trans", "")
        if ct_b64:
            padded = ct_b64 + '=' * (4 - len(ct_b64) % 4) if len(ct_b64) % 4 else ct_b64
            ct = base64.b64decode(padded)
            stream_rev = bytes(c ^ 0x41 for c in ct)
            s_scr = list(reversed(list(stream_rev)))
            blocks = [s_scr[i:i+14] for i in range(0, len(s_scr) - 13, 14)]
            if len(blocks) >= 2:
                xor_vals = [b[0] ^ b[13] for b in blocks]
                K_scr = xor_vals[0] if len(set(xor_vals)) == 1 else f"VARIES:{xor_vals}"
            else:
                K_scr = "?"
        else:
            K_scr = "?"
        print(f"    '{key}': K(no scramble)={K_no_scr}  K(scramble)={K_scr}  "
              f"Same? {K_no_scr == K_scr}")
        time.sleep(0.2)


if __name__ == "__main__":
    main()
