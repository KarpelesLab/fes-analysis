"""
Test hypothesis: K = XOR of per-dimension-pair constants.

If dim=2 (1 pair): K = K0
If dim=4 (2 pairs): K = K0 XOR K1
If dim=6 (3 pairs): K = K0 XOR K1 XOR K2
If dim=8 (4 pairs): K = K0 XOR K1 XOR K2 XOR K3

Then: K1 = K(dim=2) XOR K(dim=4)
      K2 = K(dim=4) XOR K(dim=6)
      K3 = K(dim=6) XOR K(dim=8)

Also test: does this hold for single-char keys (all K=0)?
"""

import base64
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


def main():
    # =========================================================================
    print("=" * 80)
    print("TEST 1: PER-PAIR K DECOMPOSITION")
    print("=" * 80)

    keys = ["Secret99", "hello", "password123", "alpha", "gamma",
            "testkey1", "xyz42", "FES_test", "abc", "beta",
            "AB", "BA", "CD", "EF", "longpass"]

    print(f"\n  {'Key':16s}  K(d2)  K(d4)  K(d6)  K(d8) | K0     K1     K2     K3     | Check(d8=K0^K1^K2^K3)")
    for key in keys:
        k = {}
        for dim in [2, 4, 6, 8]:
            k[dim] = get_xor_constant(key, dimensions=dim)
            time.sleep(0.15)

        if any(v is None for v in k.values()):
            print(f"  {key:16s}: some K=None, skip")
            continue

        K0 = k[2]
        K1 = k[2] ^ k[4]
        K2 = k[4] ^ k[6]
        K3 = k[6] ^ k[8]

        check = K0 ^ K1 ^ K2 ^ K3
        match = "✓" if check == k[8] else "✗"

        print(f"  {key:16s}  {k[2]:5d}  {k[4]:5d}  {k[6]:5d}  {k[8]:5d} | "
              f"{K0:5d}  {K1:5d}  {K2:5d}  {K3:5d}  | {check:5d} {match}")

    # =========================================================================
    print(f"\n{'=' * 80}")
    print("TEST 2: SINGLE-CHAR KEYS — ALL DIMENSIONS")
    print("=" * 80)

    print(f"\n  {'Key':5s}  K(d2)  K(d4)  K(d6)  K(d8)")
    for ch in range(65, 73):  # A-H
        key = chr(ch)
        k = {}
        for dim in [2, 4, 6, 8]:
            k[dim] = get_xor_constant(key, dimensions=dim)
            time.sleep(0.15)
        print(f"  '{chr(ch)}':  {k[2]:5}  {k[4]:5}  {k[6]:5}  {k[8]:5}")

    # =========================================================================
    print(f"\n{'=' * 80}")
    print("TEST 3: ODD DIMENSIONS — ARE THEY TRULY ROUNDED UP?")
    print("=" * 80)

    key = "Secret99"
    print(f"\n  Key '{key}':")
    for dim in range(2, 13):
        K = get_xor_constant(key, dimensions=dim)
        print(f"    dim={dim:2d}: K={K}")
        time.sleep(0.15)

    # =========================================================================
    print(f"\n{'=' * 80}")
    print("TEST 4: DOES EACH BLOCK POSITION HAVE ITS OWN INVARIANT?")
    print("=" * 80)

    # The XOR invariant is at positions (0, 13). But maybe each position
    # pair has a per-pair invariant that XORs to the total K.

    # Get streams at dim=2 and dim=4 for the same key
    key = "Secret99"
    for dim in [2, 4, 8]:
        s = get_stream(key, 70, dimensions=dim)
        if not s:
            continue
        blocks = [s[i:i+14] for i in range(0, len(s) - 13, 14)]
        print(f"\n  Key '{key}', dim={dim}, {len(blocks)} blocks:")
        for bi, b in enumerate(blocks[:4]):
            print(f"    Block {bi}: {b}")

        # Check ALL position-pair XOR invariants
        print(f"  Invariant pairs:")
        for i in range(14):
            for j in range(i+1, 14):
                xor_vals = [b[i] ^ b[j] for b in blocks]
                if len(set(xor_vals)) == 1:
                    print(f"    pos[{i:2d}] XOR pos[{j:2d}] = {xor_vals[0]} (CONSTANT)")
                elif len(set(xor_vals)) <= 2:
                    print(f"    pos[{i:2d}] XOR pos[{j:2d}] ∈ {sorted(set(xor_vals))} ({len(set(xor_vals))} vals)")
        time.sleep(0.3)

    # =========================================================================
    print(f"\n{'=' * 80}")
    print("TEST 5: STREAM COMPARISON dim=2 vs dim=4 vs dim=8")
    print("=" * 80)

    # If dim=4 = dim=2 + pair1, then stream(dim=4) might be stream(dim=2) XOR pair1_stream
    key = "Secret99"
    s2 = get_stream(key, 42, dimensions=2)
    time.sleep(0.2)
    s4 = get_stream(key, 42, dimensions=4)
    time.sleep(0.2)
    s8 = get_stream(key, 42, dimensions=8)

    if s2 and s4 and s8:
        min_len = min(len(s2), len(s4), len(s8))
        print(f"\n  stream lengths: dim=2:{len(s2)}, dim=4:{len(s4)}, dim=8:{len(s8)}")
        print(f"\n  First 28 bytes:")
        print(f"    dim=2: {s2[:28]}")
        print(f"    dim=4: {s4[:28]}")
        print(f"    dim=8: {s8[:28]}")

        xor_24 = [s2[i] ^ s4[i] for i in range(min(28, min_len))]
        xor_28 = [s2[i] ^ s8[i] for i in range(min(28, min_len))]
        xor_48 = [s4[i] ^ s8[i] for i in range(min(28, min_len))]

        print(f"\n    dim=2 XOR dim=4: {xor_24}")
        print(f"    dim=2 XOR dim=8: {xor_28}")
        print(f"    dim=4 XOR dim=8: {xor_48}")

        # Check: is xor_24 periodic with period 14?
        if len(xor_24) >= 28:
            same_14 = all(xor_24[i] == xor_24[i+14] for i in range(14))
            print(f"\n    dim2 XOR dim4 has 14-byte period? {same_14}")

        # Check: is xor_48 all zeros (dim=4 == dim=8)?
        all_zero = all(x == 0 for x in xor_48)
        print(f"    dim=4 == dim=8? {all_zero}")
    time.sleep(0.3)

    # =========================================================================
    print(f"\n{'=' * 80}")
    print("TEST 6: dim=2 BLOCKS — WHAT DETERMINES K0?")
    print("=" * 80)

    # At dim=2, only 1 pair. K0 should be a property of that single pair's extraction.
    # For single-char keys, K0=0. For multi-char keys, K0≠0 (usually).
    # Let me look at dim=2 blocks in detail for single vs multi-char keys.

    for key in ["A", "AB", "Secret99"]:
        s = get_stream(key, 42, dimensions=2)
        if not s:
            continue
        blocks = [s[i:i+14] for i in range(0, len(s) - 13, 14)]
        K = blocks[0][0] ^ blocks[0][13] if len(blocks) >= 1 else None
        print(f"\n  Key '{key}', dim=2, K={K}:")
        for bi, b in enumerate(blocks[:3]):
            print(f"    Block {bi}: {b}")
            # Show internal structure
            re_part = b[:7]
            im_part = b[7:]
            print(f"      Re(7): {re_part}  Im(7): {im_part}")
            print(f"      Re[0]={b[0]:3d} XOR Im[6]={b[13]:3d} = {b[0]^b[13]:3d}")
        time.sleep(0.3)

    # =========================================================================
    print(f"\n{'=' * 80}")
    print("TEST 7: K vs FULL STREAM — IS K FROM FIRST BLOCK ONLY?")
    print("=" * 80)

    # We know K is constant across blocks. But is K determined from the
    # first Mandelbrot iteration only, or from the portal/key setup?

    # If K is from the portal, it's determined before any iteration.
    # Test: does K depend on the stream length (which affects number of iterations)?
    key = "Secret99"
    for length in [28, 42, 56, 70, 84, 112]:
        K = get_xor_constant(key, dimensions=8, length=length)
        print(f"    len={length:3d}: K={K}")
        time.sleep(0.2)


if __name__ == "__main__":
    main()
