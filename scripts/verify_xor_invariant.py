"""
Verify the XOR invariant discovered in 14-byte blocks.

Observation: In each 14-byte block:
  block[0] XOR block[13] = CONSTANT (same for every block within a key)
  block[11] == block[12] (usually)

This is a structural property of the mixing function.
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


def main():
    # =========================================================================
    print("=" * 80)
    print("VERIFY: block[0] XOR block[13] = CONSTANT across all 14-byte blocks")
    print("=" * 80)

    keys = ["Secret99", "hello", "password123", "alpha", "gamma",
            "testkey1", "xyz42", "FES_test", "abc", "beta",
            "key2024", "cryptokey", "foo", "bar42", "longpass"]

    for dim in [2, 4, 8, 10]:
        print(f"\n  === Dimension {dim} ===")
        for key in keys:
            s = get_stream(key, 120, dimensions=dim)
            if not s or len(s) < 56:
                continue

            # Split into 14-byte blocks
            blocks = []
            for i in range(0, len(s) - 13, 14):
                blocks.append(s[i:i + 14])

            if len(blocks) < 2:
                continue

            # Check XOR invariant: block[0] ^ block[13] for each block
            xor_values = [b[0] ^ b[13] for b in blocks]
            all_same = len(set(xor_values)) == 1
            constant = xor_values[0] if all_same else None

            # Check position 11==12 for each block
            eq_11_12 = [b[11] == b[12] for b in blocks]
            all_eq = all(eq_11_12)

            status = "✓" if all_same else "✗"
            eq_status = "✓" if all_eq else f"({sum(eq_11_12)}/{len(eq_11_12)})"

            print(f"    {key:16s}: XOR[0,13]={xor_values} "
                  f"{status} {'constant=' + str(constant) if all_same else 'VARIES'} "
                  f"  [11]==[12]: {eq_status}")

            time.sleep(0.2)

    # =========================================================================
    print(f"\n{'=' * 80}")
    print("EXTENDED: Check ALL position-pair XOR invariants within 14-byte blocks")
    print("=" * 80)

    # For each pair (i, j) where 0 ≤ i < j ≤ 13, check if
    # block_n[i] XOR block_n[j] is constant across all blocks

    key = "Secret99"
    s = get_stream(key, 120, dimensions=8)
    time.sleep(0.3)

    if s:
        blocks = []
        for i in range(0, len(s) - 13, 14):
            blocks.append(s[i:i + 14])

        print(f"\n  Key '{key}', dim=8, {len(blocks)} blocks:")

        # Show blocks for reference
        for bi, b in enumerate(blocks):
            print(f"    Block {bi}: {b}")

        # Check all (i,j) pairs
        invariant_pairs = []
        for i in range(14):
            for j in range(i + 1, 14):
                xor_vals = [b[i] ^ b[j] for b in blocks]
                if len(set(xor_vals)) == 1:
                    invariant_pairs.append((i, j, xor_vals[0]))

        print(f"\n  Position pairs with CONSTANT XOR across all blocks:")
        for i, j, val in invariant_pairs:
            print(f"    block[{i:2d}] XOR block[{j:2d}] = {val:3d} (0x{val:02x})")

        # Also check for constant difference (mod 256)
        print(f"\n  Position pairs with CONSTANT ADD difference across all blocks:")
        for i in range(14):
            for j in range(i + 1, 14):
                diff_vals = [(b[i] - b[j]) % 256 for b in blocks]
                if len(set(diff_vals)) == 1:
                    print(f"    (block[{i:2d}] - block[{j:2d}]) mod 256 = "
                          f"{diff_vals[0]:3d} (0x{diff_vals[0]:02x})")

    # =========================================================================
    print(f"\n{'=' * 80}")
    print("CROSS-KEY: Is the XOR constant the same for all keys?")
    print("=" * 80)

    key_constants = {}
    for key in keys[:10]:
        s = get_stream(key, 70, dimensions=8)
        if not s:
            continue
        blocks = [s[i:i+14] for i in range(0, len(s) - 13, 14)]
        if len(blocks) >= 2:
            xor_vals = [b[0] ^ b[13] for b in blocks]
            if len(set(xor_vals)) == 1:
                key_constants[key] = xor_vals[0]
            else:
                key_constants[key] = f"VARIES: {xor_vals}"
        time.sleep(0.2)

    print(f"\n  XOR(block[0], block[13]) constant per key (dim=8):")
    for key, val in key_constants.items():
        print(f"    {key:16s}: {val}")

    # Check if the constant varies with dimensions
    print(f"\n  XOR(block[0], block[13]) for 'Secret99' across dimensions:")
    for dim in [2, 4, 6, 8, 10, 12]:
        s = get_stream("Secret99", 70, dimensions=dim)
        if not s:
            continue
        blocks = [s[i:i+14] for i in range(0, len(s) - 13, 14)]
        if len(blocks) >= 2:
            xor_vals = [b[0] ^ b[13] for b in blocks]
            print(f"    dim={dim:2d}: {xor_vals} "
                  f"{'CONSTANT' if len(set(xor_vals))==1 else 'VARIES'}")
        time.sleep(0.2)


if __name__ == "__main__":
    main()
