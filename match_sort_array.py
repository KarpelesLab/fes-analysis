"""
Check if the recovered Sort Array ordering matches any known column
from FT-Explained, and test if the ordering changes with dimensions.
"""

import base64
import json
import urllib.request
import urllib.parse

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


def b64_decode(s):
    padded = s + '=' * (4 - len(s) % 4) if len(s) % 4 else s
    return base64.b64decode(padded)


def recover_permutation(key, length, dimensions=8):
    # Get stream with uniform input + scramble
    result1 = fes_request(key, 'A' * length, dimensions, scramble="on")
    ct1 = b64_decode(result1.get("trans", ""))
    stream_scr = [0] * length
    for i in range(length):
        stream_scr[length - 1 - i] = ct1[i] ^ 0x41

    # Encrypt unique bytes
    unique_chars = ''.join(chr(32 + i) for i in range(length))
    result2 = fes_request(key, unique_chars, dimensions, scramble="on")
    ct2 = b64_decode(result2.get("trans", ""))

    perm = [0] * length
    pt_bytes = [ord(c) for c in unique_chars]
    for j in range(length):
        decrypted_byte = ct2[j] ^ stream_scr[length - 1 - j]
        try:
            perm[j] = pt_bytes.index(decrypted_byte)
        except ValueError:
            perm[j] = -1
    return perm


def main():
    # FT-Explained data for Secret99, "Demo Payload" (12 bytes)
    # Note: these are the FV, angle, and hypotenuse values from the FT-Explained table
    fv_values = [
        5874.7274351297,    # D
        5874.72743642702,   # e
        5874.72743503904,   # m
        5874.72743541918,   # o
        5874.72743509044,   # space
        5874.72743397111,   # P
        5874.72743567349,   # a
        5874.72743554848,   # y
        5874.72743509473,   # l
        5874.72743537211,   # o2
        5874.72743620258,   # a2
        5874.72743485877,   # d
    ]

    angles = [
        3.72743512971,
        190.45487025942,
        29.90974051884,
        164.81948103768,
        145.63896207536,
        5.27792415072,
        143.55584830144,
        232.11169660288,
        297.22339320576,
        128.44678641152,
        172.89357282304,
        322.78714564608,
    ]

    hyps = [
        3.066991110601e-17,
        5.7382629212887302e-13,
        3.999861553713324e-14,
        1.5537923727886374e-13,
        5.8767196673788068e-13,
        5.2305881856255116e-13,
        4.3536954603879642e-13,
        2.1383875229467386e-13,
        1.3230311293051764e-13,
        3.4460345693530176e-13,
        5.2767404343218082e-13,
        2.2153079374412256e-13,
    ]

    stream_bytes = [215, 27, 210, 179, 226, 199, 7, 46, 14, 223, 201, 97]

    # Recovered Sort Array ordering (smallest to largest)
    sort_order = [10, 4, 9, 7, 8, 5, 1, 2, 0, 11, 3, 6]

    print("=" * 80)
    print("MATCHING SORT ARRAY ORDER TO KNOWN COLUMNS")
    print("=" * 80)

    # Check each column
    for name, values in [("FV (|z_6|)", fv_values), ("Angle", angles),
                          ("Hypotenuse", hyps), ("Stream byte", stream_bytes)]:
        # Sort the values and get the ordering
        indexed = sorted(enumerate(values), key=lambda x: x[1])
        computed_order = [idx for idx, _ in indexed]

        match = computed_order == sort_order
        print(f"\n  {name}:")
        print(f"    Computed order:    {computed_order}")
        print(f"    Recovered order:   {sort_order}")
        print(f"    Match: {'✓ YES' if match else '✗ NO'}")

        if not match:
            # Check how many positions match
            matches = sum(1 for a, b in zip(computed_order, sort_order) if a == b)
            print(f"    Positions matching: {matches}/12")

    # Test: does the permutation change with dimensions?
    print(f"\n{'=' * 80}")
    print("PERMUTATION vs DIMENSION COUNT")
    print(f"{'=' * 80}")

    for dim in [2, 4, 6, 8, 10, 12]:
        perm = recover_permutation("Secret99", 12, dimensions=dim)
        inv_perm = [0] * 12
        if -1 not in perm:
            for j in range(12):
                inv_perm[perm[j]] = j
            order = [0] * 12
            for j in range(12):
                order[inv_perm[j]] = j
            print(f"  dim={dim:2d}: π={perm}")
            # Show the Sort Array order
            sort_ord = [inv_perm[r] for r in range(12)]
            print(f"          order (small→large): {sort_ord}")

    # Test: does the permutation change with payload length?
    print(f"\n{'=' * 80}")
    print("PERMUTATION vs PAYLOAD LENGTH")
    print(f"{'=' * 80}")

    for length in [8, 12, 16, 20, 24]:
        perm = recover_permutation("Secret99", length, dimensions=8)
        if -1 not in perm:
            print(f"  len={length:2d}: π={perm}")

    # Compare Sort Array values with the Peer Review Guide §7.4.1 table
    print(f"\n{'=' * 80}")
    print("PEER REVIEW GUIDE §7.4.1 SORT ARRAY VALUES (Pass 1)")
    print(f"{'=' * 80}")

    prg_values = {
        0: 4793.4512063949561677,
        1: 357.7112770234736040,
        2: 1447.6222373512767626,
        3: 822.5561887333744784,
        4: 2585.3478635626196090,
        5: 185.8660109157144254,
        6: 3626.0061026419645930,
        7: 205.1596320617041240,
        8: 37.3888294878806581,
        31: 656.2230266658864937,
    }

    indexed_prg = sorted(prg_values.items(), key=lambda x: x[1])
    print(f"  Sorted by value (ascending):")
    for idx, val in indexed_prg:
        print(f"    Byte {idx:2d}: {val}")

    print(f"\n  These are raw decimal z values at each byte position.")
    print(f"  Range: {min(prg_values.values()):.1f} to {max(prg_values.values()):.1f}")
    print(f"  Compare: FT-Explained FV is always ~5874.727 for ALL positions")
    print(f"  → Sort Array values are NOT the same as FV shown in FT-Explained")


if __name__ == "__main__":
    main()
