"""
Investigate stream convergence across dimensions.

KEY FINDING: dim=4 and dim=8 produce IDENTICAL streams from block 1 onward for Secret99.
Only block 0 (first 14 bytes) differs.

Questions:
1. Does this hold for ALL keys?
2. Does dim=2 also converge with dim=4/8 at some point?
3. What about dim=6? Does it match dim=4/8 from block 1?
4. What does block 0 represent? (Portal-derived initial state?)
5. Is the block 0 difference the XOR of the pair's portal Re/Im bytes?
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
    print("TEST 1: dim=4 vs dim=8 CONVERGENCE — MULTIPLE KEYS")
    print("=" * 80)

    keys = ["Secret99", "hello", "password123", "alpha", "gamma",
            "testkey1", "AB", "BA", "abc", "FES_test"]

    for key in keys:
        s4 = get_stream(key, 70, dimensions=4)
        time.sleep(0.15)
        s8 = get_stream(key, 70, dimensions=8)
        time.sleep(0.15)

        if not s4 or not s8:
            print(f"  {key:16s}: FAILED to get streams")
            continue

        min_len = min(len(s4), len(s8))
        xor = [s4[i] ^ s8[i] for i in range(min_len)]

        # Find first zero run
        first_zero = None
        for i in range(min_len):
            if all(x == 0 for x in xor[i:]):
                first_zero = i
                break

        # Check block alignment
        block0_xor = xor[:14]
        rest_zero = all(x == 0 for x in xor[14:])

        print(f"  {key:16s}: block0 XOR={block0_xor[:7]}...  "
              f"rest_all_zero={rest_zero}  converge@byte={first_zero}")

    # =========================================================================
    print(f"\n{'=' * 80}")
    print("TEST 2: dim=2 vs dim=4 vs dim=6 vs dim=8 CONVERGENCE")
    print("=" * 80)

    key = "Secret99"
    streams = {}
    for dim in [2, 4, 6, 8]:
        s = get_stream(key, 70, dimensions=dim)
        if s:
            streams[dim] = s
        time.sleep(0.2)

    for d1 in [2, 4, 6]:
        for d2 in range(d1 + 2, 10, 2):
            if d1 not in streams or d2 not in streams:
                continue
            s1, s2 = streams[d1], streams[d2]
            min_len = min(len(s1), len(s2))
            xor = [s1[i] ^ s2[i] for i in range(min_len)]

            # Find convergence point
            converge = None
            for i in range(min_len):
                if all(x == 0 for x in xor[i:min_len]):
                    converge = i
                    break

            # Per-block analysis
            blocks_diff = []
            for b in range(0, min_len, 14):
                block_xor = xor[b:b+14]
                if all(x == 0 for x in block_xor):
                    blocks_diff.append(f"B{b//14}=SAME")
                else:
                    blocks_diff.append(f"B{b//14}=DIFF")

            print(f"  dim={d1} vs dim={d2}: {' '.join(blocks_diff)}"
                  f"  converge@byte={converge}")

    # =========================================================================
    print(f"\n{'=' * 80}")
    print("TEST 3: SAME TEST FOR 'hello'")
    print("=" * 80)

    key = "hello"
    streams = {}
    for dim in [2, 4, 6, 8]:
        s = get_stream(key, 70, dimensions=dim)
        if s:
            streams[dim] = s
        time.sleep(0.2)

    for d1 in [2, 4, 6]:
        for d2 in range(d1 + 2, 10, 2):
            if d1 not in streams or d2 not in streams:
                continue
            s1, s2 = streams[d1], streams[d2]
            min_len = min(len(s1), len(s2))
            xor = [s1[i] ^ s2[i] for i in range(min_len)]

            converge = None
            for i in range(min_len):
                if all(x == 0 for x in xor[i:min_len]):
                    converge = i
                    break

            blocks_diff = []
            for b in range(0, min_len, 14):
                block_xor = xor[b:b+14]
                if all(x == 0 for x in block_xor):
                    blocks_diff.append(f"B{b//14}=SAME")
                else:
                    blocks_diff.append(f"B{b//14}=DIFF")

            print(f"  dim={d1} vs dim={d2}: {' '.join(blocks_diff)}"
                  f"  converge@byte={converge}")

    # =========================================================================
    print(f"\n{'=' * 80}")
    print("TEST 4: SAME TEST FOR 'alpha' AND 'gamma'")
    print("=" * 80)

    for key in ["alpha", "gamma"]:
        print(f"\n  Key '{key}':")
        streams = {}
        for dim in [2, 4, 6, 8]:
            s = get_stream(key, 70, dimensions=dim)
            if s:
                streams[dim] = s
            time.sleep(0.15)

        for d1 in [2, 4, 6]:
            for d2 in range(d1 + 2, 10, 2):
                if d1 not in streams or d2 not in streams:
                    continue
                s1, s2 = streams[d1], streams[d2]
                min_len = min(len(s1), len(s2))
                xor = [s1[i] ^ s2[i] for i in range(min_len)]

                converge = None
                for i in range(min_len):
                    if all(x == 0 for x in xor[i:min_len]):
                        converge = i
                        break

                blocks_diff = []
                for b in range(0, min_len, 14):
                    block_xor = xor[b:b+14]
                    if all(x == 0 for x in block_xor):
                        blocks_diff.append("SAME")
                    else:
                        blocks_diff.append("DIFF")

                print(f"    dim={d1} vs dim={d2}: blocks=[{', '.join(blocks_diff)}]"
                      f"  converge@byte={converge}")

    # =========================================================================
    print(f"\n{'=' * 80}")
    print("TEST 5: BLOCK 0 DIFFERENCE ANALYSIS")
    print("=" * 80)

    # For keys where dim=4 and dim=8 share blocks 1+,
    # what is block 0 of dim=8 XOR block 0 of dim=4?
    # This should be the contribution of pairs 2+3.

    for key in ["Secret99", "hello", "AB", "gamma"]:
        s4 = get_stream(key, 42, dimensions=4)
        time.sleep(0.15)
        s8 = get_stream(key, 42, dimensions=8)
        time.sleep(0.15)

        if not s4 or not s8:
            continue

        block0_4 = s4[:14]
        block0_8 = s8[:14]
        xor_block0 = [a ^ b for a, b in zip(block0_4, block0_8)]

        # Split into Re and Im parts (7 bytes each)
        re_xor = xor_block0[:7]
        im_xor = xor_block0[7:]

        print(f"  Key '{key}':")
        print(f"    Block0 dim=4: Re={block0_4[:7]} Im={block0_4[7:]}")
        print(f"    Block0 dim=8: Re={block0_8[:7]} Im={block0_8[7:]}")
        print(f"    XOR:          Re={re_xor}  Im={im_xor}")
        print(f"    Re XOR[0]={re_xor[0]}  Im XOR[6]={im_xor[6]}")
        print(f"    Re XOR[0] ^ Im XOR[6] = {re_xor[0] ^ im_xor[6]}")

    # =========================================================================
    print(f"\n{'=' * 80}")
    print("TEST 6: dim=2 vs dim=4 BLOCK 0 — PAIR 1 CONTRIBUTION")
    print("=" * 80)

    for key in ["Secret99", "hello", "gamma"]:
        s2 = get_stream(key, 42, dimensions=2)
        time.sleep(0.15)
        s4 = get_stream(key, 42, dimensions=4)
        time.sleep(0.15)

        if not s2 or not s4:
            continue

        block0_2 = s2[:14]
        block0_4 = s4[:14]
        xor_block0 = [a ^ b for a, b in zip(block0_2, block0_4)]

        re_xor = xor_block0[:7]
        im_xor = xor_block0[7:]

        # Check block 1 too
        block1_2 = s2[14:28] if len(s2) >= 28 else None
        block1_4 = s4[14:28] if len(s4) >= 28 else None
        b1_same = block1_2 == block1_4 if block1_2 and block1_4 else "?"

        print(f"  Key '{key}':")
        print(f"    Block0 XOR (dim=2 vs dim=4): Re={re_xor}  Im={im_xor}")
        print(f"    Block1 same? {b1_same}")

    # =========================================================================
    print(f"\n{'=' * 80}")
    print("TEST 7: CONVERGENCE PATTERN ACROSS MORE KEYS")
    print("=" * 80)

    # Quick check: for which keys do dim=2 and dim=4 converge at block 1?
    print("\n  Testing convergence block for dim=2 vs dim=4:")
    for key in keys:
        s2 = get_stream(key, 70, dimensions=2)
        time.sleep(0.15)
        s4 = get_stream(key, 70, dimensions=4)
        time.sleep(0.15)

        if not s2 or not s4:
            continue

        min_len = min(len(s2), len(s4))
        # Check each block
        converge_block = None
        for b in range(0, min_len - 13, 14):
            block_2 = s2[b:b+14]
            block_4 = s4[b:b+14]
            if block_2 == block_4:
                converge_block = b // 14
                break

        # Also check if they NEVER converge
        any_same = any(
            s2[b:b+14] == s4[b:b+14]
            for b in range(0, min_len - 13, 14)
        )

        print(f"  {key:16s}: converge at block {converge_block}"
              f"{'  (never!)' if not any_same else ''}")


if __name__ == "__main__":
    main()
