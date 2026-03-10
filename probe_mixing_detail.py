"""
Deep-dive into mixing function structure based on probe_mixing_function.py results.

Key findings to investigate:
1. byte[12] = byte[11] XOR {0 or 128} — what determines the bit-7 flip?
2. Im[0] XOR Im[1] correlation — what's the pattern?
3. If 12 bytes are independent and 2 are derived, can we identify the 12?
4. Does byte ordering within blocks follow any permutation pattern?
5. Test cross-block byte relationships beyond position (0,13)
"""

import base64
import json
import urllib.request
import urllib.parse
import time as time_mod
from collections import Counter

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


def get_blocks(stream, block_size=14):
    return [stream[i:i+block_size] for i in range(0, len(stream) - block_size + 1, block_size)]


def main():
    # =========================================================================
    print("=" * 80)
    print("TEST 1: WHAT DETERMINES THE BIT-7 FLIP IN byte[12] vs byte[11]?")
    print("=" * 80)

    # Collect many blocks and analyze when XOR=0 vs XOR=128
    print("\n  Collecting blocks for analysis...")
    flip_data = []  # list of (key, block_idx, block, flip)

    for ki in range(30):
        key = f"test_{ki:03d}"
        s = get_stream(key, 280, dimensions=2)
        if not s:
            continue
        blocks = get_blocks(s)
        for bi, block in enumerate(blocks):
            xor_val = block[11] ^ block[12]
            flip = 1 if xor_val == 128 else 0
            flip_data.append((key, bi, block, flip))
        time_mod.sleep(0.15)

    total = len(flip_data)
    flips = sum(d[3] for d in flip_data)
    print(f"\n  {total} blocks: {total - flips} with XOR=0 ({100*(total-flips)/total:.1f}%), "
          f"{flips} with XOR=128 ({100*flips/total:.1f}%)")

    # Is the flip determined by any single byte in the block?
    print(f"\n  Correlation of bit-7 flip with each byte position:")
    for pos in range(14):
        if pos in (11, 12):
            continue
        # Check if any specific bit of byte[pos] predicts the flip
        for bit in range(8):
            match = sum(1 for _, _, block, flip in flip_data
                        if ((block[pos] >> (7 - bit)) & 1) == flip)
            pct = 100 * match / total
            if pct > 65 or pct < 35:  # Only show strong correlations
                part = f"Re[{pos}]" if pos < 7 else f"Im[{pos-7}]"
                print(f"    {part}.bit{bit}: {pct:.1f}% match with flip")

    # Is the flip determined by the block index?
    print(f"\n  Flip pattern by block index (first 15 blocks):")
    for bi in range(15):
        bi_flips = [d[3] for d in flip_data if d[1] == bi]
        if bi_flips:
            flip_pct = 100 * sum(bi_flips) / len(bi_flips)
            print(f"    block {bi:2d}: {sum(bi_flips)}/{len(bi_flips)} flip "
                  f"({flip_pct:.0f}%)")

    # Is the flip related to parity of the 12 other bytes?
    print(f"\n  Flip vs parity of other bytes:")
    # XOR parity of bytes 0-10
    match_parity = sum(1 for _, _, block, flip in flip_data
                       if (sum(block[i].bit_count() for i in range(11)) % 2) == flip)
    print(f"    XOR parity of bytes 0-10: {100*match_parity/total:.1f}% match")

    # XOR of all other bytes
    match_xor = sum(1 for _, _, block, flip in flip_data
                    if ((block[0] ^ block[13]) >> 7 & 1) == flip)
    print(f"    MSB of (byte[0] XOR byte[13]): {100*match_xor/total:.1f}% match")

    # byte[11] bit 7
    match_b11 = sum(1 for _, _, block, flip in flip_data
                    if ((block[11] >> 7) & 1) == flip)
    print(f"    byte[11] bit 7: {100*match_b11/total:.1f}% match")

    # =========================================================================
    print(f"\n{'=' * 80}")
    print("TEST 2: Im[0] AND Im[1] CORRELATION PATTERN")
    print("=" * 80)

    # We saw XOR entropy 6.403 for (7,8). Let's understand the pattern
    xor_78 = [d[2][7] ^ d[2][8] for d in flip_data]
    c = Counter(xor_78)
    print(f"\n  Im[0] XOR Im[1] distribution (top 20):")
    for val, count in c.most_common(20):
        print(f"    {val:3d} ({val:08b}): {count} times ({100*count/total:.1f}%)")

    # Is there a pattern in the XOR values?
    unique_xor = len(set(xor_78))
    print(f"\n  {unique_xor} unique XOR values out of 256 possible")

    # Check if the XOR value is key-dependent (constant within key)
    print(f"\n  Is Im[0] XOR Im[1] constant per key?")
    for ki in range(5):
        key = f"test_{ki:03d}"
        key_xors = [d[2][7] ^ d[2][8] for d in flip_data if d[0] == key]
        unique = len(set(key_xors))
        print(f"    {key}: {key_xors[:10]}  ({unique} unique)")

    # =========================================================================
    print(f"\n{'=' * 80}")
    print("TEST 3: SYSTEMATIC PAIR-WISE XOR CONSTANT CHECK")
    print("=" * 80)

    # For each pair (p1, p2), check if XOR is constant within any single key
    print(f"\n  Checking all 91 position pairs for per-key XOR constancy:")

    # Use data from first 5 keys, check if XOR is constant
    constant_pairs = []
    nearly_constant_pairs = []

    for p1 in range(14):
        for p2 in range(p1+1, 14):
            all_const = True
            almost_const = True
            for ki in range(min(10, 30)):
                key = f"test_{ki:03d}"
                key_xors = [d[2][p1] ^ d[2][p2] for d in flip_data if d[0] == key]
                if not key_xors:
                    continue
                unique = len(set(key_xors))
                if unique > 1:
                    all_const = False
                if unique > 2:
                    almost_const = False
            if all_const:
                constant_pairs.append((p1, p2))
            elif almost_const:
                nearly_constant_pairs.append((p1, p2))

    print(f"\n  CONSTANT XOR pairs (all keys):")
    for p1, p2 in constant_pairs:
        part1 = f"Re[{p1}]" if p1 < 7 else f"Im[{p1-7}]"
        part2 = f"Re[{p2}]" if p2 < 7 else f"Im[{p2-7}]"
        # Show actual K values
        k_vals = set()
        for ki in range(5):
            key = f"test_{ki:03d}"
            key_xors = [d[2][p1] ^ d[2][p2] for d in flip_data if d[0] == key]
            if key_xors:
                k_vals.add(key_xors[0])
        print(f"    ({p1:2d},{p2:2d}) = ({part1:>6s}, {part2:>6s}): K values={sorted(k_vals)}")

    print(f"\n  NEARLY-CONSTANT XOR pairs (≤2 unique values per key):")
    for p1, p2 in nearly_constant_pairs:
        part1 = f"Re[{p1}]" if p1 < 7 else f"Im[{p1-7}]"
        part2 = f"Re[{p2}]" if p2 < 7 else f"Im[{p2-7}]"
        # Show example values
        key = "test_000"
        key_xors = [d[2][p1] ^ d[2][p2] for d in flip_data if d[0] == key]
        if key_xors:
            print(f"    ({p1:2d},{p2:2d}) = ({part1:>6s}, {part2:>6s}): "
                  f"example={sorted(set(key_xors))}")

    # =========================================================================
    print(f"\n{'=' * 80}")
    print("TEST 4: BYTE POSITION AUTOCORRELATION (ACROSS BLOCKS)")
    print("=" * 80)

    # For each position, compute autocorrelation between block n and block n+k
    key = "Secret99"
    s = get_stream(key, 560, dimensions=2)
    if not s:
        print("  Failed to get stream")
        return
    blocks = get_blocks(s)

    print(f"\n  Autocorrelation (XOR) at lag 1,2,3 for Secret99:")
    print(f"  {'Pos':>4s}  {'Part':>6s}  {'Lag1_uniq':>10s}  {'Lag2_uniq':>10s}  {'Lag3_uniq':>10s}")
    for pos in range(14):
        lag_data = {}
        for lag in [1, 2, 3]:
            xors = [blocks[i][pos] ^ blocks[i-lag][pos]
                    for i in range(lag, len(blocks))]
            lag_data[lag] = len(set(xors))
        part = f"Re[{pos}]" if pos < 7 else f"Im[{pos-7}]"
        print(f"  {pos:4d}  {part:>6s}  {lag_data[1]:10d}  {lag_data[2]:10d}  {lag_data[3]:10d}")

    # =========================================================================
    print(f"\n{'=' * 80}")
    print("TEST 5: CAN byte[13] BE RECONSTRUCTED FROM OTHER BYTES?")
    print("=" * 80)

    # We know byte[13] = byte[0] XOR K. But can K be determined from the block?
    # Test: is K related to any combination of the other 12 bytes?

    print("\n  Testing if K can be computed from non-(0,13) bytes:")
    for ki in range(5):
        key = f"test_{ki:03d}"
        key_blocks = [d[2] for d in flip_data if d[0] == key]
        if not key_blocks:
            continue
        K = key_blocks[0][0] ^ key_blocks[0][13]

        # Try: K = XOR of various byte subsets
        tests = [
            ("XOR(1..6)", lambda b: b[1]^b[2]^b[3]^b[4]^b[5]^b[6]),
            ("XOR(7..12)", lambda b: b[7]^b[8]^b[9]^b[10]^b[11]^b[12]),
            ("XOR(1..12)", lambda b: b[1]^b[2]^b[3]^b[4]^b[5]^b[6]^b[7]^b[8]^b[9]^b[10]^b[11]^b[12]),
            ("byte[1]", lambda b: b[1]),
            ("byte[6]", lambda b: b[6]),
            ("byte[7]", lambda b: b[7]),
        ]

        print(f"\n  Key '{key}', K={K}:")
        for label, func in tests:
            vals = [func(b) for b in key_blocks]
            if len(set(vals)) == 1 and vals[0] == K:
                print(f"    {label:20s}: MATCH! (all = {K})")
            elif len(set(vals)) == 1:
                print(f"    {label:20s}: constant={vals[0]} but K={K}")
            else:
                print(f"    {label:20s}: varies: {vals[:5]}")

    # =========================================================================
    print(f"\n{'=' * 80}")
    print("TEST 6: BYTE PATTERN WITHIN [Re₇ || Im₇] AT dim=2")
    print("=" * 80)

    # At dim=2, we have a single pair. Let's look at the full block as two
    # 7-byte numbers and see if there's any mathematical relationship

    key = "Secret99"
    s = get_stream(key, 280, dimensions=2)
    if not s:
        return
    blocks = get_blocks(s)

    print(f"\n  Re and Im as 56-bit integers (dim=2, Secret99):")
    for bi, block in enumerate(blocks[:10]):
        re_val = sum(block[i] << (8*(6-i)) for i in range(7))
        im_val = sum(block[7+i] << (8*(6-i)) for i in range(7))
        re_signed = re_val - (1 << 56) if re_val >= (1 << 55) else re_val
        im_signed = im_val - (1 << 56) if im_val >= (1 << 55) else im_val
        xor_val = re_val ^ im_val
        print(f"    Block {bi:2d}: Re={re_signed:>18d}  Im={im_signed:>18d}  "
              f"Re^Im={xor_val:>18d}  ReXORIm_MSB={block[0]^block[7]:3d}  "
              f"ReXORIm_LSB={block[6]^block[13]:3d}")

    # Check if Re+Im or Re-Im has any pattern
    print(f"\n  Sum and difference of Re, Im:")
    for bi, block in enumerate(blocks[:10]):
        re_val = sum(block[i] << (8*(6-i)) for i in range(7))
        im_val = sum(block[7+i] << (8*(6-i)) for i in range(7))
        re_s = re_val - (1 << 56) if re_val >= (1 << 55) else re_val
        im_s = im_val - (1 << 56) if im_val >= (1 << 55) else im_val
        s = re_s + im_s
        d = re_s - im_s
        print(f"    Block {bi:2d}: Re+Im={s:>18d}  Re-Im={d:>18d}")

    # =========================================================================
    print(f"\n{'=' * 80}")
    print("TEST 7: FIXED-POINT FORMAT CONSTRAINT FROM BLOCK VALUES")
    print("=" * 80)

    # For Mandelbrot set, typical values are in [-2, 2]
    # Different fixed-point formats:
    # 2.54: range [-2, 2), 1 sign + 1 int + 54 frac bits => byte[0] encodes sign+int
    # For z in [-2, 2): byte[0] should be 00, 01, 10, 11 (unsigned view: 0, 64, 128, 192)
    # But we see byte[0] spanning 0-255 — so either not Mandelbrot values, or different format

    print("\n  Byte[0] (Re MSB) distribution analysis:")
    print("  If format is s.1.54 (Mandelbrot range [-2,2)):")
    print("    byte[0] should be in {0x00..0x01, 0xFE..0xFF} for values in [-2,2)")

    # Collect byte[0] values
    byte0_vals = [d[2][0] for d in flip_data]
    # How many are in [-2,2) range for different formats?
    for int_bits in [1, 2, 3, 4, 8]:
        frac_bits = 56 - int_bits
        max_byte0_for_mandelbrot = (1 << int_bits) - 1  # positive
        min_byte0_for_mandelbrot = 256 - (1 << int_bits)  # negative
        in_range = sum(1 for v in byte0_vals if v <= max_byte0_for_mandelbrot or v >= min_byte0_for_mandelbrot)
        print(f"    {int_bits}.{frac_bits}: byte[0] in [-{1<<int_bits}, {1<<int_bits}): "
              f"{in_range}/{len(byte0_vals)} ({100*in_range/len(byte0_vals):.1f}%)")

    # =========================================================================
    print(f"\n{'=' * 80}")
    print("TEST 8: SPECIFIC BIT RELATIONSHIPS BETWEEN Re AND Im")
    print("=" * 80)

    # The XOR invariant says Re[MSB] XOR Im[LSB] = K
    # The bit-7 pattern says Im[4] and Im[5] differ by at most bit 7
    # Are there other cross-Re/Im bit relationships?

    print("\n  Checking if specific Re bits determine Im bits:")
    for re_pos in range(7):
        for im_pos in range(7):
            for re_bit in range(8):
                for im_bit in range(8):
                    match = sum(1 for _, _, b, _ in flip_data
                                if ((b[re_pos] >> (7-re_bit)) & 1) ==
                                   ((b[7+im_pos] >> (7-im_bit)) & 1))
                    pct = 100 * match / total
                    if pct > 80 or pct < 20:
                        print(f"    Re[{re_pos}].bit{re_bit} {'==' if pct > 80 else '!='} "
                              f"Im[{im_pos}].bit{im_bit}: {pct:.1f}%")

    print("\n  Done.")


if __name__ == "__main__":
    main()
