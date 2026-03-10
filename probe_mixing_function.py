"""
Characterize the "nonlinear rolling transformation" (mixing function).

We know:
- 14-byte blocks = [Re₇ || Im₇] (7 bytes each, 56-bit fixed-point)
- block[0] XOR block[13] = K (constant across all blocks, key+dim dependent)
- block[11] XOR block[12] ∈ {0, 128} (Im[4] and Im[5] differ by at most bit 7)
- "12 significant bytes" per dim per iteration (vs 14 raw bytes)
- Mixing has "inter-byte and inter-iteration dependencies"
- Described as "a small cryptographic permutation" (Appendix B, HFN Theory)

Key questions:
1. Are bytes 0 and 13 untouched by mixing? (They preserve XOR invariant)
2. Is the mixing position-preserving? (bytes stay in same slot)
3. What is the byte-level entropy per position?
4. How do byte values correlate between consecutive blocks?
5. What bit-level patterns exist per position?
6. Does the mixing function have a detectable period?
"""

import base64
import json
import urllib.request
import urllib.parse
import time as time_mod
import hashlib
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


def entropy(values):
    """Shannon entropy in bits."""
    import math
    n = len(values)
    if n == 0:
        return 0
    counts = Counter(values)
    return -sum((c/n) * math.log2(c/n) for c in counts.values() if c > 0)


def main():
    # =========================================================================
    print("=" * 80)
    print("TEST 1: BYTE-POSITION ENTROPY ACROSS MANY KEYS (dim=2)")
    print("=" * 80)
    print("\n  Collecting streams for 40 different keys at dim=2...")

    keys = [f"key_{i:03d}" for i in range(40)]
    all_blocks = {pos: [] for pos in range(14)}

    for key in keys:
        s = get_stream(key, 70, dimensions=2)
        if s:
            blocks = get_blocks(s)
            for block in blocks:
                for pos in range(14):
                    all_blocks[pos].append(block[pos])
        time_mod.sleep(0.15)

    print(f"\n  Entropy per byte position (across {sum(len(v) for v in all_blocks.values())//14} total blocks):")
    print(f"  {'Pos':>4s}  {'Part':>6s}  {'Entropy':>8s}  {'UniqueVals':>10s}  {'Min':>4s}  {'Max':>4s}  {'Mean':>6s}")
    for pos in range(14):
        vals = all_blocks[pos]
        if not vals:
            continue
        part = f"Re[{pos}]" if pos < 7 else f"Im[{pos-7}]"
        e = entropy(vals)
        unique = len(set(vals))
        print(f"  {pos:4d}  {part:>6s}  {e:8.3f}  {unique:10d}  {min(vals):4d}  {max(vals):4d}  {sum(vals)/len(vals):6.1f}")

    # =========================================================================
    print(f"\n{'=' * 80}")
    print("TEST 2: BYTE VALUE DISTRIBUTIONS AT POSITIONS 0 AND 13")
    print("=" * 80)

    # If bytes 0 and 13 are unmixed MSB/LSB, they should have specific distributions
    # MSB of Re: for Mandelbrot values in [-2, 2], the MSB should cluster around specific values
    # LSB of Im: should be more uniformly distributed (low-order fractional bits)

    print(f"\n  Position 0 (Re[MSB]) top-10 values:")
    c0 = Counter(all_blocks[0])
    for val, count in c0.most_common(10):
        print(f"    {val:3d} ({val:08b}): {count} times ({100*count/len(all_blocks[0]):.1f}%)")

    print(f"\n  Position 13 (Im[LSB]) top-10 values:")
    c13 = Counter(all_blocks[13])
    for val, count in c13.most_common(10):
        print(f"    {val:3d} ({val:08b}): {count} times ({100*count/len(all_blocks[13]):.1f}%)")

    # Compare with a "middle" byte (position 6)
    print(f"\n  Position 6 (Re[LSB]) top-10 values:")
    c6 = Counter(all_blocks[6])
    for val, count in c6.most_common(10):
        print(f"    {val:3d} ({val:08b}): {count} times ({100*count/len(all_blocks[6]):.1f}%)")

    # =========================================================================
    print(f"\n{'=' * 80}")
    print("TEST 3: INTER-BLOCK CORRELATION BY POSITION (dim=2, single key)")
    print("=" * 80)

    # For a single key, how do byte values change across consecutive blocks?
    # If mixing is "rolling", consecutive blocks should have cross-block dependencies
    key = "Secret99"
    s = get_stream(key, 280, dimensions=2)  # ~20 blocks
    if s:
        blocks = get_blocks(s)
        print(f"\n  Key '{key}', {len(blocks)} blocks")
        print(f"\n  Block-to-block XOR per position:")
        print(f"  {'Pos':>4s}  {'Deltas (XOR with prev block)':s}")
        for pos in range(14):
            deltas = [blocks[i][pos] ^ blocks[i-1][pos] for i in range(1, min(8, len(blocks)))]
            part = f"Re[{pos}]" if pos < 7 else f"Im[{pos-7}]"
            print(f"  {pos:4d}  {part:>6s}  {deltas}")

        # Check if any position has periodic behavior
        print(f"\n  Byte values across blocks:")
        print(f"  {'Block':>6s}  ", end="")
        for pos in range(14):
            print(f"{pos:>4d}", end="")
        print()
        for bi, block in enumerate(blocks[:10]):
            print(f"  {bi:6d}  ", end="")
            for pos in range(14):
                print(f"{block[pos]:4d}", end="")
            print()

    # =========================================================================
    print(f"\n{'=' * 80}")
    print("TEST 4: BIT-LEVEL PATTERNS PER POSITION")
    print("=" * 80)

    # For each bit position within each byte, compute bias (deviation from 50/50)
    print(f"\n  Bit bias per position (0=always 0, 1=always 1, 0.5=unbiased):")
    print(f"  {'Pos':>4s}  {'Part':>6s}  ", end="")
    for bit in range(8):
        print(f"  bit{bit}", end="")
    print()

    for pos in range(14):
        vals = all_blocks[pos]
        if not vals:
            continue
        part = f"Re[{pos}]" if pos < 7 else f"Im[{pos-7}]"
        print(f"  {pos:4d}  {part:>6s}  ", end="")
        for bit in range(8):
            ones = sum(1 for v in vals if v & (1 << (7 - bit)))
            bias = ones / len(vals)
            # Highlight significantly biased bits
            marker = "*" if abs(bias - 0.5) > 0.15 else " "
            print(f"  {bias:.2f}{marker}", end="")
        print()

    # =========================================================================
    print(f"\n{'=' * 80}")
    print("TEST 5: CROSS-POSITION BYTE CORRELATIONS WITHIN BLOCKS")
    print("=" * 80)

    # For each pair of positions, compute correlation
    # Focus on pairs that might reveal mixing structure
    print(f"\n  XOR between specific position pairs (mode of XOR value):")

    interesting_pairs = [
        (0, 13), (0, 7), (6, 7), (6, 13),
        (0, 1), (1, 2), (5, 6), (7, 8),
        (11, 12), (10, 11), (12, 13),
        (0, 6), (7, 13), (3, 10),
    ]
    for p1, p2 in interesting_pairs:
        xor_vals = [all_blocks[p1][i] ^ all_blocks[p2][i]
                    for i in range(len(all_blocks[p1]))]
        c = Counter(xor_vals)
        top3 = c.most_common(3)
        part1 = f"Re[{p1}]" if p1 < 7 else f"Im[{p1-7}]"
        part2 = f"Re[{p2}]" if p2 < 7 else f"Im[{p2-7}]"
        e = entropy(xor_vals)
        print(f"  {p1:2d}({part1:>6s}) ^ {p2:2d}({part2:>6s}): "
              f"entropy={e:.2f}  top3={top3}")

    # =========================================================================
    print(f"\n{'=' * 80}")
    print("TEST 6: DOES THE MIXING HAVE INTER-ITERATION DEPENDENCY?")
    print("=" * 80)

    # If mixing has inter-iteration dependency, then the same raw block
    # at different positions would produce different output.
    # Test: for keys where the Mandelbrot orbit enters a cycle (period-2 or period-4),
    # the raw blocks would repeat, but the mixed output should differ.
    # We can detect this by checking if any 14-byte blocks repeat in the stream.

    print(f"\n  Checking for repeated blocks in long streams (dim=2):")
    for key in ["Secret99", "hello", "AB", "x", "key_001"]:
        s = get_stream(key, 560, dimensions=2)  # ~40 blocks
        if not s:
            continue
        blocks = get_blocks(s)
        block_strs = [tuple(b) for b in blocks]
        unique = len(set(block_strs))
        # Check for near-repeats (blocks that match on 12+ bytes)
        near_repeats = []
        for i in range(len(blocks)):
            for j in range(i+1, len(blocks)):
                match = sum(1 for k in range(14) if blocks[i][k] == blocks[j][k])
                if match >= 12:
                    near_repeats.append((i, j, match))
        print(f"  {key:12s}: {len(blocks)} blocks, {unique} unique"
              f"  near-repeats(≥12/14): {near_repeats[:5]}")
        time_mod.sleep(0.15)

    # =========================================================================
    print(f"\n{'=' * 80}")
    print("TEST 7: POSITION 0 AND 13 — ARE THEY RAW (UNMIXED)?")
    print("=" * 80)

    # If pos 0 and 13 are raw Re[MSB] and Im[LSB], then:
    # 1. For the SAME key, pos 0 should track the MSB of Re(z) across iterations
    #    The MSB changes slowly for bounded orbits
    # 2. For DIFFERENT keys, pos 0 should correlate with the key's portal Re coordinate

    # Test: collect pos 0 values across many blocks for several keys
    print(f"\n  Position 0 (Re[MSB]) values across blocks:")
    for key in ["Secret99", "hello", "AB", "1234"]:
        s = get_stream(key, 210, dimensions=2)
        if not s:
            continue
        blocks = get_blocks(s)
        vals = [b[0] for b in blocks[:15]]
        unique_pct = 100 * len(set(vals)) / len(vals)
        print(f"    {key:12s}: {vals}  ({unique_pct:.0f}% unique)")
        time_mod.sleep(0.15)

    print(f"\n  Position 13 (Im[LSB]) values across blocks:")
    for key in ["Secret99", "hello", "AB", "1234"]:
        s = get_stream(key, 210, dimensions=2)
        if not s:
            continue
        blocks = get_blocks(s)
        vals = [b[13] for b in blocks[:15]]
        unique_pct = 100 * len(set(vals)) / len(vals)
        print(f"    {key:12s}: {vals}  ({unique_pct:.0f}% unique)")
        time_mod.sleep(0.15)

    # =========================================================================
    print(f"\n{'=' * 80}")
    print("TEST 8: BLOCK STRUCTURE — 12 vs 14 SIGNIFICANT BYTES")
    print("=" * 80)

    # The spec says "12 significant bytes per dimension per iteration"
    # Website says "104 bits per dimension" = 13 bytes
    # We observe 14-byte blocks
    # Which 2 bytes are "insignificant"?

    # Hypothesis A: bytes 11 and 12 (Im[4] and Im[5]) — they're nearly identical
    # Hypothesis B: bytes 0 and 13 — they're linked by K
    # Hypothesis C: some other pair

    # Test: if we remove bytes 11 and 12, or 0 and 13, do the remaining 12 bytes
    # still have full entropy?

    print(f"\n  Entropy analysis — which bytes might be 'derived':")
    # For each byte, check if it can be predicted from other bytes
    for pos in range(14):
        vals = all_blocks[pos]
        e = entropy(vals)
        # Check correlation with other positions
        best_pred = None
        best_pred_entropy = 8.0
        for other_pos in range(14):
            if other_pos == pos:
                continue
            # XOR with other position — if XOR has low entropy, pos is predictable from other
            xor_vals = [all_blocks[pos][i] ^ all_blocks[other_pos][i]
                        for i in range(len(vals))]
            xe = entropy(xor_vals)
            if xe < best_pred_entropy:
                best_pred_entropy = xe
                best_pred = other_pos
        part = f"Re[{pos}]" if pos < 7 else f"Im[{pos-7}]"
        print(f"  pos={pos:2d} ({part:>6s}): entropy={e:.3f}  "
              f"best_XOR_predictor=pos {best_pred} (XOR entropy={best_pred_entropy:.3f})")

    # =========================================================================
    print(f"\n{'=' * 80}")
    print("TEST 9: XOR OF CONSECUTIVE BLOCKS AT POSITION 0 vs 13")
    print("=" * 80)

    # From investigate_mixing.py we know block_n[0] XOR block_{n+1}[0] == block_n[13] XOR block_{n+1}[13]
    # This means the DELTA at pos 0 equals the DELTA at pos 13
    # This is a VERY strong constraint on the mixing function

    # Let's verify and extend: do any other positions share deltas?
    key = "Secret99"
    s = get_stream(key, 280, dimensions=2)
    if s:
        blocks = get_blocks(s)
        # For each pair of positions, check if their deltas are always equal
        print(f"\n  Positions with identical block-to-block XOR deltas:")
        n_blocks = min(15, len(blocks))
        for p1 in range(14):
            for p2 in range(p1+1, 14):
                deltas_p1 = [blocks[i][p1] ^ blocks[i-1][p1] for i in range(1, n_blocks)]
                deltas_p2 = [blocks[i][p2] ^ blocks[i-1][p2] for i in range(1, n_blocks)]
                if deltas_p1 == deltas_p2:
                    print(f"    pos {p1} and pos {p2}: deltas IDENTICAL  {deltas_p1[:5]}...")

        # Also check if delta at pos 0 equals delta at pos 13 across multiple keys
        print(f"\n  Verifying pos 0 delta == pos 13 delta across keys:")
        for key2 in ["hello", "AB", "key_005", "test123"]:
            s2 = get_stream(key2, 140, dimensions=2)
            if not s2:
                continue
            blocks2 = get_blocks(s2)
            n = min(8, len(blocks2))
            d0 = [blocks2[i][0] ^ blocks2[i-1][0] for i in range(1, n)]
            d13 = [blocks2[i][13] ^ blocks2[i-1][13] for i in range(1, n)]
            match = d0 == d13
            print(f"    {key2:12s}: {'MATCH' if match else 'DIFFER'}  d0={d0}  d13={d13}")
            time_mod.sleep(0.15)

    # =========================================================================
    print(f"\n{'=' * 80}")
    print("TEST 10: NIBBLE-LEVEL ANALYSIS OF MIXING")
    print("=" * 80)

    # If the mixing operates at the nibble (4-bit) level, we might see patterns
    # Check if high and low nibbles of each byte have independent distributions
    print(f"\n  High vs low nibble entropy per position:")
    print(f"  {'Pos':>4s}  {'Part':>6s}  {'HiNibEnt':>8s}  {'LoNibEnt':>8s}  {'ByteEnt':>8s}")
    for pos in range(14):
        vals = all_blocks[pos]
        hi_nibs = [v >> 4 for v in vals]
        lo_nibs = [v & 0xF for v in vals]
        he = entropy(hi_nibs)
        le = entropy(lo_nibs)
        be = entropy(vals)
        print(f"  {pos:4d}  {'Re['+str(pos)+']' if pos < 7 else 'Im['+str(pos-7)+']':>6s}  "
              f"{he:8.3f}  {le:8.3f}  {be:8.3f}")


if __name__ == "__main__":
    main()
