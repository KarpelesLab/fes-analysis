"""
Investigate the period-3 pattern in byte[11] vs byte[12] (Im[4] vs Im[5]).

Findings from probe_mixing_detail.py:
- Blocks at index 0 mod 3: ALWAYS Im[4]==Im[5] (100% across 30 keys)
- Blocks at index 1 mod 3: ~50% have Im[4]!=Im[5]
- Blocks at index 2 mod 3: ~65-70% have Im[4]!=Im[5]

This period-3 structure is a major clue about the mixing function.

Tests:
1. Verify period-3 with more keys and more blocks
2. Does period-3 hold at different dimensions?
3. Are there other byte positions with period-3 patterns?
4. Does the period change with key?
5. At blocks 0 mod 3, are there OTHER byte relationships that are deterministic?
6. What about period-2 or period-7 patterns?
"""

import base64
import json
import urllib.request
import urllib.parse
import time as time_mod
from collections import Counter, defaultdict

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
    print("TEST 1: VERIFY PERIOD-3 WITH 50 KEYS, 30 BLOCKS EACH")
    print("=" * 80)

    all_data = defaultdict(list)  # block_idx -> list of (key, xor_val)

    print("\n  Collecting data for 50 keys at dim=2...")
    for ki in range(50):
        key = f"p3_{ki:03d}"
        s = get_stream(key, 420, dimensions=2)  # 30 blocks
        if not s:
            continue
        blocks = get_blocks(s)
        for bi, block in enumerate(blocks):
            xor_val = block[11] ^ block[12]
            all_data[bi].append((key, xor_val))
        time_mod.sleep(0.12)

    print(f"\n  Period-3 analysis (block index mod 3):")
    print(f"  {'Block':>6s}  {'mod3':>4s}  {'XOR=0':>6s}  {'XOR=128':>8s}  {'Total':>6s}  {'Flip%':>6s}")
    for bi in range(min(30, max(all_data.keys()) + 1)):
        if bi not in all_data:
            continue
        data = all_data[bi]
        xor0 = sum(1 for _, x in data if x == 0)
        xor128 = sum(1 for _, x in data if x == 128)
        total = len(data)
        flip_pct = 100 * xor128 / total if total > 0 else 0
        mod3 = bi % 3
        marker = " <<<" if mod3 == 0 else ""
        print(f"  {bi:6d}  {mod3:4d}  {xor0:6d}  {xor128:8d}  {total:6d}  {flip_pct:5.1f}%{marker}")

    # =========================================================================
    print(f"\n{'=' * 80}")
    print("TEST 2: PERIOD-3 AT DIFFERENT DIMENSIONS")
    print("=" * 80)

    for dim in [2, 4, 8, 10]:
        print(f"\n  dim={dim}:")
        dim_data = defaultdict(list)
        for ki in range(15):
            key = f"pd_{ki:03d}"
            s = get_stream(key, 280, dimensions=dim)
            if not s:
                continue
            blocks = get_blocks(s)
            for bi, block in enumerate(blocks):
                xor_val = block[11] ^ block[12]
                dim_data[bi].append(xor_val)
            time_mod.sleep(0.15)

        print(f"  {'Block':>6s}  {'mod3':>4s}  {'XOR=0':>6s}  {'XOR=128':>8s}  {'Flip%':>6s}")
        for bi in range(min(15, max(dim_data.keys()) + 1)):
            if bi not in dim_data:
                continue
            data = dim_data[bi]
            xor0 = sum(1 for x in data if x == 0)
            xor128 = sum(1 for x in data if x == 128)
            total = len(data)
            flip_pct = 100 * xor128 / total if total > 0 else 0
            mod3 = bi % 3
            print(f"  {bi:6d}  {mod3:4d}  {xor0:6d}  {xor128:8d}  {flip_pct:5.1f}%")

    # =========================================================================
    print(f"\n{'=' * 80}")
    print("TEST 3: ARE THERE OTHER POSITIONS WITH PERIOD-3 PATTERNS?")
    print("=" * 80)

    # Check every byte position for block-index-dependent behavior
    print(f"\n  Using 50-key dim=2 data, checking each position for mod-3 patterns:")

    # Rebuild full block data
    all_blocks = defaultdict(list)  # bi -> list of blocks
    for ki in range(50):
        key = f"p3_{ki:03d}"
        s = get_stream(key, 420, dimensions=2)
        if not s:
            continue
        blocks = get_blocks(s)
        for bi, block in enumerate(blocks):
            all_blocks[bi].append(block)
        time_mod.sleep(0.12)

    # For each position, check if any byte value or bit has a mod-3 pattern
    print(f"\n  Positions where mod-3 block index affects byte[pos] XOR byte[pos+k]:")
    for p1 in range(13):
        for p2 in range(p1+1, 14):
            # For each mod-3 class, compute percentage of XOR=0
            results = {}
            for mod3 in range(3):
                total = 0
                zero_count = 0
                for bi in range(30):
                    if bi % 3 != mod3 or bi not in all_blocks:
                        continue
                    for block in all_blocks[bi]:
                        total += 1
                        if block[p1] == block[p2]:
                            zero_count += 1
                results[mod3] = (zero_count, total)

            # Check if there's a significant difference between mod-3 classes
            pcts = []
            for mod3 in range(3):
                z, t = results[mod3]
                pcts.append(100 * z / t if t > 0 else 0)

            # Only show if there's a strong mod-3 dependency
            if max(pcts) - min(pcts) > 20:
                part1 = f"Re[{p1}]" if p1 < 7 else f"Im[{p1-7}]"
                part2 = f"Re[{p2}]" if p2 < 7 else f"Im[{p2-7}]"
                print(f"    ({p1:2d},{p2:2d}) {part1:>6s}={part2:>6s}: "
                      f"mod0={pcts[0]:.0f}%  mod1={pcts[1]:.0f}%  mod2={pcts[2]:.0f}%")

    # Also check for XOR=128 patterns
    print(f"\n  Positions where mod-3 affects XOR ∈ {{0, 128}} ratio:")
    for p1 in range(13):
        for p2 in range(p1+1, 14):
            results = {}
            for mod3 in range(3):
                total = 0
                xor_0_or_128 = 0
                for bi in range(30):
                    if bi % 3 != mod3 or bi not in all_blocks:
                        continue
                    for block in all_blocks[bi]:
                        total += 1
                        xor_val = block[p1] ^ block[p2]
                        if xor_val in (0, 128):
                            xor_0_or_128 += 1
                results[mod3] = (xor_0_or_128, total)

            pcts = []
            for mod3 in range(3):
                z, t = results[mod3]
                pcts.append(100 * z / t if t > 0 else 0)

            if min(pcts) > 80:  # Strong XOR ∈ {0, 128} pattern
                if not (p1 == 11 and p2 == 12):  # Skip known pair
                    part1 = f"Re[{p1}]" if p1 < 7 else f"Im[{p1-7}]"
                    part2 = f"Re[{p2}]" if p2 < 7 else f"Im[{p2-7}]"
                    print(f"    ({p1:2d},{p2:2d}) {part1:>6s}^{part2:>6s} ∈ {{0,128}}: "
                          f"mod0={pcts[0]:.0f}%  mod1={pcts[1]:.0f}%  mod2={pcts[2]:.0f}%")

    # =========================================================================
    print(f"\n{'=' * 80}")
    print("TEST 4: AT BLOCKS 0 MOD 3, WHAT OTHER PATTERNS HOLD?")
    print("=" * 80)

    # At blocks 0 mod 3, Im[4]==Im[5] is guaranteed. What else is special?
    print("\n  Block 0 mod 3 vs blocks 1,2 mod 3 — byte-level differences:")

    for pos in range(14):
        vals_mod0 = []
        vals_mod12 = []
        for bi in range(30):
            if bi not in all_blocks:
                continue
            for block in all_blocks[bi]:
                if bi % 3 == 0:
                    vals_mod0.append(block[pos])
                else:
                    vals_mod12.append(block[pos])

        mean_0 = sum(vals_mod0) / len(vals_mod0) if vals_mod0 else 0
        mean_12 = sum(vals_mod12) / len(vals_mod12) if vals_mod12 else 0
        std_0 = (sum((v - mean_0)**2 for v in vals_mod0) / len(vals_mod0))**0.5 if vals_mod0 else 0
        std_12 = (sum((v - mean_12)**2 for v in vals_mod12) / len(vals_mod12))**0.5 if vals_mod12 else 0

        part = f"Re[{pos}]" if pos < 7 else f"Im[{pos-7}]"
        diff = abs(mean_0 - mean_12)
        marker = " <<<" if diff > 20 else ""
        print(f"  pos={pos:2d} ({part:>6s}): "
              f"mean_mod0={mean_0:6.1f}(±{std_0:.1f})  "
              f"mean_other={mean_12:6.1f}(±{std_12:.1f})  "
              f"Δ={diff:.1f}{marker}")

    # =========================================================================
    print(f"\n{'=' * 80}")
    print("TEST 5: BIT-LEVEL PERIOD-3 ANALYSIS")
    print("=" * 80)

    # Check each bit of each byte for period-3 pattern
    print("\n  Bit bias by mod-3 class (showing only biased bits):")
    for pos in range(14):
        for bit in range(8):
            biases = {}
            for mod3 in range(3):
                total = 0
                ones = 0
                for bi in range(30):
                    if bi % 3 != mod3 or bi not in all_blocks:
                        continue
                    for block in all_blocks[bi]:
                        total += 1
                        if block[pos] & (1 << (7 - bit)):
                            ones += 1
                biases[mod3] = ones / total if total > 0 else 0.5

            # Check if bias differs significantly by mod-3
            max_diff = max(biases.values()) - min(biases.values())
            if max_diff > 0.15:
                part = f"Re[{pos}]" if pos < 7 else f"Im[{pos-7}]"
                print(f"    {part:>6s}.bit{bit}: "
                      f"mod0={biases[0]:.3f}  mod1={biases[1]:.3f}  mod2={biases[2]:.3f}  "
                      f"Δ={max_diff:.3f}")

    # =========================================================================
    print(f"\n{'=' * 80}")
    print("TEST 6: IS THE PERIOD REALLY 3, OR SOMETHING ELSE?")
    print("=" * 80)

    # Check periods 2, 3, 4, 5, 6, 7 for the (11,12) XOR pattern
    print("\n  Checking different periods for (11,12) XOR pattern:")
    for period in [2, 3, 4, 5, 6, 7, 14]:
        print(f"\n  Period {period}:")
        for mod in range(period):
            total = 0
            flips = 0
            for bi in range(30):
                if bi % period != mod or bi not in all_blocks:
                    continue
                for block in all_blocks[bi]:
                    total += 1
                    if block[11] ^ block[12] == 128:
                        flips += 1
            pct = 100 * flips / total if total > 0 else 0
            print(f"    mod {mod}: {flips}/{total} flip ({pct:.1f}%)")

    # =========================================================================
    print(f"\n{'=' * 80}")
    print("TEST 7: DOES THE PERIOD-3 PATTERN CORRELATE WITH PHASE TRANSITIONS?")
    print("=" * 80)

    # Phase transitions happen at specific payload lengths (multiples of 28 for dim=8)
    # At dim=2, check if the period-3 pattern resets at phase boundaries

    key = "Secret99"
    # Get streams at different lengths around known transition points
    print(f"\n  Key '{key}', checking (11,12) XOR across payload lengths:")
    for length in [42, 43, 44, 70, 71, 72, 98, 99, 100]:
        s = get_stream(key, length, dimensions=2)
        if not s:
            print(f"    length={length}: no stream")
            continue
        blocks = get_blocks(s)
        xors = [b[11] ^ b[12] for b in blocks]
        print(f"    length={length:3d}: {len(blocks)} blocks  "
              f"XORs={xors[:10]}{'...' if len(xors) > 10 else ''}")
        time_mod.sleep(0.15)


if __name__ == "__main__":
    main()
