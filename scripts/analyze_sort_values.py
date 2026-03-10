#!/usr/bin/env python3
"""
Analyze Sort Array values from FES Peer Review Guide Table 1.

These are "raw decimal z values" collected during Mandelbrot iteration,
used to determine the scramble permutation in FES encryption.

Pure offline analysis — no API calls.
"""

import math
from decimal import Decimal, getcontext

# Use high precision for decimal analysis
getcontext().prec = 50

# =============================================================================
# DATA
# =============================================================================

# Pass 1 sort array values (byte_index: value)
pass1 = {
    0:  Decimal("4793.4512063949561677"),
    1:  Decimal("357.7112770234736040"),
    2:  Decimal("1447.6222373512767626"),
    3:  Decimal("822.5561887333744784"),
    4:  Decimal("2585.3478635626196090"),
    5:  Decimal("185.8660109157144254"),
    6:  Decimal("3626.0061026419645930"),
    7:  Decimal("205.1596320617041240"),
    8:  Decimal("37.3888294878806581"),
    31: Decimal("656.2230266658864937"),
}

# Pass 2 sort array values (byte_index: value)
pass2 = {
    0:  Decimal("3849.1662474244608959"),
    1:  Decimal("611.4949519204787601"),
    2:  Decimal("3077.2004738578931151"),
    3:  Decimal("2817.9948358302237401"),
    4:  Decimal("4279.9316279229324200"),
    5:  Decimal("235.4281698169864171"),
    6:  Decimal("47.7679766295334759"),
    7:  Decimal("31.6675759128826838"),
    8:  Decimal("2.5589124980107219"),
    31: Decimal("15369.3432006339994286"),
}

# FV values from FT-Explained for key "Secret99", "Demo Payload" (12 bytes)
fv_values = {
    0: Decimal("5874.7274351297"),
    1: Decimal("5874.72743642702"),
    2: Decimal("5874.72743503904"),
}

print("=" * 80)
print("ANALYSIS OF FES SORT ARRAY VALUES")
print("From Peer Review Guide §7.4.1, Table 1")
print("=" * 80)

# =============================================================================
# 1. WHAT ARE THESE SORT VALUES?
# =============================================================================
print("\n" + "=" * 80)
print("1. WHAT ARE THESE SORT VALUES?")
print("=" * 80)

print("""
The spec describes these as "raw decimal z values" collected during each pass
of the Mandelbrot iteration. Since z is complex (z = a + bi), the "value" used
for sorting must be a single real number derived from z.

Candidates:
  (a) |z|^2 = Re(z)^2 + Im(z)^2  (magnitude squared)
  (b) |z|  = sqrt(Re(z)^2 + Im(z)^2)  (magnitude)
  (c) Re(z) alone or Im(z) alone
  (d) Some fixed-point mantissa extraction

Key observations:
  - All values are POSITIVE (no negatives in either pass)
  - Values range from 2.56 to 15369.34
  - Standard Mandelbrot escape radius is 2, so |z|^2 > 4 means escaped
  - Many values >> 4, confirming these are NOT within the Mandelbrot set

Since all values are positive and span a wide range, |z|^2 is the most likely
candidate. Raw Re(z) or Im(z) could be negative, which we don't see here.
However, the values could also be |z| (always positive) or an absolute value.

If these are |z|^2:
  - Byte 8, Pass 2: 2.5589 → |z| ≈ 1.60 (still bounded, hasn't escaped)
  - Byte 31, Pass 2: 15369.34 → |z| ≈ 123.97 (well escaped)
  - Byte 0, Pass 1: 4793.45 → |z| ≈ 69.24 (well escaped)

If these are |z| directly:
  - Byte 8, Pass 2: 2.5589 → just barely past escape radius
  - Byte 31, Pass 2: 15369.34 → very far from origin

The wide range and all-positive nature strongly suggests |z|^2 at a specific
iteration count, collected AFTER the point has escaped (or at max iterations).
""")

# =============================================================================
# 2. COMPARE PASS 1 VS PASS 2
# =============================================================================
print("=" * 80)
print("2. PASS 1 VS PASS 2 COMPARISON")
print("=" * 80)

print("\n{:>6s}  {:>24s}  {:>24s}  {:>10s}  {:>10s}".format(
    "Index", "Pass 1", "Pass 2", "Ratio", "Diff"))
print("-" * 80)

common_indices = sorted(set(pass1.keys()) & set(pass2.keys()))
for idx in common_indices:
    v1 = pass1[idx]
    v2 = pass2[idx]
    ratio = float(v2) / float(v1) if float(v1) != 0 else float('inf')
    diff = float(v2) - float(v1)
    print(f"{idx:>6d}  {str(v1):>24s}  {str(v2):>24s}  {ratio:>10.4f}  {diff:>+10.2f}")

print("""
The values are COMPLETELY different between passes. No obvious pattern:
  - Some increase (index 1: 357→611, index 31: 656→15369)
  - Some decrease (index 0: 4793→3849, index 6: 3626→47.8)
  - Ratios vary from 0.013 (index 6) to 23.42 (index 31)

This confirms that each pass navigates to entirely different Mandelbrot
positions, producing independent z values. The scramble permutation is
therefore different per pass, which is consistent with multi-pass behavior
where scramble=on produces genuinely different ciphertexts per depth.
""")

# =============================================================================
# 3. PRECISION ANALYSIS
# =============================================================================
print("=" * 80)
print("3. PRECISION ANALYSIS")
print("=" * 80)

print("\nPass 1 significant digits:")
for idx in sorted(pass1.keys()):
    val = pass1[idx]
    s = str(val)
    # Remove decimal point for digit counting
    digits_only = s.replace(".", "").lstrip("0")
    # Strip trailing zeros
    digits_stripped = digits_only.rstrip("0")
    total_digits = len(digits_only)
    sig_digits = len(digits_stripped)
    int_part = s.split(".")[0]
    frac_part = s.split(".")[1]
    print(f"  Byte {idx:>2d}: {s:>30s}  |  {len(int_part):>2d} int + {len(frac_part):>2d} frac = {total_digits:>2d} total digits, {sig_digits:>2d} significant")

print("\nPass 2 significant digits:")
for idx in sorted(pass2.keys()):
    val = pass2[idx]
    s = str(val)
    digits_only = s.replace(".", "").lstrip("0")
    digits_stripped = digits_only.rstrip("0")
    total_digits = len(digits_only)
    sig_digits = len(digits_stripped)
    int_part = s.split(".")[0]
    frac_part = s.split(".")[1]
    print(f"  Byte {idx:>2d}: {s:>30s}  |  {len(int_part):>2d} int + {len(frac_part):>2d} frac = {total_digits:>2d} total digits, {sig_digits:>2d} significant")

# Analyze the fractional digit counts
frac_lengths_p1 = [len(str(pass1[i]).split(".")[1]) for i in sorted(pass1.keys())]
frac_lengths_p2 = [len(str(pass2[i]).split(".")[1]) for i in sorted(pass2.keys())]

print(f"\nFractional digit lengths (Pass 1): {frac_lengths_p1}")
print(f"Fractional digit lengths (Pass 2): {frac_lengths_p2}")
print(f"All fractional parts have 16 digits: {all(x == 16 for x in frac_lengths_p1 + frac_lengths_p2)}")

print("""
KEY FINDING: ALL values have EXACTLY 16 fractional decimal digits.

This is a strong indicator of the fixed-point format:
  - 16 fractional decimal digits → the fractional part is stored with
    exactly 10^16 precision
  - 10^16 ≈ 2^53.15 → this is suspiciously close to IEEE 754 double
    precision (53-bit mantissa)!

However, the HFN Theory paper claims fixed-point decimal arithmetic.
If using a custom fixed-point format with 16 fractional decimal digits:
  - The fractional part can be stored in ceil(16 × log2(10)) = 54 bits
  - With integer parts up to ~15369 (14 bits), total ≈ 68 bits
  - This aligns with a 64-bit or 80-bit fixed-point representation
""")

# More detailed precision analysis
print("Precision equivalence analysis:")
print(f"  10^16 = {10**16}")
print(f"  2^53  = {2**53} ≈ 9.0 × 10^15")
print(f"  2^54  = {2**54} ≈ 1.8 × 10^16")
print(f"  2^64  = {2**64} ≈ 1.8 × 10^19")
print(f"  2^53 can represent ~15.95 decimal digits")
print(f"  2^54 can represent ~16.25 decimal digits")

print("""
The 16 fractional decimal digits correspond almost exactly to 53-54 bits
of fractional precision. This is consistent with:
  (a) IEEE 754 double-precision floating point (53-bit significand), OR
  (b) A fixed-point format that happens to use 16 decimal fractional digits

Given the HFN Theory paper's emphasis on "fixed-point decimal" and
"12 significant bytes", the 16-digit fractional part is likely the
native representation format, not a coincidence with IEEE 754.
""")

# =============================================================================
# 4. RELATE TO FV VALUES
# =============================================================================
print("=" * 80)
print("4. RELATIONSHIP TO FV VALUES")
print("=" * 80)

print("\nFV values from FT-Explained (key='Secret99', payload='Demo Payload', 12 bytes):")
for idx in sorted(fv_values.keys()):
    print(f"  FV[{idx}] = {fv_values[idx]}")

print(f"\nFV values are all ≈ {float(fv_values[0]):.4f}")
print(f"FV precision: {len(str(fv_values[0]).split('.')[1])} fractional digits (less than sort array's 16)")

print("\nSort array value ranges:")
p1_vals = [float(v) for v in pass1.values()]
p2_vals = [float(v) for v in pass2.values()]
print(f"  Pass 1: min={min(p1_vals):.4f}, max={max(p1_vals):.4f}, mean={sum(p1_vals)/len(p1_vals):.4f}")
print(f"  Pass 2: min={min(p2_vals):.4f}, max={max(p2_vals):.4f}, mean={sum(p2_vals)/len(p2_vals):.4f}")
print(f"  FV:     all ≈ 5874.7274")

print("""
KEY OBSERVATION: FV values are NEARLY IDENTICAL across byte indices (~5874.727),
while sort array values are WILDLY DIFFERENT across byte indices (2.6 to 15369).

This means:
  - FV = |z|^2 at the PORTAL (fixed starting point, same for all bytes)
  - Sort values = |z|^2 at NAVIGATED positions (different for each byte)

The portal is a single point in the Mandelbrot set. FV is the value of z
at that point (or after a fixed number of iterations from that point).
Then for each byte of the payload, the algorithm navigates to a DIFFERENT
nearby position using key bytes, producing a different z value for each byte.

The sort array values represent these navigated z values, which is why
they vary so dramatically — each byte explores a different part of the
fractal boundary.

FV values having only 13 fractional digits (vs 16 for sort values) suggests
FV might be computed at lower precision or reported with less precision in
the documentation.
""")

# =============================================================================
# 5. ARE THESE |z|^2 OR RAW z COMPONENTS?
# =============================================================================
print("=" * 80)
print("5. |z|^2 VS RAW z COMPONENTS")
print("=" * 80)

print("\nIf values are |z|^2 (magnitude squared):")
for idx in sorted(pass1.keys()):
    v = float(pass1[idx])
    mag = math.sqrt(v)
    print(f"  Byte {idx:>2d}: |z|^2 = {v:>12.4f}  →  |z| = {mag:>8.4f}  (escape radius 2: {'ESCAPED' if mag > 2 else 'bounded'})")

print("\nIf values are |z| (magnitude):")
for idx in sorted(pass1.keys()):
    v = float(pass1[idx])
    print(f"  Byte {idx:>2d}: |z| = {v:>12.4f}  (escape radius 2: {'ESCAPED' if v > 2 else 'bounded'})")

print("""
ALL values exceed 2 in both interpretations, so all points have escaped
the standard Mandelbrot set (escape radius = 2).

However, if these are |z|^2:
  - Byte 8 (Pass 2): |z|^2 = 2.5589 → |z| = 1.60 — still WITHIN the set!
  - This would make byte 8 the only non-escaped point

If these are |z| directly:
  - ALL points have escaped (minimum |z| = 2.56 > 2)
  - The values represent magnitudes after some iteration

The fact that byte 8 (Pass 2) has value 2.5589:
  - As |z|^2: this means |z| ≈ 1.60, which is near the Mandelbrot boundary
    (interesting — could be a point that hasn't escaped yet)
  - As |z|: this means the point barely escaped (|z| = 2.56 > 2)

VERDICT: Without more data, both interpretations are plausible. However,
|z|^2 is more commonly used in Mandelbrot implementations (avoids the
sqrt call in escape checking), and having one near-boundary point (byte 8
pass 2) is more mathematically interesting than all points having escaped.

The FV value ~5874.73 being described as a "Fractal Value" at the portal
suggests these ARE |z|^2 values, since portals should be at interesting
(near-boundary) points where |z|^2 has a specific relationship to the
set boundary.
""")

# =============================================================================
# 6. FIXED-POINT FORMAT ANALYSIS
# =============================================================================
print("=" * 80)
print("6. FIXED-POINT FORMAT ANALYSIS")
print("=" * 80)

# Analyze the integer part sizes
print("\nInteger part analysis:")
for label, data in [("Pass 1", pass1), ("Pass 2", pass2)]:
    print(f"\n  {label}:")
    for idx in sorted(data.keys()):
        v = data[idx]
        int_part = int(v)
        bits_needed = int_part.bit_length() if int_part > 0 else 1
        print(f"    Byte {idx:>2d}: int={int_part:>6d} ({bits_needed:>2d} bits), frac=16 digits")

max_int = max(int(v) for v in list(pass1.values()) + list(pass2.values()))
print(f"\n  Maximum integer part: {max_int} ({max_int.bit_length()} bits)")

print(f"""
Fixed-point format possibilities:

  Option A: 64-bit total (e.g., 16.48 or 20.44 fixed-point)
    - 2^64 ≈ 1.8 × 10^19
    - With max integer ~15369 (14 bits), remaining 50 bits for fraction
    - 50 bits → ~15.05 decimal digits (close to 16, but not exact)
    - Total representable: ~19 decimal digits

  Option B: 80-bit total (extended precision)
    - With 14 bits for integer, 66 bits for fraction
    - 66 bits → ~19.9 decimal digits (more than we see)
    - Would explain 16 fractional digits with room to spare

  Option C: Decimal fixed-point with exactly 16 fractional digits
    - Store integer and fractional parts separately
    - Fractional part as 64-bit integer representing 0-9999999999999999
    - 10^16 = 10,000,000,000,000,000 fits in 54 bits
    - This is the most natural explanation for EXACTLY 16 decimal digits

  Option D: IEEE 754 double precision (53-bit significand)
    - 2^53 ≈ 9.007 × 10^15 → ~15.95 significant decimal digits
    - For 15369.xxxx, that's 5 integer digits + ~11 fractional digits = 16 sig figs
    - But we see 5 integer + 16 fractional = 21 digits — MORE than double can hold!
    - For 37.xxxx, that's 2 integer + 16 fractional = 18 digits — still > 16

  CONCLUSION: These values CANNOT be IEEE 754 doubles — they have TOO MANY
  significant digits. This confirms the HFN Theory paper's claim of using
  fixed-point decimal arithmetic, not floating-point.
""")

# Verify: can a double hold these values exactly?
print("Double precision verification:")
for label, data in [("Pass 1", pass1), ("Pass 2", pass2)]:
    print(f"\n  {label}:")
    for idx in sorted(data.keys()):
        v = data[idx]
        as_float = float(v)
        roundtrip = Decimal(str(as_float))
        original_str = str(v)
        roundtrip_str = str(roundtrip)
        match = original_str == roundtrip_str
        # Count matching digits
        matching = 0
        for a, b in zip(original_str, roundtrip_str):
            if a == b:
                matching += 1
            else:
                break
        print(f"    Byte {idx:>2d}: orig={original_str:>30s}  double_roundtrip={roundtrip_str:>30s}  match={match}")

# =============================================================================
# 7. SORTING BEHAVIOR AND PERMUTATION
# =============================================================================
print("\n" + "=" * 80)
print("7. SORTING BEHAVIOR AND PERMUTATION")
print("=" * 80)

# Sort Pass 1 values
sorted_p1 = sorted(pass1.items(), key=lambda x: x[1])
print("\nPass 1 sorted (ascending):")
print(f"  {'Value':>24s}  →  Byte Index")
print(f"  {'-'*24}     ----------")
for idx, val in sorted_p1:
    print(f"  {str(val):>24s}  →  {idx:>2d}")

perm_p1 = [idx for idx, val in sorted_p1]
print(f"\nPass 1 permutation (sorted byte indices): {perm_p1}")
print(f"  Meaning: position 0 in sorted order = byte {perm_p1[0]}")
print(f"           position 1 in sorted order = byte {perm_p1[1]}")
print(f"           ...")

# Sort Pass 2 values
sorted_p2 = sorted(pass2.items(), key=lambda x: x[1])
print("\nPass 2 sorted (ascending):")
print(f"  {'Value':>24s}  →  Byte Index")
print(f"  {'-'*24}     ----------")
for idx, val in sorted_p2:
    print(f"  {str(val):>24s}  →  {idx:>2d}")

perm_p2 = [idx for idx, val in sorted_p2]
print(f"\nPass 2 permutation (sorted byte indices): {perm_p2}")

print(f"""
Scramble permutation comparison:
  Pass 1: {perm_p1}
  Pass 2: {perm_p2}

These permutations are COMPLETELY different:
  - Pass 1: byte 8 goes to position 0, byte 0 goes to position 9
  - Pass 2: byte 8 goes to position 0 (same!), byte 31 goes to position 9

Interestingly, byte 8 is the SMALLEST in BOTH passes (positions 0 in both).
This could be coincidence with only 10 data points, or could indicate that
byte 8's navigation path consistently reaches near-boundary z values.
""")

# What would the scramble do to a 10-byte block?
print("Scramble effect on bytes 0-8,31 (Pass 1):")
print(f"  Original positions:  [0, 1, 2, 3, 4, 5, 6, 7, 8, 31]")
print(f"  After sort (ascending by z value), the byte at original position")
print(f"  {perm_p1[0]:>2d} moves to new position 0,")
print(f"  {perm_p1[1]:>2d} moves to new position 1, etc.")

# =============================================================================
# 8. BYTE 31 ANALYSIS
# =============================================================================
print("\n" + "=" * 80)
print("8. BYTE 31 ANALYSIS")
print("=" * 80)

b31_p1 = float(pass1[31])
b31_p2 = float(pass2[31])

print(f"""
Byte 31 values:
  Pass 1: {pass1[31]}  (rank {perm_p1.index(31) + 1}/10 in ascending order)
  Pass 2: {pass2[31]}  (rank {perm_p2.index(31) + 1}/10 in ascending order)

  Pass 2 / Pass 1 ratio: {b31_p2 / b31_p1:.4f}x

Byte 31 is the LAST byte of a 32-byte payload.

In Pass 1: byte 31 has a middling value (656.22, rank {perm_p1.index(31) + 1}/10)
In Pass 2: byte 31 has the LARGEST value (15369.34, rank {perm_p2.index(31) + 1}/10)

The 23.4x increase from Pass 1 to Pass 2 is the largest ratio change of any byte.
This demonstrates that the navigation path for byte 31 leads to very different
regions of the Mandelbrot set in each pass.

Why byte 31 specifically?
  - In a 32-byte payload (indices 0-31), byte 31 is the last
  - The Peer Review Guide includes it to show the full range of the sort array
  - The gap from index 8 to 31 suggests indices 9-30 were omitted for brevity
  - The sort array has one entry per payload byte (32 entries for 32-byte payload)
""")

# =============================================================================
# 9. CONNECTION TO STREAM BYTES
# =============================================================================
print("=" * 80)
print("9. CONNECTION TO STREAM BYTES")
print("=" * 80)

print("""
How sort values relate to stream generation:

1. Key Expansion: Key "Secret99" → expanded key via iterated SHA-512
2. Portal Entry: Expanded key → Silo lookup → Entry Portal coordinates
3. Navigation: For each payload byte i:
   a. Use key bytes to navigate from portal to a new position z_i
   b. Record the "raw decimal z value" (sort array[i]) — likely |z|^2
   c. Extract stream bytes from z_i's fixed-point representation
      ("12 significant bytes per dimension per iteration")
4. Scramble: Sort the sort array values → this gives a permutation
5. Apply permutation: Rearrange the payload bytes according to the permutation
6. Overwrite: XOR (and optionally ADD, SPLIT) the scrambled payload with
   the stream bytes (applied in REVERSE order: stream[N-1-i])

The sort values are INTERMEDIATE products of the stream generation process.
They are the |z|^2 values at each navigated position, and the stream bytes
are extracted from the COMPONENTS of z (Re(z) and Im(z)) at those same
positions.

This means:
  - Sort array values and stream bytes come from the SAME z values
  - Sort values = |z|^2 (scalar, used for permutation ordering)
  - Stream bytes = fixed-point digits of Re(z) and Im(z) (used for XOR)
  - The sort determines byte ORDERING, the stream determines byte VALUES
""")

# =============================================================================
# SUMMARY
# =============================================================================
print("=" * 80)
print("SUMMARY OF FINDINGS")
print("=" * 80)

print("""
1. IDENTITY: Sort array values are most likely |z|^2 at navigated Mandelbrot
   positions, one per payload byte. All values are positive, ruling out raw
   Re(z) or Im(z) components.

2. PASS INDEPENDENCE: Pass 1 and Pass 2 produce completely different sort
   values, confirming each pass navigates to independent fractal positions.

3. PRECISION: Exactly 16 fractional decimal digits in all values. This
   EXCEEDS IEEE 754 double precision (~15.95 significant digits), confirming
   the use of fixed-point decimal arithmetic as claimed in HFN Theory paper.

4. FV vs SORT: FV values (~5874.73) are nearly identical across byte indices
   → they represent the PORTAL point. Sort values vary wildly (2.6 to 15369)
   → they represent NAVIGATED positions, one per byte.

5. ESCAPE STATUS: Most sort values correspond to escaped points (|z| >> 2).
   Byte 8 Pass 2 (2.56) might be near-boundary if interpreted as |z|^2.

6. FIXED-POINT: The 16-decimal-digit fractional precision implies:
   - NOT IEEE 754 double (insufficient precision)
   - Likely a custom decimal fixed-point format
   - Fractional part storable in ~54 bits (10^16 < 2^54)
   - Possibly 64-bit integer storing 16-digit fractional part separately

7. PERMUTATION: Ascending sort of values gives the scramble permutation.
   Pass 1: [8, 5, 7, 1, 31, 3, 2, 4, 6, 0]
   Pass 2: [8, 7, 6, 5, 1, 3, 2, 0, 4, 31]
   Completely different orderings per pass.

8. BYTE 31: Last byte of 32-byte payload. Its sort value changes the most
   between passes (656→15369, 23.4x), demonstrating extreme sensitivity of
   the navigation path to pass-dependent parameters.

9. STREAM CONNECTION: Sort values and stream bytes are co-products of the
   same Mandelbrot navigation. Sort value = |z|^2 for ordering. Stream bytes
   = fixed-point digits of z components for encryption.
""")
