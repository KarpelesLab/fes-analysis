"""
Analyze the fixed-point arithmetic format used by FES.

From the Peer Review Guide §7.4.1, we have Sort Array values with full decimal precision.
From FT-Explained, we have FV values with 13 significant digits.
The HFN Theory paper says: "strictly decimal (or integer) arithmetic, not floating-point"
and "each dimension contributes 112 bits to the key space" (= 14 bytes per dimension).

This script analyzes these values to determine:
1. The fixed-point format (total bits, decimal places, scale factor)
2. Whether values are |z|², Re(z), Im(z), or something else
3. The relationship between Sort Array values and stream bytes
"""

from decimal import Decimal, getcontext
import math

getcontext().prec = 50

# Peer Review Guide §7.4.1 Sort Array values (raw decimal z values)
SORT_PASS1 = {
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

SORT_PASS2 = {
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

# FT-Explained FV values (|z|² at portal)
FV_VALUES = [
    Decimal("5874.7274351297"),
    Decimal("5874.72743642702"),
    Decimal("5874.72743503904"),
    Decimal("5874.72743541918"),
    Decimal("5874.72743509044"),
    Decimal("5874.72743397111"),
    Decimal("5874.72743567349"),
    Decimal("5874.72743554848"),
    Decimal("5874.72743509473"),
    Decimal("5874.72743537211"),
    Decimal("5874.72743620258"),
    Decimal("5874.72743485877"),
]

# Known stream bytes for Secret99 (dim=8)
STREAM = [215, 27, 210, 179, 226, 199, 7, 46, 14, 223, 201, 97]


def analyze_precision():
    print("=" * 80)
    print("1. PRECISION ANALYSIS OF SORT ARRAY VALUES")
    print("=" * 80)

    for label, values in [("Pass 1", SORT_PASS1), ("Pass 2", SORT_PASS2)]:
        print(f"\n  {label}:")
        for idx in sorted(values.keys()):
            val = values[idx]
            s = str(val)
            parts = s.split('.')
            int_digits = len(parts[0])
            frac_digits = len(parts[1]) if len(parts) > 1 else 0
            total = int_digits + frac_digits
            # Remove trailing zeros to find significant digits
            sig = s.replace('.', '').lstrip('0').rstrip('0')
            sig_digits = len(sig) if sig else 0
            print(f"    Byte {idx:2d}: {s:>30s}  int={int_digits}  "
                  f"frac={frac_digits}  total={total}  sig={sig_digits}")

    print("\n  Summary:")
    all_frac = []
    for values in [SORT_PASS1, SORT_PASS2]:
        for val in values.values():
            s = str(val)
            if '.' in s:
                frac = s.split('.')[1]
                all_frac.append(len(frac))
    print(f"    Fractional digits: min={min(all_frac)}, max={max(all_frac)}, "
          f"mode={max(set(all_frac), key=all_frac.count)}")

    # Check total significant digits
    all_total = []
    for values in [SORT_PASS1, SORT_PASS2]:
        for val in values.values():
            s = str(val).replace('.', '').lstrip('0')
            all_total.append(len(s))
    print(f"    Total digits (excl leading zeros): min={min(all_total)}, max={max(all_total)}")


def analyze_fixed_point_format():
    print(f"\n{'=' * 80}")
    print("2. FIXED-POINT FORMAT HYPOTHESIS")
    print("=" * 80)

    # All sort values have exactly 16 fractional digits
    # This is consistent with a 64-bit integer representation where
    # the value = integer_value / 10^16
    # Max value in data: 15369.3432... → integer = 153693432006339994286
    # That's about 2^67 — too big for 64-bit

    # Or maybe the fractional part is SEPARATE from the integer part
    # Integer part stored separately (up to ~16 bits), fraction as 64-bit

    print("\n  Testing: value = integer_part + fractional_part / 10^16")
    for idx in sorted(SORT_PASS1.keys()):
        val = SORT_PASS1[idx]
        int_part = int(val)
        frac_part = val - int_part
        frac_as_int = int(frac_part * 10**16)
        # How many bits for the fractional integer?
        bits = frac_as_int.bit_length() if frac_as_int > 0 else 0
        print(f"    Byte {idx:2d}: int={int_part:6d}  frac_int={frac_as_int:>20d}  "
              f"bits={bits:2d}")

    # Check if this is |z|² (zx² + zy²) or something else
    print("\n  Value range analysis:")
    all_vals = list(SORT_PASS1.values()) + list(SORT_PASS2.values())
    print(f"    Min: {min(all_vals)}")
    print(f"    Max: {max(all_vals)}")
    print(f"    Mean: {sum(all_vals)/len(all_vals)}")
    print(f"    FV reference: {FV_VALUES[0]}")
    print(f"    If |z|² with escape radius 2: max would be ~4")
    print(f"    If |z|² at escaped points: values can be huge")
    print(f"    These values (2.5 to 15369) suggest these are |z|² at")
    print(f"    navigated points that may or may not have escaped")


def analyze_byte_extraction():
    print(f"\n{'=' * 80}")
    print("3. STREAM BYTE FROM SORT ARRAY VALUES — HYPOTHESIS TESTING")
    print("=" * 80)

    # The FT-Explained FV values are all ~5874.727, but stream bytes are diverse
    # The Sort Array values (from PRG) range from 2.5 to 15369
    # These are from a DIFFERENT key/config than Secret99

    # But let's check: for FT-Explained FV values, can we find a consistent
    # extraction that gives the known stream bytes?

    print("\n  FT-Explained FV values → stream byte extraction attempts:")
    for i in range(12):
        fv = FV_VALUES[i]
        target = STREAM[i]
        s = str(fv)
        parts = s.split('.')
        int_part = int(parts[0])
        frac = parts[1] if len(parts) > 1 else "0"

        # Method 1: first N fractional digits mod 256
        methods = {}
        for n in range(1, 15):
            if len(frac) >= n:
                val = int(frac[:n]) % 256
                methods[f"frac[:{n}]%256"] = val

        # Method 2: int(FV * 10^k) mod 256
        for k in range(0, 10):
            val = int(fv * Decimal(10)**k) % 256
            methods[f"int(FV*10^{k})%256"] = val

        # Method 3: specific digit groups
        if len(frac) >= 6:
            # bytes from pairs of digits
            for start in range(0, 12, 2):
                if start + 2 <= len(frac):
                    val = int(frac[start:start+2])
                    methods[f"frac[{start}:{start+2}]"] = val

        # Find matches
        matches = {k: v for k, v in methods.items() if v == target}
        if i < 4 or matches:
            print(f"\n    Byte {i}: target={target}")
            if matches:
                for k, v in matches.items():
                    print(f"      ✓ {k} = {v}")
            else:
                # Show closest
                closest = min(methods.items(), key=lambda x: abs(x[1] - target))
                print(f"      No match. Closest: {closest[0]} = {closest[1]} "
                      f"(diff={abs(closest[1]-target)})")


def analyze_mandelbrot_computation():
    print(f"\n{'=' * 80}")
    print("4. MANDELBROT |z|² AT SECRET99 PORTAL — PRECISION ANALYSIS")
    print("=" * 80)

    getcontext().prec = 100
    cx = Decimal("-2.08907476180957704082504287877")
    cy = Decimal("-0.08680597208354758390593279988")

    zx, zy = Decimal(0), Decimal(0)
    for i in range(1, 20):
        xt = zx * zy
        zx_new = zx * zx - zy * zy + cx
        zy_new = 2 * xt + cy
        zx, zy = zx_new, zy_new
        fv = zx * zx + zy * zy

        if fv > 10000:
            # Check what zx and zy look like as fixed-point
            print(f"\n  Iteration {i} (ESCAPED): |z|² = {str(fv)[:50]}")
            print(f"    zx = {str(zx)[:50]}")
            print(f"    zy = {str(zy)[:50]}")
            print(f"    zx as fixed-point mantissa: ", end="")
            zx_s = str(abs(zx))
            if '.' in zx_s:
                frac = zx_s.split('.')[1]
                print(f"{frac[:20]}...")
                # What if stream bytes come from the mantissa digits?
                for g in [2, 3, 4]:
                    val = int(frac[:g]) % 256
                    match = " ✓" if val == STREAM[0] else ""
                    print(f"      frac[:{g}] mod 256 = {val}{match}")
            break

        print(f"  Iteration {i}: |z|² = {str(fv)[:40]}, "
              f"zx = {str(zx)[:30]}, zy = {str(zy)[:30]}")


def analyze_sort_vs_mandelbrot():
    print(f"\n{'=' * 80}")
    print("5. SORT ARRAY VALUES — ARE THEY |z|² OR RAW z COMPONENTS?")
    print("=" * 80)

    # If value = |z|² = zx² + zy², and the Mandelbrot set boundary is |z| ≤ 2,
    # then inside the set: |z|² ≤ 4
    # Escaped points: |z|² can be very large

    # Sort values range: 2.56 to 15369
    # ALL are > 4, meaning ALL points have escaped!
    # This makes sense: the portal is chosen NEAR the boundary,
    # and navigation moves it slightly, likely causing escape

    all_pass1 = list(SORT_PASS1.values())
    all_pass2 = list(SORT_PASS2.values())

    print(f"\n  Pass 1: min={min(all_pass1)}, max={max(all_pass1)}")
    print(f"  Pass 2: min={min(all_pass2)}, max={max(all_pass2)}")
    print(f"  All values > 4: {all(v > 4 for v in all_pass1 + all_pass2)}")
    print(f"  → ALL navigated points have escaped the Mandelbrot set boundary")

    # Alternatively, sort values might be sqrt(|z|²) = |z|
    # Or they might be the iteration count or some other metric
    # Let's check: is there a consistent iteration depth at which |z|² matches?

    print(f"\n  Testing if sort values are |z|² at specific iterations:")
    print(f"  (Using Secret99 portal as reference)")

    getcontext().prec = 100
    cx = Decimal("-2.08907476180957704082504287877")
    cy = Decimal("-0.08680597208354758390593279988")

    zx, zy = Decimal(0), Decimal(0)
    for i in range(1, 20):
        xt = zx * zy
        zx_new = zx * zx - zy * zy + cx
        zy_new = 2 * xt + cy
        zx, zy = zx_new, zy_new
        fv = zx * zx + zy * zy
        if fv > 100000:
            break
        print(f"    iter {i:2d}: |z|² = {str(fv)[:25]:>25s}")

    # The FT-Explained FV ≈ 5874.727 for all 12 bytes
    # Sort values for byte 0: Pass1=4793.45, Pass2=3849.17
    # These are DIFFERENT from 5874 — they must be at DIFFERENT positions
    # (since each byte navigates to a unique position)

    print(f"\n  FT-Explained FV[all] ≈ 5874.727 (same portal, all bytes)")
    print(f"  Sort Pass1[0] = {SORT_PASS1[0]} ← different portal position")
    print(f"  Sort Pass2[0] = {SORT_PASS2[0]} ← yet another position")
    print(f"  → Sort values are from NAVIGATED positions, not the original portal")


def analyze_fixed_point_binary():
    print(f"\n{'=' * 80}")
    print("6. FIXED-POINT BINARY REPRESENTATION")
    print("=" * 80)

    # HFN Theory Appendix B says:
    # 1. Interpret Re(z) and Im(z) as signed fixed-point integers
    # 2. Concatenate their binary encodings
    # 3. Apply mixing function
    # 4. Take first b bits

    # If each coordinate is stored as a 56-bit fixed-point integer
    # (7 bytes, matching "14 hex bytes" / 2 because hex bytes = 4 bits each,
    #  so 14 hex chars = 7 bytes = 56 bits)
    # Then Re + Im = 112 bits = 14 bytes per dimension pair
    # After mixing, take first 12 bytes (96 bits) → 12 significant bytes ✓

    # Wait: "14 hex bytes" in the spec context means 14 bytes represented
    # as hex (28 hex chars). So 14 bytes = 112 bits per offset.
    # Each pair: 4 bytes (index) + 14 bytes (x offset) + 14 bytes (y offset) = 32 bytes
    # That's 256 bits per pair, 1024 bits for dim=8 (4 pairs)

    # But "each dimension contributes 112 bits" from HFN §7.5
    # This likely means: per dimension (half a pair), 112 bits = 14 bytes
    # A dimension pair has 2 × 112 = 224 bits of coordinate precision

    print("\n  Hypothesis: fixed-point representation")
    print("    Per coordinate: 14 bytes = 112 bits")
    print("    Per pair (Re + Im): 28 bytes = 224 bits")
    print("    Extraction per pair per iteration: 12 bytes = 96 bits")
    print("    → 96/224 = ~43% of coordinate precision extracted per iteration")

    # Test: what fixed-point scale would give Sort Array value range?
    # 4793.4512... with 16 fractional digits
    # If fixed-point with 16 decimal places: value = int_repr / 10^16
    # 4793.4512063949561677 → 47934512063949561677
    # That's about 2^65.4 — needs at least 66 bits

    print("\n  Fixed-point scale analysis:")
    for idx in [0, 5, 8, 31]:
        for values, label in [(SORT_PASS1, "P1"), (SORT_PASS2, "P2")]:
            if idx in values:
                val = values[idx]
                # Convert to integer with 16 decimal places
                int_repr = int(val * 10**16)
                bits = int_repr.bit_length()
                print(f"    {label} Byte {idx:2d}: {val} → int={int_repr} "
                      f"({bits} bits)")


def analyze_byte_extraction_from_binary():
    print(f"\n{'=' * 80}")
    print("7. BYTE EXTRACTION FROM FIXED-POINT BINARY ENCODING")
    print("=" * 80)

    # For Secret99, FV ≈ 5874.7274351297 for byte 0
    # If |z|² = 5874.7274351297, then in fixed-point with 16 decimal places:
    # 58747274351297 (13 digits) → but we need to know exact precision

    # Let's try: take the FV as a fixed-point number and extract bytes
    # from its binary representation

    getcontext().prec = 50

    print("\n  Testing byte extraction from FV binary representation:")
    for i in range(min(3, len(FV_VALUES))):
        fv = FV_VALUES[i]
        target = STREAM[i]
        print(f"\n    FV[{i}] = {fv}, target stream byte = {target}")

        # Convert to integer representation (scale by 10^13 to get all digits)
        for scale in [10, 13, 16, 20]:
            int_repr = int(fv * Decimal(10)**scale)
            # Extract bytes from binary
            byte_vals = []
            tmp = int_repr
            for b in range(16):
                byte_vals.append(tmp & 0xFF)
                tmp >>= 8
            byte_vals_be = list(reversed(byte_vals[:8]))
            print(f"      Scale 10^{scale}: int={int_repr}")
            print(f"        LE bytes: {byte_vals[:8]}")
            print(f"        BE bytes: {byte_vals_be}")
            matches = [j for j, bv in enumerate(byte_vals[:12]) if bv == target]
            if matches:
                print(f"        ✓ Match at LE position(s): {matches}")
            matches_be = [j for j, bv in enumerate(byte_vals_be) if bv == target]
            if matches_be:
                print(f"        ✓ Match at BE position(s): {matches_be}")


if __name__ == "__main__":
    analyze_precision()
    analyze_fixed_point_format()
    analyze_byte_extraction()
    analyze_mandelbrot_computation()
    analyze_sort_vs_mandelbrot()
    analyze_fixed_point_binary()
    analyze_byte_extraction_from_binary()
