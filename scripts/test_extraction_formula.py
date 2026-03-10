"""
Test the visualization's stream byte extraction formula against known server output.

The fractal.js visualization uses:
  streamByte = parseInt(fv.toString().replace('.', '')) % 256

where fv = |z|² = zx² + zy² at the navigation point after maxDepth iterations.

Test this with the known Secret99 portal coordinates and varying maxDepth values
to find which depth the server uses.

Also test the V3 spec's key-byte influence hypothesis: SHA bytes mixed into navigation.
"""

from decimal import Decimal, getcontext
import hashlib

# Use very high precision
getcontext().prec = 100

# Known portal for Secret99 (from FT-Explained)
PORTAL_X = Decimal("-2.08907476180957704082504287877")
PORTAL_Y = Decimal("-0.08680597208354758390593279988")

# Known stream bytes for Secret99, "Demo Payload", dim=8
KNOWN_STREAM = [215, 27, 210, 179, 226, 199, 7, 46, 14, 223, 201, 97]

# Known FV values from FT-Explained
KNOWN_FV = [
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

# Known angles from FT-Explained
KNOWN_ANGLES = [
    Decimal("3.72743512971"),
    Decimal("190.45487025942"),
    Decimal("29.90974051884"),
    Decimal("164.81948103768"),
    Decimal("145.63896207536"),
    Decimal("5.27792415072"),
    Decimal("143.55584830144"),
    Decimal("232.11169660288"),
    Decimal("297.22339320576"),
    Decimal("128.44678641152"),
    Decimal("172.89357282304"),
    Decimal("322.78714564608"),
]


def mandelbrot_fv(cx, cy, max_depth):
    """Compute |z|² after max_depth iterations of z = z² + c."""
    zx = Decimal(0)
    zy = Decimal(0)
    for i in range(max_depth):
        xt = zx * zy
        zx_new = zx * zx - zy * zy + cx
        zy_new = 2 * xt + cy
        zx = zx_new
        zy = zy_new
        # Check for escape
        if zx * zx + zy * zy > Decimal(10000):
            break
    return zx * zx + zy * zy


def extract_byte_stripped(fv):
    """Extract byte using visualization's formula: str(fv).replace('.','') % 256."""
    s = str(fv)
    # Remove leading minus if present
    if s.startswith('-'):
        s = s[1:]
    stripped = s.replace('.', '')
    # Remove leading zeros
    stripped = stripped.lstrip('0') or '0'
    # In JavaScript, this would be parsed as a float then mod 256
    # For large numbers, we need to handle this carefully
    val = int(stripped) if len(stripped) < 20 else int(stripped) % 256
    return val % 256


def extract_byte_int_mod(fv, mod=256):
    """V3 spec formula: int(fv) mod 256."""
    return int(fv) % mod


def extract_byte_frac3(fv):
    """First 3 fractional digits mod 256."""
    s = str(fv)
    if '.' in s:
        frac = s.split('.')[1]
        digits3 = int(frac[:3])
        return digits3 % 256
    return 0


def main():
    print("=" * 80)
    print("TEST 1: COMPUTE |z|² AT PORTAL WITH VARYING maxDepth")
    print("=" * 80)

    cx = PORTAL_X
    cy = PORTAL_Y

    for depth in [5, 6, 7, 8, 10, 15, 20, 50, 100, 200, 256, 500]:
        fv = mandelbrot_fv(cx, cy, depth)
        fv_float = float(fv)
        stripped_byte = extract_byte_stripped(fv)
        int_mod_byte = extract_byte_int_mod(fv)
        frac3_byte = extract_byte_frac3(fv)

        match = "✓" if stripped_byte == KNOWN_STREAM[0] else " "
        match_int = "✓" if int_mod_byte == KNOWN_STREAM[0] else " "
        match_frac = "✓" if frac3_byte == KNOWN_STREAM[0] else " "

        # Show enough digits
        fv_str = str(fv)[:40]
        print(f"  depth={depth:3d}: |z|²={fv_str:42s}  "
              f"stripped%256={stripped_byte:3d}{match}  "
              f"int%256={int_mod_byte:3d}{match_int}  "
              f"frac3%256={frac3_byte:3d}{match_frac}")

    # Also check: does |z|² escape at low depth?
    print(f"\n  Known FT-Explained FV[0] = {KNOWN_FV[0]}")
    print(f"  Target stream byte 0 = {KNOWN_STREAM[0]}")

    # =========================================================================
    print(f"\n{'=' * 80}")
    print("TEST 2: ALL 12 KNOWN FV VALUES — TEST EXTRACTION FORMULAS")
    print("=" * 80)

    print(f"\n  {'Pos':>3s} {'Char':>4s} {'FV':>18s} {'stream':>6s} "
          f"{'strip%256':>9s} {'int%256':>7s} {'frac3%256':>9s}")

    payload = "Demo Payload"
    for i in range(12):
        fv = KNOWN_FV[i]
        target = KNOWN_STREAM[i]
        stripped = extract_byte_stripped(fv)
        int_mod = extract_byte_int_mod(fv)
        frac3 = extract_byte_frac3(fv)

        print(f"  {i:3d} {payload[i]:>4s}  {float(fv):18.10f}  {target:6d}  "
              f"{stripped:9d}{'✓' if stripped == target else ' '}  "
              f"{int_mod:7d}{'✓' if int_mod == target else ' '}  "
              f"{frac3:9d}{'✓' if frac3 == target else ' '}")

    # =========================================================================
    print(f"\n{'=' * 80}")
    print("TEST 3: DIFFERENT DIGIT GROUP SIZES FROM FV")
    print("=" * 80)

    for digit_count in range(1, 20):
        matches = 0
        results = []
        for i in range(12):
            fv_str = str(KNOWN_FV[i])
            if '.' in fv_str:
                frac = fv_str.split('.')[1]
                if len(frac) >= digit_count:
                    val = int(frac[:digit_count]) % 256
                else:
                    val = int(frac) % 256
            else:
                val = 0
            results.append(val)
            if val == KNOWN_STREAM[i]:
                matches += 1

        if matches > 0:
            print(f"  frac[:{digit_count:2d}] mod 256: {results}  matches={matches}/12")

    # =========================================================================
    print(f"\n{'=' * 80}")
    print("TEST 4: DIGIT GROUPS FROM DIFFERENT FV COMPONENTS")
    print("=" * 80)

    # Test: remove integer part entirely, use fractional digits in groups
    for i in range(12):
        fv = KNOWN_FV[i]
        fv_str = str(fv)
        if '.' in fv_str:
            frac = fv_str.split('.')[1]
        else:
            frac = "0"
        angle_str = str(KNOWN_ANGLES[i])
        if '.' in angle_str:
            angle_frac = angle_str.split('.')[1]
        else:
            angle_frac = "0"

        if i < 3:  # Show detail for first 3
            print(f"\n  Byte {i} ('{payload[i]}'), target={KNOWN_STREAM[i]}:")
            print(f"    FV frac digits:    {frac[:20]}")
            print(f"    Angle frac digits: {angle_frac[:20]}")
            # Try every 3-digit group from FV fractional part
            print(f"    3-digit groups from FV frac (mod 256):")
            for j in range(0, min(len(frac)-2, 30), 3):
                grp = int(frac[j:j+3])
                print(f"      [{j}:{j+3}] = {grp} mod 256 = {grp % 256}"
                      f"{'  ✓' if grp % 256 == KNOWN_STREAM[i] else ''}")

    # =========================================================================
    print(f"\n{'=' * 80}")
    print("TEST 5: WHOLE STRING STRIPPED MOD 256 WITH VARYING PRECISION")
    print("=" * 80)

    # The visualization uses toString().replace('.','') which depends on
    # float precision. Test with different number of decimal places.
    for prec in range(1, 25):
        matches = 0
        results = []
        for i in range(12):
            fv = KNOWN_FV[i]
            # Format with specific decimal places
            fv_formatted = f"{float(fv):.{prec}f}"
            stripped = fv_formatted.replace('.', '').replace('-', '').lstrip('0') or '0'
            val = int(stripped) % 256
            results.append(val)
            if val == KNOWN_STREAM[i]:
                matches += 1

        if matches > 0:
            print(f"  {prec:2d} decimals: matches={matches}/12  {results}")

    # =========================================================================
    print(f"\n{'=' * 80}")
    print("TEST 6: ANGLE INTEGER PART — FIND DYNAMIC PRIME MODULUS")
    print("=" * 80)

    # For each byte, angle_int = FV_int mod prime
    # We know FV_int ≈ 5874 for all, and the angle integers vary
    fv_int = 5874
    for i in range(12):
        angle_int = int(KNOWN_ANGLES[i])
        remainder = fv_int - angle_int
        if remainder > 0:
            # Find all divisors
            divs = []
            for d in range(2, min(remainder + 1, 10000)):
                if remainder % d == 0 and fv_int % d == angle_int:
                    divs.append(d)
            print(f"  Byte {i:2d}: angle_int={angle_int:3d}, "
                  f"5874 - {angle_int} = {remainder}, "
                  f"primes that work: {divs[:10]}")

    # =========================================================================
    print(f"\n{'=' * 80}")
    print("TEST 7: DECIMAL STRING OF |z|² AT PORTAL (HIGH PRECISION)")
    print("=" * 80)

    # Compute |z|² with very high precision for depth where it matches FV
    getcontext().prec = 150
    cx = Decimal("-2.08907476180957704082504287877")
    cy = Decimal("-0.08680597208354758390593279988")

    for depth in [5, 6, 7, 8]:
        fv = mandelbrot_fv(cx, cy, depth)
        fv_str = str(fv)
        print(f"\n  depth={depth}: |z|² = {fv_str[:80]}")

        # Show the full fractional part
        if '.' in fv_str:
            parts = fv_str.split('.')
            print(f"    Integer part: {parts[0]}")
            print(f"    Fractional:   {parts[1][:60]}")

            # Try stripped value mod 256
            stripped = (parts[0] + parts[1]).lstrip('0')
            # Need to handle very large numbers carefully
            mod_val = 0
            for ch in stripped:
                mod_val = (mod_val * 10 + int(ch)) % 256
            print(f"    Stripped mod 256 = {mod_val}")
            print(f"    int(FV) mod 256 = {int(parts[0]) % 256}")

            # Check specific digit groups
            frac = parts[1]
            for g in [3, 4, 5, 6]:
                if len(frac) >= g:
                    val = int(frac[:g]) % 256
                    match = "✓" if val == 215 else ""
                    print(f"    frac[:{g}] mod 256 = {val} {match}")

    # =========================================================================
    print(f"\n{'=' * 80}")
    print("TEST 8: KEY BYTE INFLUENCE — SHA-512 XOR WITH RAW EXTRACTION")
    print("=" * 80)

    # Hypothesis: stream[i] = raw_extraction[i] XOR sha512(key)[i]
    sha = hashlib.sha512("Secret99".encode()).digest()
    print(f"  SHA-512(Secret99)[:12] = {list(sha[:12])}")
    print(f"  Known stream[:12]      = {KNOWN_STREAM}")

    # For each extraction method, check if XOR with SHA gives stream
    for depth in [5, 6, 7, 8]:
        fv = mandelbrot_fv(PORTAL_X, PORTAL_Y, depth)
        fv_str = str(fv)
        if '.' in fv_str:
            frac = fv_str.split('.')[1]
            for g in [3]:
                raw = int(frac[:g]) % 256
                xor_result = raw ^ sha[0]
                match = "✓" if xor_result == KNOWN_STREAM[0] else ""
                print(f"  depth={depth}, frac[:{g}]%256={raw}, "
                      f"XOR SHA[0]={sha[0]}: {xor_result} {match}")
                # Also try ADD
                add_result = (raw + sha[0]) % 256
                match_add = "✓" if add_result == KNOWN_STREAM[0] else ""
                print(f"  depth={depth}, frac[:{g}]%256={raw}, "
                      f"ADD SHA[0]={sha[0]}: {add_result} {match_add}")


if __name__ == "__main__":
    main()
