"""
Reverse-engineer the key→portal mapping using the known Secret99 test vector.

Known:
- Key: "Secret99"
- Fractal Portal: (-2.0890747618095770104082504287, -0.0868059720835475839205932798)
- |z_6| = 5874.7274351297 (from FT-Explained)
- Navigation uses key bytes with angle from Mandelbrot + hypotenuse from FV

Strategy:
1. Reverse the key-byte navigation (8 steps backward) to find the Entry Portal
2. Entry Portal = silo_entry + scaled_offset
3. Compute what SHA-512("Secret99") gives for the offset bits
4. Subtract offset from entry portal → silo entry
5. This gives us silo entry for one index!

Key formulas from spec:
- At each navigation step: angle = cv mod 360 (or mod prime)
- hypotenuse = ms / bkb (ms = 0.01, bkb = key byte)
- x += hyp * cos(angle), y += hyp * sin(angle)
"""

import hashlib
import math
from decimal import Decimal, getcontext

# Need very high precision for Mandelbrot near the boundary
getcontext().prec = 80

# Known test vector from FT-Explained
PORTAL_X = Decimal("-2.0890747618095770104082504287")
PORTAL_Y = Decimal("-0.0868059720835475839205932798")
KEY = b"Secret99"
MS = Decimal("0.01")  # Mapping scale

def mandelbrot_iterations(cx, cy, max_iter=10):
    """Compute Mandelbrot iterations at point (cx, cy).
    Returns list of (zx, zy) at each iteration."""
    zx, zy = Decimal(0), Decimal(0)
    results = [(zx, zy)]
    for i in range(max_iter):
        new_zx = zx * zx - zy * zy + cx
        new_zy = 2 * zx * zy + cy
        zx, zy = new_zx, new_zy
        results.append((zx, zy))
    return results


def fractal_value(cx, cy, num_iter=6):
    """Compute |z_N| at position (cx, cy) after N Mandelbrot iterations."""
    iters = mandelbrot_iterations(cx, cy, num_iter)
    zx, zy = iters[num_iter]
    return (zx * zx + zy * zy).sqrt()


def experiment_reverse_navigation():
    """Try to reverse the 8 navigation steps from Fractal Portal back to Entry Portal."""
    print("=" * 70)
    print("EXPERIMENT: Reverse Key-Byte Navigation")
    print("=" * 70)

    cx, cy = PORTAL_X, PORTAL_Y
    print(f"  Fractal Portal: ({cx}, {cy})")
    print(f"  Key bytes: {list(KEY)}")

    # Forward simulation first: navigate from portal using key bytes
    # to verify the navigation formula
    # The spec says: for each key byte bkb (in order):
    #   cv = mandelbrot value at current pos
    #   angle = cv mod 360
    #   hyp = ms / bkb
    #   x += hyp * cos(angle), y += hyp * sin(angle)

    # But first, let's try to figure out what "cv" is.
    # We know FV = |z_6| = 5874.727...
    # The FT-Explained shows angle = 3.727 for the first byte
    # 5874.727 mod 360 = 5874.727 - 16*360 = 5874.727 - 5760 = 114.727
    # But the actual angle is 3.727. So it's NOT mod 360.

    fv = fractal_value(cx, cy, 6)
    print(f"\n  |z_6| at portal = {fv}")
    print(f"  FT-Explained says: 5874.7274351297")

    # Test various moduli
    fv_float = float(fv)
    fv_int = int(fv_float)
    print(f"\n  Trying different moduli for angle extraction:")
    print(f"  FV = {fv_float:.10f}, int(FV) = {fv_int}")
    for mod in [360, 359, 353, 349, 347, 337, 331, 317, 313, 311, 307, 293,
                281, 277, 271, 269, 263, 257, 251, 241, 239, 233, 229, 227,
                223, 211, 199, 197, 193, 191, 181, 179, 173, 167, 163, 157,
                151, 149, 139, 137, 131, 127, 113, 109, 107, 103, 101, 97,
                89, 83, 79, 73, 71, 67, 61, 59, 53, 47, 43, 41, 37, 31,
                29, 23, 19, 17, 13, 11, 7, 5, 3, 2]:
        remainder = fv_int % mod
        frac = fv_float - fv_int
        result = remainder + frac
        # Check if close to 3.727
        if abs(result - 3.7274351297) < 0.01:
            print(f"  *** int(FV) mod {mod} = {remainder}, "
                  f"full = {result:.10f} (target: 3.72743512971)")

    # Also test: FV mod prime with fractional part preserved differently
    # What if it's just FV mod prime (full float)?
    print(f"\n  Trying FV mod prime (full float):")
    for mod in [19, 23, 29, 31, 37, 41, 43, 47, 53, 59, 61, 67, 71, 73,
                79, 83, 89, 97, 101, 103, 107, 109, 113, 127, 131, 137,
                139, 149, 151, 157, 163, 167, 173, 179, 181, 191, 193,
                197, 199, 211, 223, 227, 229, 233, 239, 241, 251, 257,
                263, 269, 271, 277, 281, 283, 293, 307, 311, 313, 317,
                331, 337, 347, 349, 353, 359]:
        result = fv_float % mod
        if abs(result - 3.7274351297) < 0.01:
            print(f"  *** FV mod {mod} = {result:.10f}")
        # Also check if the result matches any of the known angles
        # from FT-Explained table


def experiment_find_angle_modulus():
    """Use ALL angles from FT-Explained to find the dynamic prime array.

    Known angles (from FT-Explained, "Demo Payload" with Secret99):
    D: 3.72743512971
    e: 190.45487025942
    m: 29.90974051884
    o: 164.81948103768
    (space): unknown
    P: 5.27792415072
    a: 143.55584830144
    y: 232.11169660288
    l: 297.22339320576
    o: 128.44678641152
    a: 172.89357282304
    d: 322.78714564608

    The fractional parts double: 0.72743512971 × 2^n mod 1
    So we need: floor(angle_n) = int(FV_n) mod prime_n
    """
    print("\n" + "=" * 70)
    print("EXPERIMENT: Find Dynamic Prime Modulus Array")
    print("=" * 70)

    # FV at portal: 5874.7274351297...
    # FV at subsequent steps: barely different (tiny navigation steps)
    # Let's approximate all FVs as having int part = 5874

    fv_int = 5874  # int part of fractal value (barely changes)

    angles_int = [3, 190, 29, 164, None, 5, 143, 232, 297, 128, 172, 322]
    # Missing angle for space (character at position 4)

    print(f"  FV integer part: {fv_int}")
    print(f"  Known angle integer parts: {angles_int}")

    # For each angle: fv_int mod prime = angle_int
    # So prime divides (fv_int - angle_int)
    print(f"\n  Finding candidate primes:")
    for i, a in enumerate(angles_int):
        if a is None:
            print(f"  Step {i}: unknown (space character)")
            continue
        diff = fv_int - a
        if diff <= 0:
            print(f"  Step {i}: angle={a}, diff={diff} (no solution)")
            continue

        # Find prime factors of diff
        primes = []
        d = diff
        for p in range(2, min(d + 1, 10000)):
            if d % p == 0:
                while d % p == 0:
                    d //= p
                primes.append(p)
            if p * p > d:
                break
        if d > 1:
            primes.append(d)

        # The modulus must be > angle_int (otherwise remainder can't be that large)
        candidates = []
        # Generate all factors of diff from prime factors
        factors = [1]
        temp = fv_int - a
        for p in range(2, min(temp + 1, 10000)):
            if temp % p == 0:
                new_factors = []
                pk = 1
                while temp % p == 0:
                    pk *= p
                    temp //= p
                    new_factors.extend([f * pk for f in factors])
                factors.extend(new_factors)
        if temp > 1:
            factors.extend([f * temp for f in factors])

        prime_candidates = [f for f in set(factors) if f > a and is_prime(f)]
        print(f"  Step {i}: angle={a:3d}, diff={fv_int-a}, "
              f"prime candidates (>{a}): {sorted(prime_candidates)[:10]}")


def is_prime(n):
    if n < 2:
        return False
    if n < 4:
        return True
    if n % 2 == 0 or n % 3 == 0:
        return False
    i = 5
    while i * i <= n:
        if n % i == 0 or n % (i + 2) == 0:
            return False
        i += 6
    return True


def experiment_common_primes():
    """Find primes that work for MULTIPLE angles simultaneously.

    If the dynamic prime array selects different primes for each step,
    the same prime might appear multiple times or the primes might come
    from a small fixed set.
    """
    print("\n" + "=" * 70)
    print("EXPERIMENT: Common Primes Across Steps")
    print("=" * 70)

    fv_int = 5874
    angles_int = [3, 190, 29, 164, None, 5, 143, 232, 297, 128, 172, 322]

    # For each prime, check which angles it satisfies
    prime_hits = {}
    for p in range(2, 6000):
        if not is_prime(p):
            continue
        remainder = fv_int % p
        hits = []
        for i, a in enumerate(angles_int):
            if a is not None and a == remainder:
                hits.append(i)
        if hits:
            prime_hits[p] = hits

    # Show primes that hit multiple steps
    multi_hit = {p: h for p, h in prime_hits.items() if len(h) >= 2}
    if multi_hit:
        print("  Primes satisfying multiple angles:")
        for p, hits in sorted(multi_hit.items()):
            r = fv_int % p
            print(f"    prime={p}: fv_int mod {p} = {r}, matches steps {hits}")

    # Show all primes that satisfy at least one angle
    print(f"\n  All primes satisfying at least one angle (fv_int={fv_int}):")
    for i, a in enumerate(angles_int):
        if a is None:
            continue
        matching = [p for p, h in prime_hits.items() if i in h]
        print(f"  Step {i} (angle={a:3d}): primes={matching[:15]}...")


def experiment_reverse_with_primes():
    """Try to reverse the navigation using candidate primes.

    For each combination of primes, simulate forward navigation from
    some entry portal and see if we arrive at the known fractal portal.
    """
    print("\n" + "=" * 70)
    print("EXPERIMENT: Reverse Navigation with Prime Candidates")
    print("=" * 70)

    # We know: key "Secret99" = bytes [83, 101, 99, 114, 101, 116, 57, 57]
    # Navigation: 8 steps from Entry Portal to Fractal Portal
    # Each step: angle = FV mod prime, hyp = 0.01 / key_byte
    #   x += hyp * cos(angle_deg), y += hyp * sin(angle_deg)

    # Since steps are tiny, FV barely changes. Let's assume FV_int = 5874 throughout.
    # angle_deg = FV mod prime + fractional_angle
    # The fractional angle doubles each step

    # For step 0 (key byte 83='S'):
    #   angle has int part determined by prime, frac = 0.72743512971
    #   hyp = 0.01 / 83 ≈ 0.000120481927711

    # We need the prime for step 0 to give int(angle) = 3 (from FT-Explained)
    # Wait - the FT-Explained angles are for Demo Payload encryption, not navigation!
    # The navigation angles come from the Mandelbrot value at each position.

    # Let me just try the reverse directly.
    # Going backwards from the Fractal Portal:
    # The last step was with key byte 57 ('9')
    # Before that step: x_prev, y_prev
    # At (x_prev, y_prev), FV was computed → angle → hyp
    # x_portal = x_prev + hyp * cos(angle), y_portal = y_prev + hyp * sin(angle)
    # So: x_prev = x_portal - hyp * cos(angle), y_prev = y_portal - hyp * sin(angle)

    # But we need to know the angle at x_prev. Since the step is tiny,
    # FV at x_prev ≈ FV at portal. And the angle ≈ angle at portal.
    # So we can iterate to convergence.

    # Actually, the question is: what prime modulus is used for navigation?
    # The FT-Explained angles are for the stream generation (encryption), not navigation.
    # Navigation might use a different prime or even a fixed mod 360.

    # Let's try mod 360 first (simplest hypothesis)
    fv = fractal_value(PORTAL_X, PORTAL_Y, 6)
    fv_float = float(fv)
    angle_mod360 = fv_float % 360
    print(f"  FV at portal: {fv_float:.10f}")
    print(f"  FV mod 360: {angle_mod360:.6f}°")

    # Try navigation reversal with mod 360
    cx, cy = PORTAL_X, PORTAL_Y
    key_bytes = list(KEY)

    print(f"\n  Reversing navigation (mod 360):")
    for i in range(len(key_bytes) - 1, -1, -1):
        bkb = key_bytes[i]
        # Compute FV at current position
        fv_cur = float(fractal_value(cx, cy, 6))
        angle = fv_cur % 360
        hyp = Decimal("0.01") / Decimal(bkb)

        # Reverse the step
        angle_rad = float(angle) * math.pi / 180
        dx = hyp * Decimal(str(math.cos(angle_rad)))
        dy = hyp * Decimal(str(math.sin(angle_rad)))
        cx = cx - dx
        cy = cy - dy

        print(f"  Step {i} (byte={bkb:3d} '{chr(bkb)}'): "
              f"angle={angle:10.4f}° hyp={float(hyp):.6e} → "
              f"({float(cx):.20f}, {float(cy):.20f})")

    entry_portal_360 = (cx, cy)
    print(f"\n  Entry Portal (mod 360): ({float(cx):.25f}, {float(cy):.25f})")

    # Now try to extract the silo entry and offset
    # If SHA-512("Secret99") gives us the offset bits...
    sha = hashlib.sha512(KEY).digest()
    silo_idx = (sha[0] << 8) | sha[1]
    print(f"\n  SHA-512('Secret99') first 16 bits (silo index?): {silo_idx}")
    print(f"  SHA-512 first 16 bytes: {sha[:16].hex()}")

    # The offset would be bytes 2-15 of SHA-512
    # Split into x_offset (bytes 2-8) and y_offset (bytes 9-15)
    x_offset_bytes = sha[2:9]  # 7 bytes = 56 bits
    y_offset_bytes = sha[9:16]  # 7 bytes = 56 bits

    # Scale: max value of 7 bytes = 2^56 - 1 = 72057594037927935
    # Scaled to 0.01
    max_val = (1 << 56) - 1
    x_offset = Decimal(int.from_bytes(x_offset_bytes, 'big')) / Decimal(max_val) * Decimal("0.01")
    y_offset = Decimal(int.from_bytes(y_offset_bytes, 'big')) / Decimal(max_val) * Decimal("0.01")
    print(f"  x_offset (scaled): {float(x_offset):.15f}")
    print(f"  y_offset (scaled): {float(y_offset):.15f}")

    # Silo entry = entry portal - offset
    silo_x = cx - x_offset
    silo_y = cy - y_offset
    print(f"\n  Derived silo entry (if mod 360 is correct):")
    print(f"    silo_x = {float(silo_x):.20f}")
    print(f"    silo_y = {float(silo_y):.20f}")
    print(f"    silo_idx = {silo_idx}")

    # Also try: what if the angle uses the arg(z) directly?
    print(f"\n  Reversing navigation (using arg(z_6)):")
    cx, cy = PORTAL_X, PORTAL_Y
    for i in range(len(key_bytes) - 1, -1, -1):
        bkb = key_bytes[i]
        iters = mandelbrot_iterations(cx, cy, 6)
        zx, zy = iters[6]
        angle = float(Decimal.from_float(math.atan2(float(zy), float(zx)))) * 180 / math.pi
        if angle < 0:
            angle += 360
        hyp = Decimal("0.01") / Decimal(bkb)

        angle_rad = angle * math.pi / 180
        dx = hyp * Decimal(str(math.cos(angle_rad)))
        dy = hyp * Decimal(str(math.sin(angle_rad)))
        cx = cx - dx
        cy = cy - dy

        print(f"  Step {i} (byte={bkb:3d} '{chr(bkb)}'): "
              f"arg(z6)={angle:10.4f}° hyp={float(hyp):.6e}")

    print(f"\n  Entry Portal (arg(z6)): ({float(cx):.25f}, {float(cy):.25f})")


def experiment_sha512_layout():
    """Show how SHA-512("Secret99") maps to expanded key bytes under
    various splitting hypotheses."""
    print("\n" + "=" * 70)
    print("EXPERIMENT: SHA-512 Layout for 'Secret99'")
    print("=" * 70)

    sha = hashlib.sha512(KEY).digest()
    print(f"  SHA-512('Secret99'): {sha.hex()}")
    print(f"  Length: {len(sha)} bytes = {len(sha)*8} bits")

    # Hypothesis A: 16 bytes per pair (2 idx + 7 x + 7 y)
    print(f"\n  Hypothesis A: 16 bytes/pair (2+7+7)")
    for pair in range(4):
        start = pair * 16
        idx_bytes = sha[start:start+2]
        x_off = sha[start+2:start+9]
        y_off = sha[start+9:start+16]
        idx = int.from_bytes(idx_bytes, 'big')
        print(f"    Pair {pair}: idx={idx:5d} (0x{idx_bytes.hex()}) "
              f"x_off={x_off.hex()} y_off={y_off.hex()}")

    # Hypothesis B: 14 bytes per pair (2 idx + 6 x + 6 y)
    print(f"\n  Hypothesis B: 14 bytes/pair (2+6+6)")
    for pair in range(4):
        start = pair * 14
        idx_bytes = sha[start:start+2]
        x_off = sha[start+2:start+8]
        y_off = sha[start+8:start+14]
        idx = int.from_bytes(idx_bytes, 'big')
        print(f"    Pair {pair}: idx={idx:5d} (0x{idx_bytes.hex()}) "
              f"x_off={x_off.hex()} y_off={y_off.hex()}")

    # Hypothesis C: 8 bytes per pair (2 idx + 3 x + 3 y) — compact
    print(f"\n  Hypothesis C: 8 bytes/pair (2+3+3)")
    for pair in range(4):
        start = pair * 8
        idx_bytes = sha[start:start+2]
        x_off = sha[start+2:start+5]
        y_off = sha[start+5:start+8]
        idx = int.from_bytes(idx_bytes, 'big')
        print(f"    Pair {pair}: idx={idx:5d} (0x{idx_bytes.hex()}) "
              f"x_off={x_off.hex()} y_off={y_off.hex()}")


def main():
    import sys
    tests = {
        "reverse": experiment_reverse_navigation,
        "primes": experiment_find_angle_modulus,
        "common": experiment_common_primes,
        "reverse_nav": experiment_reverse_with_primes,
        "layout": experiment_sha512_layout,
    }

    if len(sys.argv) > 1:
        selected = sys.argv[1:]
        if selected == ["all"]:
            selected = list(tests.keys())
    else:
        selected = ["reverse", "primes", "common", "layout"]

    for name in selected:
        if name not in tests:
            print(f"Unknown: {name}. Available: {', '.join(tests.keys())}")
            sys.exit(1)
        try:
            tests[name]()
        except Exception as e:
            print(f"\n  ERROR in {name}: {e}")
            import traceback
            traceback.print_exc()
        print()


if __name__ == "__main__":
    main()
