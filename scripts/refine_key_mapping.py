"""
Refine the key mapping formula, now that we know:
- iter=5, angle = |z| mod 19 (degrees) gives ~1e-12 roundtrip error
- hyp = 0.01 * key_byte / 256

Test variations:
1. |z| vs |z|² vs zx vs zy
2. Different iteration counts
3. Different primes and combinations
4. Hypotenuse formula variations
5. Angle in degrees vs radians
"""

import math
from decimal import Decimal, getcontext

getcontext().prec = 80

PORTAL_X = Decimal("-2.08907476180957704082504287877")
PORTAL_Y = Decimal("-0.08680597208354758390593279988")
KEY_BYTES = [83, 101, 99, 114, 101, 116, 57, 57]  # "Secret99"


def mandelbrot_z(cx, cy, n_iters):
    """Return (zx, zy) at iteration n."""
    zx, zy = Decimal(0), Decimal(0)
    for _ in range(n_iters):
        zx, zy = zx * zx - zy * zy + cx, 2 * zx * zy + cy
    return zx, zy


def compute_fv_variants(cx, cy, n_iters):
    """Return dict of FV variants."""
    zx, zy = mandelbrot_z(cx, cy, n_iters)
    mag_sq = zx * zx + zy * zy
    mag = mag_sq.sqrt()
    return {
        "|z|": mag,
        "|z|²": mag_sq,
        "zx": abs(zx),
        "zy": abs(zy),
    }


def reverse_navigate(portal_x, portal_y, key_bytes, fv_func, angle_mod,
                     hyp_func, angle_unit="degrees", iters=8):
    """Generic reverse navigation."""
    x, y = portal_x, portal_y

    for byte_val in reversed(key_bytes):
        hyp = hyp_func(byte_val)
        if hyp == 0:
            continue

        est_x, est_y = x, y
        for _ in range(iters):
            fv = fv_func(est_x, est_y)
            angle_val = float(fv) % angle_mod
            if angle_unit == "degrees":
                angle_rad = math.radians(angle_val)
            else:
                angle_rad = angle_val

            est_x = x - Decimal(str(hyp * math.cos(angle_rad)))
            est_y = y - Decimal(str(hyp * math.sin(angle_rad)))

        x, y = est_x, est_y

    return x, y


def forward_navigate(entry_x, entry_y, key_bytes, fv_func, angle_mod,
                     hyp_func, angle_unit="degrees"):
    """Generic forward navigation."""
    x, y = entry_x, entry_y

    for byte_val in key_bytes:
        fv = fv_func(x, y)
        angle_val = float(fv) % angle_mod
        if angle_unit == "degrees":
            angle_rad = math.radians(angle_val)
        else:
            angle_rad = angle_val

        hyp = hyp_func(byte_val)
        x = x + Decimal(str(hyp * math.cos(angle_rad)))
        y = y + Decimal(str(hyp * math.sin(angle_rad)))

    return x, y


def roundtrip_error(fv_func, angle_mod, hyp_func, angle_unit="degrees"):
    """Compute roundtrip error for a given formula."""
    entry_x, entry_y = reverse_navigate(
        PORTAL_X, PORTAL_Y, KEY_BYTES, fv_func, angle_mod, hyp_func, angle_unit)
    final_x, final_y = forward_navigate(
        entry_x, entry_y, KEY_BYTES, fv_func, angle_mod, hyp_func, angle_unit)
    err_x = abs(float(final_x - PORTAL_X))
    err_y = abs(float(final_y - PORTAL_Y))
    return err_x, err_y, entry_x, entry_y


def main():
    ms = 0.01

    # Standard hyp formulas
    hyp_standard = lambda b: ms * b / 256
    hyp_255 = lambda b: ms * b / 255
    hyp_128 = lambda b: ms * b / 128

    print("=" * 100)
    print("SYSTEMATIC FORMULA SEARCH")
    print("=" * 100)

    results = []

    for n_iters in [4, 5, 6, 7]:
        for fv_name in ["|z|", "|z|²"]:
            def make_fv_func(n, name):
                def f(cx, cy):
                    return compute_fv_variants(cx, cy, n)[name]
                return f

            fv_func = make_fv_func(n_iters, fv_name)

            for angle_mod in [19, 360, 103, 37, 41, 43, 53, 59, 61, 67, 71, 73, 79, 83, 89, 97]:
                for hyp_fn, hyp_name in [(hyp_standard, "b/256"), (hyp_255, "b/255")]:
                    for angle_unit in ["degrees"]:
                        try:
                            err_x, err_y, entry_x, entry_y = roundtrip_error(
                                fv_func, angle_mod, hyp_fn, angle_unit)
                            total_err = err_x + err_y
                            results.append((total_err, n_iters, fv_name, angle_mod,
                                            hyp_name, angle_unit, err_x, err_y,
                                            entry_x, entry_y))
                        except Exception:
                            pass

    # Sort by total error
    results.sort(key=lambda r: r[0])

    print(f"\nTop 20 results (sorted by total error):")
    print(f"{'Rank':>4} {'Err_total':>12} {'iter':>4} {'FV':>5} {'mod':>5} {'hyp':>6} {'unit':>4} "
          f"{'Err_x':>12} {'Err_y':>12}")
    print("-" * 90)

    for i, (total_err, n_iters, fv_name, angle_mod, hyp_name, angle_unit,
            err_x, err_y, entry_x, entry_y) in enumerate(results[:20]):
        print(f"{i+1:4d} {total_err:12.4e} {n_iters:4d} {fv_name:>5} {angle_mod:5d} {hyp_name:>6} "
              f"{angle_unit:>4} {err_x:12.4e} {err_y:12.4e}")

    # Show the best result in detail
    if results:
        best = results[0]
        _, n_iters, fv_name, angle_mod, hyp_name, angle_unit, err_x, err_y, entry_x, entry_y = best
        print(f"\n{'=' * 80}")
        print(f"BEST FORMULA: iter={n_iters}, FV={fv_name}, mod={angle_mod}, hyp={hyp_name}")
        print(f"{'=' * 80}")
        print(f"  Entry Portal: ({entry_x}, {entry_y})")
        print(f"  Roundtrip error: ({err_x:.4e}, {err_y:.4e})")

        # Show the full navigation path
        def make_fv_func2(n, name):
            def f(cx, cy):
                return compute_fv_variants(cx, cy, n)[name]
            return f

        fv_func = make_fv_func2(n_iters, fv_name)
        hyp_fn = hyp_standard if hyp_name == "b/256" else hyp_255

        print(f"\n  Forward navigation path:")
        x, y = entry_x, entry_y
        for i, byte_val in enumerate(KEY_BYTES):
            fv = fv_func(x, y)
            angle_val = float(fv) % angle_mod
            hyp = hyp_fn(byte_val)
            angle_rad = math.radians(angle_val)
            new_x = x + Decimal(str(hyp * math.cos(angle_rad)))
            new_y = y + Decimal(str(hyp * math.sin(angle_rad)))
            print(f"    Step {i}: byte={byte_val:3d} ('{chr(byte_val)}')"
                  f" FV={float(fv):15.6f}"
                  f" angle={angle_val:10.6f}°"
                  f" hyp={hyp:.8f}"
                  f" → ({float(new_x):.15f}, {float(new_y):.15f})")
            x, y = new_x, new_y

    # EXPERIMENT 2: Test hypotenuse scaling more carefully
    print(f"\n{'=' * 80}")
    print("HYPOTENUSE SCALING TEST")
    print("  Using best FV/iter/mod, try different hyp formulas")
    print(f"{'=' * 80}")

    if results:
        _, n_iters, fv_name, angle_mod, _, _, _, _, _, _ = results[0]
        fv_func = make_fv_func2(n_iters, fv_name)

        for ms_val in [0.01, 0.001, 0.1, 0.005, 0.02]:
            for divisor in [256, 255, 128, 100]:
                hyp_fn = lambda b, m=ms_val, d=divisor: m * b / d
                try:
                    err_x, err_y, ex, ey = roundtrip_error(
                        fv_func, angle_mod, hyp_fn)
                    total = err_x + err_y
                    print(f"  ms={ms_val}, div={divisor}: err=({err_x:.4e}, {err_y:.4e})"
                          f" entry=({float(ex):.10f}, {float(ey):.10f})")
                except Exception:
                    pass

    # EXPERIMENT 3: Try also using key byte as direct angle offset or hyp selector
    print(f"\n{'=' * 80}")
    print("EXPERIMENT 3: Does key byte affect the prime modulus?")
    print(f"{'=' * 80}")

    # Maybe the angle modulus changes per key byte?
    # Try: angle = FV mod prime_for_byte_value
    # Since we found prime=19 works for all bytes, this seems unlikely
    # But let's verify

    # Test: same entry portal, but different prime per step
    if results:
        best = results[0]
        _, n_iters, fv_name, _, _, _, _, _, entry_x, entry_y = best
        fv_func = make_fv_func2(n_iters, fv_name)

        # Try constant primes first
        for prime in [2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47]:
            try:
                final_x, final_y = forward_navigate(
                    entry_x, entry_y, KEY_BYTES, fv_func, prime, hyp_standard)
                err_x = abs(float(final_x - PORTAL_X))
                err_y = abs(float(final_y - PORTAL_Y))
                if err_x + err_y < 0.001:
                    print(f"  prime={prime:3d}: err=({err_x:.4e}, {err_y:.4e}) ***")
                elif err_x + err_y < 0.1:
                    print(f"  prime={prime:3d}: err=({err_x:.4e}, {err_y:.4e})")
            except Exception:
                pass


if __name__ == "__main__":
    main()
