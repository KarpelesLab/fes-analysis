"""
Analyze the FT-Explained table data to determine the exact byte extraction formula.

Known data from FT-Explained PDF (page 18):
- Key: Secret99, Payload: "Demo Payload", ADD mode
- Per-byte: Fractal X, Fractal Y, Fractal Value, Angle, Hypotenuse

Key observations:
1. Angle fractional part EXACTLY doubles each step (z² property)
2. FV integer part is always 5874
3. Stream[0] for XOR = 215 = first_3_frac_digits(FV) mod 256 = 727 mod 256
"""

import base64
import json
import sys
import time
import urllib.request
import urllib.parse
from decimal import Decimal, getcontext

getcontext().prec = 80

API_URL = "https://portalz.solutions/fes.dna"
HEADERS = {
    "Content-Type": "application/x-www-form-urlencoded",
    "Referer": "https://portalz.solutions/fractalTransform.html",
    "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36",
}

# FT-Explained table data for Secret99 "Demo Payload"
FT_TABLE = [
    # (char, fractal_x, fractal_y, fractal_value, angle, hypotenuse)
    ("D", "-2.08907476180957701022001083650", "-0.08680597208354758191207770730", "5874.7274351297", "3.72743512971", "0.000000000000000306699110601"),
    ("e", "-2.08907476181522003792380968740", "-0.08680597208458885481071240080", "5874.72743642702", "190.45487025942", "0.00000000000573826292128887302"),
    ("m", "-2.08907476180923032802915825710", "-0.08680597208334813676592169720", "5874.72743503904", "29.90974051884", "0.00000000000039998615537133240"),
    ("o", "-2.08907476181107661452222121900", "-0.08680597208314070620383176580", "5874.72743541918", "164.81948103768", "0.00000000001553792372788637400"),
    (" ", "-2.08907476181442825818550023280", "-0.08680597208023072934617983240", "5874.7274359044", "145.63896207536", "0.00000000005876719667378806800"),
    ("P", "-2.08907476180436862921232677160", "-0.08680597208306643814826154770", "5874.72743397111", "5.27792415072", "0.00000000005230588185625111600"),
    ("a", "-2.08907476181307931138051932930", "-0.08680597208096131920214754340", "5874.72743567349", "143.55584830144", "0.00000000004353695460387964200"),
    ("y", "-2.08907476181089027613870934230", "-0.08680597208523521959207236210", "5874.72743554848", "232.11169660288", "0.00000000002138387522294673860"),
    ("l", "-2.08907476180897180563306393630", "-0.08680597208472406243986805040", "5874.72743509473", "297.22339320576", "0.00000000001323031129305176400"),
    ("o2", "-2.08907476181171974211069395000", "-0.08680597208084869794064169780", "5874.72743537211", "128.44678641152", "0.00000000003446034456935301760"),
    ("a2", "-2.08907476181481324569076360310", "-0.08680597208289478361839539360", "5874.72743620258", "172.89357282304", "0.00000000005276740434321808200"),
    ("d", "-2.08907476180781278213431070650", "-0.08680597208488735293400753930", "5874.72743485877", "322.78714564608", "0.00000000002215307937441225600"),
]

PLAINTEXT = "Demo Payload"


def fes_request(key, payload="", dimensions=8, xor=True, add=False):
    data = {
        "mode": "1", "key": key, "payload": payload, "trans": "",
        "dimensions": str(dimensions), "depth": "3", "scramble": "",
        "xor": "on" if xor else "", "whirl": "", "asciiRange": "256",
    }
    if add:
        data["add"] = "on"
    encoded = urllib.parse.urlencode(data).encode()
    req = urllib.request.Request(API_URL, encoded, headers=HEADERS)
    with urllib.request.urlopen(req) as resp:
        return json.loads(resp.read())


def b64_decode(s):
    padded = s + '=' * (4 - len(s) % 4) if len(s) % 4 else s
    return base64.b64decode(padded)


def experiment_add_transform_values():
    """Get ADD-mode cipher for 'Demo Payload' and extract per-byte transform values."""
    print("=" * 70)
    print("EXPERIMENT: ADD Mode Transform Values vs FT-Explained Table")
    print("=" * 70)

    key = "Secret99"
    pt = PLAINTEXT
    pt_bytes = list(pt.encode())

    # Get ADD-only cipher (xor=off, add=on)
    # BUT: server always applies XOR regardless of checkbox!
    # So we need to test both ways

    # Method 1: XOR-only (default)
    result_xor = fes_request(key, payload=pt, xor=True, add=False)
    ct_xor = list(b64_decode(result_xor.get("trans", "")))
    xor_stream_rev = [(c ^ p) for c, p in zip(ct_xor, pt_bytes)]
    xor_stream = list(reversed(xor_stream_rev))

    print(f"\n  Plaintext: {pt_bytes}")
    print(f"  XOR cipher: {ct_xor}")
    print(f"  XOR stream (forward): {xor_stream}")

    # Method 2: ADD-only (xor=off, add=on)
    result_add = fes_request(key, payload=pt, xor=False, add=True)
    ct_add = list(b64_decode(result_add.get("trans", "")))
    # If server always applies XOR first, then ADD:
    # cipher[i] = (pt[i] XOR stream[N-1-i] + stream_add[N-1-i]) mod 256
    # But if ADD uses same stream:
    # cipher[i] = ((pt[i] XOR stream[N-1-i]) + stream[N-1-i]) mod 256
    print(f"\n  ADD cipher: {ct_add}")

    # Method 3: Both XOR and ADD
    result_both = fes_request(key, payload=pt, xor=True, add=True)
    ct_both = list(b64_decode(result_both.get("trans", "")))
    print(f"  XOR+ADD cipher: {ct_both}")

    # Check if ADD cipher == XOR+ADD cipher (since XOR is always on)
    print(f"  ADD == XOR+ADD: {ct_add == ct_both}")

    # If XOR is always applied, the "ADD-only" cipher is actually XOR+ADD
    # Decompose: temp[i] = pt[i] XOR stream[N-1-i], cipher[i] = (temp[i] + add_val[i]) mod 256
    # So add_val[i] = (cipher[i] - temp[i]) mod 256
    # where temp[i] = ct_xor[i] (the XOR-only cipher)
    N = len(pt_bytes)
    if ct_add != ct_xor:
        add_vals_rev = [(ct_add[i] - ct_xor[i]) % 256 for i in range(N)]
        add_vals = list(reversed(add_vals_rev))
        print(f"\n  ADD transform values (forward): {add_vals}")

        # Compare with FV-based calculations
        print(f"\n  Comparing ADD vals with FT-Explained FVs:")
        for idx, (row, av) in enumerate(zip(FT_TABLE, add_vals)):
            ch, fx, fy, fv_str, angle_str, hyp_str = row
            fv = Decimal(fv_str)
            fv_int = int(fv)
            fv_frac = fv - fv_int
            fv_frac_str = str(fv_frac)
            if '.' in fv_frac_str:
                frac_digits = fv_frac_str.split('.')[1]
            else:
                frac_digits = '0'

            # Try: byte = int(frac_digits[:N]) mod 256 for various N
            matches = []
            for nd in range(1, min(20, len(frac_digits) + 1)):
                cv = int(frac_digits[:nd])
                if cv % 256 == av:
                    matches.append(nd)

            # Also try: byte = int(FV) mod 256
            int_fv_mod = fv_int % 256

            match_str = f"frac[:{matches[0]}]" if matches else "NO MATCH"
            print(f"    [{idx:2d}] '{ch}': FV={fv_str}, add_val={av:3d}, "
                  f"int(FV)%256={int_fv_mod}, {match_str}")


def experiment_angle_doubling():
    """Verify the exact angle doubling pattern from the table."""
    print("\n" + "=" * 70)
    print("EXPERIMENT: Angle Fractional Part Doubling Verification")
    print("=" * 70)

    angles = []
    for row in FT_TABLE:
        ch, _, _, _, angle_str, _ = row
        angle = Decimal(angle_str)
        angles.append((ch, angle))

    print(f"\n  Angle doubling chain:")
    for i, (ch, angle) in enumerate(angles):
        frac = angle - int(angle)
        int_part = int(angle)
        if i > 0:
            prev_frac = angles[i-1][1] - int(angles[i-1][1])
            expected_frac = (2 * prev_frac) % 1
            diff = abs(float(frac - expected_frac))
            status = "OK" if diff < 1e-10 else f"DIFF={diff:.2e}"
        else:
            status = "INITIAL"
        print(f"    [{i:2d}] '{ch}': angle={float(angle):>14.11f}  "
              f"int={int_part:>3d}  frac={float(frac):.11f}  {status}")


def experiment_prime_modulus():
    """Find the dynamic prime modulus for each byte position."""
    print("\n" + "=" * 70)
    print("EXPERIMENT: Dynamic Prime Modulus Array")
    print("=" * 70)

    fv_int = 5874  # int(FV) is same for all bytes

    print(f"\n  int(FV) = {fv_int} for all bytes")
    print(f"  Solving: {fv_int} mod p[i] = angle_int[i]\n")

    for idx, row in enumerate(FT_TABLE):
        ch, _, _, fv_str, angle_str, _ = row
        angle_int = int(Decimal(angle_str))
        remainder = fv_int - angle_int

        # Factor remainder
        if remainder <= 0:
            print(f"    [{idx:2d}] '{ch}': angle_int={angle_int}, remainder={remainder} (INVALID)")
            continue

        # Find all divisors > angle_int
        divisors = []
        for d in range(2, remainder + 1):
            if remainder % d == 0:
                divisors.append(d)

        # Filter to those > angle_int (so remainder is valid)
        valid_divisors = [d for d in divisors if d > angle_int]

        # Check which are prime
        def is_prime(n):
            if n < 2:
                return False
            for p in range(2, int(n**0.5) + 1):
                if n % p == 0:
                    return False
            return True

        primes = [d for d in valid_divisors if is_prime(d)]
        composites = [d for d in valid_divisors if not is_prime(d)]

        print(f"    [{idx:2d}] '{ch}': angle_int={angle_int:>3d}, "
              f"{fv_int}-{angle_int}={remainder}, "
              f"primes={primes[:5]}, composites={composites[:3]}")


def experiment_hypotenuse():
    """Analyze the hypotenuse values to find the formula."""
    print("\n" + "=" * 70)
    print("EXPERIMENT: Hypotenuse Formula Analysis")
    print("=" * 70)

    key_bytes = list("Secret99".encode())
    print(f"\n  Key bytes: {key_bytes}")
    print(f"  Key: {''.join(chr(b) for b in key_bytes)}")

    for idx, row in enumerate(FT_TABLE):
        ch, _, _, _, _, hyp_str = row
        hyp = Decimal(hyp_str)

        # Try: hyp = scale / key_byte
        # Key bytes cycle: S(83), e(101), c(99), r(114), e(101), t(116), 9(57), 9(57)
        kb = key_bytes[idx % len(key_bytes)]

        # Try various scale formulas
        if hyp > 0:
            scale = float(hyp) * kb
            inv_hyp = 1.0 / float(hyp) if float(hyp) > 0 else 0
        else:
            scale = 0
            inv_hyp = 0

        print(f"    [{idx:2d}] '{ch}': hyp={float(hyp):.6e}, "
              f"key_byte={kb}({chr(kb)}), "
              f"hyp*kb={scale:.6e}, 1/hyp={inv_hyp:.6e}")


def experiment_fv_at_portals():
    """Compute FV at each portal position from the table and compare."""
    print("\n" + "=" * 70)
    print("EXPERIMENT: Compute FV at Table Portal Positions")
    print("=" * 70)

    for idx, row in enumerate(FT_TABLE[:4]):
        ch, fx_str, fy_str, fv_str, angle_str, _ = row
        cx = Decimal(fx_str)
        cy = Decimal(fy_str)

        # Mandelbrot iterations
        zx, zy = Decimal(0), Decimal(0)
        for i in range(10):
            new_zx = zx * zx - zy * zy + cx
            new_zy = 2 * zx * zy + cy
            zx, zy = new_zx, new_zy
            mag_sq = zx * zx + zy * zy
            if mag_sq > 4:
                mag = mag_sq.sqrt()
                print(f"    [{idx}] '{ch}': escaped at iter {i+1}, |z|={float(mag):.10f}")
                break
        else:
            mag = (zx * zx + zy * zy).sqrt()
            # Find iteration where |z| matches FV
            print(f"    [{idx}] '{ch}': did not escape in 10 iters, |z_10|={float(mag):.10f}")

        # Try specific iterations
        zx, zy = Decimal(0), Decimal(0)
        for i in range(8):
            new_zx = zx * zx - zy * zy + cx
            new_zy = 2 * zx * zy + cy
            zx, zy = new_zx, new_zy
            mag = (zx * zx + zy * zy).sqrt()

            if abs(float(mag) - float(Decimal(fv_str))) < 1:
                print(f"        iter {i+1}: |z|={float(mag):.10f} vs FV={fv_str} "
                      f"({'MATCH' if abs(float(mag) - float(Decimal(fv_str))) < 0.001 else 'close'})")


def experiment_cv_digit_count():
    """Determine how many fractional digits are used for cv mod 256.

    We know our computed |z_6| at original portal = 5874.727435129700904829789479727831...
    And stream[0] = 215.

    Test: for each digit count D, compute int(frac_digits[:D]) mod 256 and check.
    """
    print("\n" + "=" * 70)
    print("EXPERIMENT: CV Digit Count for mod 256")
    print("=" * 70)

    cx = Decimal("-2.0890747618095770104082504287")
    cy = Decimal("-0.0868059720835475839205932798")

    zx, zy = Decimal(0), Decimal(0)
    for i in range(6):
        zx, zy = zx * zx - zy * zy + cx, 2 * zx * zy + cy

    mag = (zx * zx + zy * zy).sqrt()
    frac = mag - int(mag)
    frac_str = str(frac)
    frac_digits = frac_str.split('.')[1] if '.' in frac_str else '0'

    print(f"\n  |z_6| = {mag}")
    print(f"  Fractional digits: {frac_digits}")

    # Also try: cv = full number with decimal removed
    # FV = 5874.727435129700904829789479727831
    # With N decimal places, cv = integer of FV * 10^N
    mag_str = str(mag)
    int_part = str(int(mag))

    print(f"\n  Testing cv = FV_as_integer (decimal removed) with varying precision:")
    for n_dec in range(1, 40):
        if n_dec <= len(frac_digits):
            # cv = int_part + frac_digits[:n_dec] as integer
            cv_str = int_part + frac_digits[:n_dec]
            cv = int(cv_str)
            byte_val = cv % 256
            if byte_val == 215:
                print(f"    {n_dec} decimal places: cv={cv_str}, cv%256={byte_val} = 215 MATCH!")

    print(f"\n  Testing cv = fractional digits only:")
    for nd in range(1, 40):
        if nd <= len(frac_digits):
            cv = int(frac_digits[:nd])
            byte_val = cv % 256
            if byte_val == 215:
                print(f"    first {nd} frac digits: cv={cv}, cv%256={byte_val} = 215 MATCH!")

    # Get actual XOR stream for multiple bytes
    known = 'A' * 20
    result = fes_request("Secret99", payload=known)
    ct = b64_decode(result.get("trans", ""))
    stream_rev = bytes(c ^ 0x41 for c in ct)
    stream = list(reversed(stream_rev))

    print(f"\n  Actual XOR stream (first 14): {stream[:14]}")

    # For each stream byte, check all the per-byte FVs from the table
    # (the FVs are for the same portal positions, just different precision)
    print(f"\n  Testing table FVs against XOR stream bytes:")
    for idx in range(min(12, len(stream))):
        row = FT_TABLE[idx]
        ch, fx_str, fy_str, fv_str, _, _ = row
        fv = Decimal(fv_str)
        fv_frac = fv - int(fv)
        fd = str(fv_frac).split('.')[1] if '.' in str(fv_frac) else '0'

        matches = []
        for nd in range(1, min(15, len(fd) + 1)):
            cv = int(fd[:nd])
            if cv % 256 == stream[idx]:
                matches.append((nd, cv))

        # Also test full FV as integer
        full_cv_matches = []
        int_str = str(int(fv))
        for nd in range(1, min(15, len(fd) + 1)):
            full_cv = int(int_str + fd[:nd])
            if full_cv % 256 == stream[idx]:
                full_cv_matches.append((nd, full_cv))

        match_info = f"frac[:{matches[0][0]}]={matches[0][1]}" if matches else "NO frac match"
        full_info = f"full[:{full_cv_matches[0][0]}]" if full_cv_matches else "NO full match"
        print(f"    [{idx:2d}] '{ch}': stream={stream[idx]:3d}, FV={fv_str}, "
              f"{match_info}, {full_info}")


def experiment_xor_stream_vs_add():
    """Compare XOR stream extracted from 'AAA...' with ADD transform values."""
    print("\n" + "=" * 70)
    print("EXPERIMENT: XOR Stream vs ADD Transform Values")
    print("=" * 70)

    key = "Secret99"
    N = 20

    # XOR stream
    known = 'A' * N
    result_xor = fes_request(key, payload=known)
    ct_xor = b64_decode(result_xor.get("trans", ""))
    xor_stream = list(reversed([c ^ 0x41 for c in ct_xor]))

    # ADD-only stream (but XOR is always applied too)
    result_add = fes_request(key, payload=known, xor=False, add=True)
    ct_add = list(b64_decode(result_add.get("trans", "")))

    # The ADD cipher = (XOR_cipher + add_stream) mod 256
    # So add_stream[i] = (ct_add[i] - ct_xor[i]) mod 256 (in reverse order)
    ct_xor_list = list(ct_xor)
    add_stream_rev = [(ct_add[i] - ct_xor_list[i]) % 256 for i in range(N)]
    add_stream = list(reversed(add_stream_rev))

    print(f"\n  XOR stream: {xor_stream}")
    print(f"  ADD stream: {add_stream}")
    print(f"  Same: {xor_stream == add_stream}")

    # Check if ADD stream = XOR stream (just different application)
    # Or if they're different values entirely

    # Check common patterns
    diffs = [(add_stream[i] - xor_stream[i]) % 256 for i in range(N)]
    print(f"  (ADD - XOR) mod 256: {diffs}")

    xors = [add_stream[i] ^ xor_stream[i] for i in range(N)]
    print(f"  ADD XOR XOR_stream: {xors}")


def main():
    tests = {
        "add": experiment_add_transform_values,
        "double": experiment_angle_doubling,
        "prime": experiment_prime_modulus,
        "hyp": experiment_hypotenuse,
        "portals": experiment_fv_at_portals,
        "digits": experiment_cv_digit_count,
        "compare": experiment_xor_stream_vs_add,
    }

    if len(sys.argv) > 1:
        selected = sys.argv[1:]
        if selected == ["all"]:
            selected = list(tests.keys())
    else:
        selected = ["double", "prime", "digits"]

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
