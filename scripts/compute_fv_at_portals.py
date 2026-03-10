"""
Compute |z_N| at each portal position from FT-Explained table with full precision,
then test byte extraction formulas against the actual XOR stream.
"""

import base64
import json
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

# Portal positions from FT-Explained table (Secret99, "Demo Payload")
PORTALS = [
    ("D",  "-2.08907476180957701022001083650", "-0.08680597208354758191207770730"),
    ("e",  "-2.08907476181522003792380968740", "-0.08680597208458885481071240080"),
    ("m",  "-2.08907476180923032802915825710", "-0.08680597208334813676592169720"),
    ("o",  "-2.08907476181107661452222121900", "-0.08680597208314070620383176580"),
    (" ",  "-2.08907476181442825818550023280", "-0.08680597208023072934617983240"),
    ("P",  "-2.08907476180436862921232677160", "-0.08680597208306643814826154770"),
    ("a",  "-2.08907476181307931138051932930", "-0.08680597208096131920214754340"),
    ("y",  "-2.08907476181089027613870934230", "-0.08680597208523521959207236210"),
    ("l",  "-2.08907476180897180563306393630", "-0.08680597208472406243986805040"),
    ("o2", "-2.08907476181171974211069395000", "-0.08680597208084869794064169780"),
    ("a2", "-2.08907476181481324569076360310", "-0.08680597208289478361839539360"),
    ("d",  "-2.08907476180781278213431070650", "-0.08680597208488735293400753930"),
]


def fes_request(key, payload="", dimensions=8):
    data = urllib.parse.urlencode({
        "mode": "1", "key": key, "payload": payload, "trans": "",
        "dimensions": str(dimensions), "depth": "3", "scramble": "",
        "xor": "on", "whirl": "", "asciiRange": "256",
    }).encode()
    req = urllib.request.Request(API_URL, data=data, headers=HEADERS)
    with urllib.request.urlopen(req) as resp:
        return json.loads(resp.read())


def b64_decode(s):
    padded = s + '=' * (4 - len(s) % 4) if len(s) % 4 else s
    return base64.b64decode(padded)


def mandelbrot_mag(cx, cy, n_iters):
    """Compute |z_n| at point (cx, cy) for Mandelbrot iteration."""
    zx, zy = Decimal(0), Decimal(0)
    for _ in range(n_iters):
        zx, zy = zx * zx - zy * zy + cx, 2 * zx * zy + cy
    return (zx * zx + zy * zy).sqrt(), zx, zy


def frac_digits(val):
    """Get fractional digits as a string."""
    frac = abs(val) - int(abs(val))
    s = str(frac)
    return s.split('.')[1] if '.' in s else '0'


def main():
    # Get actual XOR stream
    known = 'A' * 20
    result = fes_request("Secret99", payload=known)
    ct = b64_decode(result.get("trans", ""))
    stream = list(reversed([c ^ 0x41 for c in ct]))

    print("=" * 80)
    print("Compute |z_N| at each FT-Explained portal position (full precision)")
    print("=" * 80)
    print(f"\nActual XOR stream: {stream[:14]}")

    # Try different iteration counts
    for n_iter in [5, 6, 7]:
        print(f"\n{'─' * 80}")
        print(f"  Testing iteration count N = {n_iter}")
        print(f"{'─' * 80}")

        matches_3 = 0
        matches_full = 0

        for idx, (ch, fx_str, fy_str) in enumerate(PORTALS):
            cx = Decimal(fx_str)
            cy = Decimal(fy_str)
            mag, zx, zy = mandelbrot_mag(cx, cy, n_iter)

            fd = frac_digits(mag)
            fd_zx = frac_digits(zx)
            fd_zy = frac_digits(zy)

            # Test formulas for this byte
            actual = stream[idx] if idx < len(stream) else -1

            # Formula 1: first 3 fractional digits of |z| mod 256
            if len(fd) >= 3:
                cv3 = int(fd[:3])
                b3 = cv3 % 256
            else:
                b3 = -1

            # Formula 2: full cv (int+frac as integer, 28 decimal places) mod 256
            int_part = str(int(mag))
            if len(fd) >= 28:
                full_cv = int(int_part + fd[:28])
                b_full = full_cv % 256
            else:
                b_full = -1

            # Formula 3: test various digit counts for fractional digits
            frac_match = None
            for nd in range(1, min(40, len(fd) + 1)):
                cv = int(fd[:nd])
                if cv % 256 == actual:
                    frac_match = (nd, cv)
                    break

            # Formula 4: test full cv with various decimal precisions
            full_match = None
            for nd in range(1, min(40, len(fd) + 1)):
                cv = int(int_part + fd[:nd])
                if cv % 256 == actual:
                    full_match = (nd, cv)
                    break

            if b3 == actual:
                matches_3 += 1
            if b_full == actual:
                matches_full += 1

            status_3 = "OK" if b3 == actual else f"got {b3}"
            frac_info = f"frac[:{frac_match[0]}]" if frac_match else "NO frac"
            full_info = f"full[:{full_match[0]}]" if full_match else "NO full"

            print(f"  [{idx:2d}] '{ch}': |z_{n_iter}|={float(mag):.13f}, "
                  f"stream={actual:3d}, "
                  f"3dig={b3:3d}({status_3}), "
                  f"{frac_info}, {full_info}")

        print(f"\n  Score: 3-digit={matches_3}/12, full-28={matches_full}/12")

    # Also test: what if stream bytes come from zx and zy separately?
    print(f"\n{'─' * 80}")
    print(f"  Testing zx/zy fractional digits at N=6")
    print(f"{'─' * 80}")

    for idx, (ch, fx_str, fy_str) in enumerate(PORTALS):
        cx = Decimal(fx_str)
        cy = Decimal(fy_str)
        mag, zx, zy = mandelbrot_mag(cx, cy, 6)

        actual = stream[idx] if idx < len(stream) else -1
        fd_zx = frac_digits(zx)
        fd_zy = frac_digits(zy)
        fd_mag = frac_digits(mag)

        # Test zx, zy, mag, mag² fractional digits
        results = {}
        for name, val in [("zx", abs(zx)), ("zy", abs(zy)), ("|z|", mag),
                          ("|z|²", zx*zx+zy*zy)]:
            fd_val = frac_digits(val)
            for nd in range(1, min(40, len(fd_val) + 1)):
                cv = int(fd_val[:nd])
                if cv % 256 == actual:
                    results[name] = (nd, cv)
                    break

        match_strs = [f"{name}[:{v[0]}]" for name, v in results.items()]
        print(f"  [{idx:2d}] '{ch}': stream={actual:3d}, "
              f"matches: {', '.join(match_strs) if match_strs else 'NONE'}")


if __name__ == "__main__":
    main()
