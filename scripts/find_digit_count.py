"""
Systematic search for the byte extraction formula.

For each digit count D (1..60), compute int(FV * 10^D) mod 256 at each of
the 12 portal positions from FT-Explained, and check how many match the
actual XOR stream bytes.

Also test: int(frac * 10^D) mod 256, and cv = full_integer_repr mod 256.
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


def mandelbrot_z(cx, cy, n_iters):
    """Return zx, zy at iteration n."""
    zx, zy = Decimal(0), Decimal(0)
    for _ in range(n_iters):
        zx, zy = zx * zx - zy * zy + cx, 2 * zx * zy + cy
    return zx, zy


def main():
    # Get actual XOR stream at length 12 (same as "Demo Payload")
    result = fes_request("Secret99", payload='A' * 12)
    ct = b64_decode(result.get("trans", ""))
    stream_12 = list(reversed([c ^ 0x41 for c in ct]))

    # Also get at length 20
    result20 = fes_request("Secret99", payload='A' * 20)
    ct20 = b64_decode(result20.get("trans", ""))
    stream_20 = list(reversed([c ^ 0x41 for c in ct20]))

    print(f"XOR stream (len=12): {stream_12}")
    print(f"XOR stream (len=20): {stream_20[:14]}")
    print(f"Streams match: {stream_12 == stream_20[:12]}")

    stream = stream_12  # Use 12-byte stream to match FT-Explained table

    # Compute |z_6| at each portal
    print(f"\nComputing z_6 at each portal position...")
    portal_data = []
    for idx, (ch, fx_str, fy_str) in enumerate(PORTALS):
        cx = Decimal(fx_str)
        cy = Decimal(fy_str)
        zx, zy = mandelbrot_z(cx, cy, 6)
        mag = (zx * zx + zy * zy).sqrt()
        portal_data.append({
            'ch': ch, 'zx': zx, 'zy': zy, 'mag': mag,
            'mag_sq': zx * zx + zy * zy,
            'stream_byte': stream[idx]
        })

    # Test 1: int(FV * 10^D) mod 256 for D=1..60
    print("\n" + "=" * 80)
    print("TEST 1: int(|z_6| * 10^D) mod 256")
    print("=" * 80)

    best_d = 0
    best_matches = 0

    for D in range(1, 65):
        matches = 0
        match_detail = []
        for idx, pd in enumerate(portal_data):
            cv = int(pd['mag'] * Decimal(10) ** D)
            byte_val = cv % 256
            if byte_val == pd['stream_byte']:
                matches += 1
                match_detail.append(idx)

        if matches >= best_matches:
            if matches > best_matches or D < best_d:
                best_d = D
                best_matches = matches

        if matches >= 2:
            print(f"  D={D:2d}: {matches}/12 matches at positions {match_detail}")

    print(f"\n  Best: D={best_d} with {best_matches}/12 matches")

    # Test 2: int(frac(|z_6|) * 10^D) mod 256
    print("\n" + "=" * 80)
    print("TEST 2: int(frac(|z_6|) * 10^D) mod 256")
    print("=" * 80)

    best_d = 0
    best_matches = 0

    for D in range(1, 65):
        matches = 0
        match_detail = []
        for idx, pd in enumerate(portal_data):
            frac = pd['mag'] - int(pd['mag'])
            cv = int(frac * Decimal(10) ** D)
            byte_val = cv % 256
            if byte_val == pd['stream_byte']:
                matches += 1
                match_detail.append(idx)

        if matches >= best_matches:
            if matches > best_matches:
                best_d = D
                best_matches = matches

        if matches >= 2:
            print(f"  D={D:2d}: {matches}/12 matches at positions {match_detail}")

    print(f"\n  Best: D={best_d} with {best_matches}/12 matches")

    # Test 3: same but using zx (real part)
    print("\n" + "=" * 80)
    print("TEST 3: int(frac(|zx_6|) * 10^D) mod 256")
    print("=" * 80)

    for D in range(1, 65):
        matches = 0
        match_detail = []
        for idx, pd in enumerate(portal_data):
            frac = abs(pd['zx']) - int(abs(pd['zx']))
            cv = int(frac * Decimal(10) ** D)
            byte_val = cv % 256
            if byte_val == pd['stream_byte']:
                matches += 1
                match_detail.append(idx)
        if matches >= 2:
            print(f"  D={D:2d}: {matches}/12 matches at positions {match_detail}")

    # Test 4: same but using zy (imaginary part)
    print("\n" + "=" * 80)
    print("TEST 4: int(frac(|zy_6|) * 10^D) mod 256")
    print("=" * 80)

    for D in range(1, 65):
        matches = 0
        match_detail = []
        for idx, pd in enumerate(portal_data):
            frac = abs(pd['zy']) - int(abs(pd['zy']))
            cv = int(frac * Decimal(10) ** D)
            byte_val = cv % 256
            if byte_val == pd['stream_byte']:
                matches += 1
                match_detail.append(idx)
        if matches >= 2:
            print(f"  D={D:2d}: {matches}/12 matches at positions {match_detail}")

    # Test 5: base-256 extraction from fractional part
    # byte_k = floor(frac * 256^(k+1)) mod 256
    print("\n" + "=" * 80)
    print("TEST 5: Base-256 extraction from frac(|z_6|)")
    print("=" * 80)

    for k in range(20):
        matches = 0
        match_detail = []
        for idx, pd in enumerate(portal_data):
            frac = pd['mag'] - int(pd['mag'])
            cv = int(frac * Decimal(256) ** (k + 1))
            byte_val = cv % 256
            if byte_val == pd['stream_byte']:
                matches += 1
                match_detail.append(idx)
        if matches >= 2:
            print(f"  k={k:2d}: {matches}/12 matches at positions {match_detail}")

    # Test 6: Maybe the formula uses z (complex) directly as bytes
    # Extract bytes from fixed-point representation of zx and zy
    print("\n" + "=" * 80)
    print("TEST 6: Bytes from zx/zy fixed-point (base-256)")
    print("=" * 80)

    for component in ['zx', 'zy', 'mag']:
        for k in range(20):
            matches = 0
            match_detail = []
            for idx, pd in enumerate(portal_data):
                if component == 'zx':
                    val = pd['zx']
                elif component == 'zy':
                    val = pd['zy']
                else:
                    val = pd['mag']

                # Treat as fixed-point, extract byte k from fractional part
                frac = abs(val) - int(abs(val))
                cv = int(frac * Decimal(256) ** (k + 1))
                byte_val = cv % 256
                if byte_val == pd['stream_byte']:
                    matches += 1
                    match_detail.append(idx)
            if matches >= 3:
                print(f"  {component} k={k:2d}: {matches}/12 matches at positions {match_detail}")

    # Test 7: XOR/combine of zx and zy bytes
    print("\n" + "=" * 80)
    print("TEST 7: zx_byte XOR zy_byte (base-256)")
    print("=" * 80)

    for k in range(20):
        matches = 0
        match_detail = []
        for idx, pd in enumerate(portal_data):
            frac_x = abs(pd['zx']) - int(abs(pd['zx']))
            frac_y = abs(pd['zy']) - int(abs(pd['zy']))
            bx = int(frac_x * Decimal(256) ** (k + 1)) % 256
            by = int(frac_y * Decimal(256) ** (k + 1)) % 256
            combined = bx ^ by
            if combined == pd['stream_byte']:
                matches += 1
                match_detail.append(idx)
        if matches >= 3:
            print(f"  k={k:2d}: {matches}/12 matches XOR at {match_detail}")

    # Test 7b: ADD of zx and zy bytes
    for k in range(20):
        matches = 0
        match_detail = []
        for idx, pd in enumerate(portal_data):
            frac_x = abs(pd['zx']) - int(abs(pd['zx']))
            frac_y = abs(pd['zy']) - int(abs(pd['zy']))
            bx = int(frac_x * Decimal(256) ** (k + 1)) % 256
            by = int(frac_y * Decimal(256) ** (k + 1)) % 256
            combined = (bx + by) % 256
            if combined == pd['stream_byte']:
                matches += 1
                match_detail.append(idx)
        if matches >= 3:
            print(f"  k={k:2d}: {matches}/12 matches ADD at {match_detail}")

    # Test 8: int part contributes?  int(zx) XOR int(zy) etc.
    print("\n" + "=" * 80)
    print("TEST 8: Integer parts and sign bits")
    print("=" * 80)

    for idx, pd in enumerate(portal_data):
        zx_int = int(pd['zx'])
        zy_int = int(pd['zy'])
        zx_sign = 1 if pd['zx'] < 0 else 0
        zy_sign = 1 if pd['zy'] < 0 else 0
        mag_int = int(pd['mag'])

        # Various combinations
        combos = {
            'zx_int%256': abs(zx_int) % 256,
            'zy_int%256': abs(zy_int) % 256,
            'zx^zy_int%256': (abs(zx_int) ^ abs(zy_int)) % 256,
            '(zx+zy)%256': (abs(zx_int) + abs(zy_int)) % 256,
            'mag_int%256': mag_int % 256,
        }

        matches = {k: v for k, v in combos.items() if v == pd['stream_byte']}
        if matches:
            print(f"  [{idx:2d}] '{pd['ch']}': stream={pd['stream_byte']:3d}, "
                  f"matches: {matches}")

    # Test 9: Maybe stream byte depends on iteration count, not fixed at 6
    print("\n" + "=" * 80)
    print("TEST 9: Variable iteration count")
    print("=" * 80)
    print("  (Does each byte use a different Mandelbrot iteration?)")

    for idx, (ch, fx_str, fy_str) in enumerate(PORTALS[:6]):
        cx = Decimal(fx_str)
        cy = Decimal(fy_str)
        actual = stream[idx]

        zx, zy = Decimal(0), Decimal(0)
        for n in range(1, 12):
            zx, zy = zx * zx - zy * zy + cx, 2 * zx * zy + cy
            mag = (zx * zx + zy * zy).sqrt()
            frac = mag - int(mag)
            fd = str(frac).split('.')[1] if '.' in str(frac) else '0'
            for nd in range(1, min(15, len(fd) + 1)):
                cv = int(fd[:nd])
                if cv % 256 == actual:
                    print(f"  [{idx}] '{ch}': iter={n}, frac[:{nd}]={cv}, "
                          f"cv%256={cv%256} = stream[{idx}]={actual}")
                    break


if __name__ == "__main__":
    main()
