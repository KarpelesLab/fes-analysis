"""
Verify the stream byte extraction formula: first 3 fractional digits of |z_N| mod 256.

For Secret99 dim=8: |z_6| = 5874.727... → 727 mod 256 = 215 = stream[0] ✓

Questions:
1. Is it always 3 digits, or does the digit count depend on the FV magnitude?
2. What about stream bytes 1-19? Where do they come from?
3. Does it work for other keys?
4. Does the navigation step between bytes change the FV enough to affect the digits?
"""

import base64
import hashlib
import json
import math
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


def extract_stream(key, length, dimensions=8):
    known = 'A' * length
    result = fes_request(key, payload=known, dimensions=dimensions)
    ct_b64 = result.get("trans", "")
    if not ct_b64:
        return None
    ct = b64_decode(ct_b64)
    stream_rev = bytes(c ^ 0x41 for c in ct)
    return bytes(reversed(stream_rev))


def mandelbrot_iters(cx, cy, max_iter=20):
    """Return list of (zx, zy) at each iteration."""
    zx, zy = Decimal(0), Decimal(0)
    results = [(zx, zy)]
    for i in range(max_iter):
        new_zx = zx * zx - zy * zy + cx
        new_zy = 2 * zx * zy + cy
        zx, zy = new_zx, new_zy
        results.append((zx, zy))
    return results


def verify_secret99():
    """Verify the 3-digit extraction for Secret99 across multiple z iterations."""
    print("=" * 70)
    print("VERIFY: Secret99 dim=8 Byte Extraction")
    print("=" * 70)

    cx = Decimal("-2.0890747618095770104082504287")
    cy = Decimal("-0.0868059720835475839205932798")

    iters = mandelbrot_iters(cx, cy, 10)
    stream = extract_stream("Secret99", 42, dimensions=8)

    if not stream:
        print("  Failed to get stream")
        return

    print(f"  Stream (first 14): {list(stream[:14])}")
    print(f"  Stream[0] = {stream[0]}")

    # For each iteration, try extracting bytes
    for n in range(1, 10):
        zx, zy = iters[n]
        mag = (zx * zx + zy * zy).sqrt()
        mag_float = float(mag)

        # Get fractional part
        frac = mag - int(mag)
        frac_str = str(frac)
        if '.' in frac_str:
            frac_digits = frac_str.split('.')[1]
        else:
            frac_digits = '0'

        # Try different digit counts
        matches = []
        for nd in range(1, min(20, len(frac_digits) + 1)):
            cv = int(frac_digits[:nd])
            byte_val = cv % 256
            if byte_val == stream[0]:
                matches.append((nd, cv))

        # Also try with zx, zy, and zx²+zy² directly
        for name, val in [("zx", abs(zx)), ("zy", abs(zy)), ("|z|²", zx*zx+zy*zy)]:
            val_frac = val - int(val)
            val_frac_str = str(val_frac)
            if '.' in val_frac_str:
                vfd = val_frac_str.split('.')[1]
            else:
                vfd = '0'
            for nd in range(1, min(20, len(vfd) + 1)):
                cv = int(vfd[:nd])
                byte_val = cv % 256
                if byte_val == stream[0]:
                    matches.append((nd, cv, f"iter{n}_{name}"))

        if matches:
            mag_str = f"{mag_float:.15f}"
            print(f"\n  Iter {n}: |z|={mag_str}")
            for m in matches:
                if len(m) == 2:
                    print(f"    *** |z| frac {m[0]} digits: cv={m[1]}, "
                          f"cv%256={m[1]%256} = stream[0]={stream[0]}")
                else:
                    print(f"    *** {m[2]} frac {m[0]} digits: cv={m[1]}, "
                          f"cv%256={m[1]%256} = stream[0]={stream[0]}")

    # Now check ALL stream bytes against iteration 6
    print(f"\n  Checking all stream bytes against z_6 components:")
    zx6, zy6 = iters[6]
    mag6 = (zx6 * zx6 + zy6 * zy6).sqrt()

    components = {
        "|z_6|": mag6,
        "z6_re": abs(zx6),
        "z6_im": abs(zy6),
        "|z_6|²": zx6*zx6 + zy6*zy6,
    }

    for comp_name, comp_val in components.items():
        frac = comp_val - int(comp_val)
        frac_str = str(frac)
        if '.' in frac_str:
            frac_digits = frac_str.split('.')[1]
        else:
            frac_digits = '0'

        print(f"\n  {comp_name} = {float(comp_val):.15f}")
        print(f"  Fractional digits: {frac_digits[:30]}")

        # For each stream byte, find which digit count gives a match
        for si in range(min(14, len(stream))):
            for nd in range(1, min(25, len(frac_digits) + 1)):
                cv = int(frac_digits[:nd])
                if cv % 256 == stream[si]:
                    print(f"    stream[{si:2d}]={stream[si]:3d} ← "
                          f"{comp_name} frac[:{nd}]={cv} mod 256")
                    break

    # Check if consecutive stream bytes come from advancing the
    # fractal navigation (tiny step)
    print(f"\n  Checking bytes from consecutive navigation steps:")
    # After each byte, the portal moves slightly
    # New position → new z → new FV → new byte
    # But the move is tiny (hyp ≈ 10^-17), so FV barely changes
    # The change might be in the 10th+ fractional digit

    print(f"  FV at portal:        {float(mag6):.20f}")
    # Perturb portal slightly and recompute
    for delta in [Decimal("1e-15"), Decimal("1e-16"), Decimal("1e-17")]:
        cx2 = cx + delta
        iters2 = mandelbrot_iters(cx2, cy, 6)
        zx2, zy2 = iters2[6]
        mag2 = (zx2 * zx2 + zy2 * zy2).sqrt()
        print(f"  FV at portal+{float(delta):.0e}: {float(mag2):.20f}")


def verify_block_structure():
    """Verify the 14-byte block structure and duplication pattern."""
    print("\n" + "=" * 70)
    print("VERIFY: 14-Byte Block Structure")
    print("=" * 70)

    keys = ["Secret99", "TestKey1", "probe_0001"]

    for key in keys:
        print(f"\n  Key: '{key}', dim=8")
        stream = extract_stream(key, 56, dimensions=8)
        if not stream:
            continue

        print(f"  Stream ({len(stream)} bytes):")
        for block in range(len(stream) // 14 + 1):
            start = block * 14
            end = min(start + 14, len(stream))
            if start >= len(stream):
                break
            chunk = list(stream[start:end])

            # Check duplication at positions 11-12
            dup = "DUP" if len(chunk) > 12 and chunk[11] == chunk[12] else "   "
            print(f"    Block {block}: {chunk}  {dup}")
        time.sleep(0.15)


def verify_cross_key():
    """Test the 3-digit extraction for multiple keys.

    Get dim=8 stream[0] for several keys and check if int(FV_frac[:3]) mod 256
    matches, IF we knew their portals. Since we don't know other portals,
    just collect the data for pattern analysis.
    """
    print("\n" + "=" * 70)
    print("VERIFY: Cross-Key Stream[0] Analysis")
    print("=" * 70)

    # Get stream[0] for many keys
    keys = [f"test{i}" for i in range(50)]
    results = []

    for key in keys:
        stream = extract_stream(key, 4, dimensions=8)
        if stream:
            sha = hashlib.sha512(key.encode()).digest()
            results.append({
                "key": key,
                "stream0": stream[0],
                "sha_idx": (sha[0] << 8) | sha[1],
            })
        time.sleep(0.05)

    # Analyze: is there any correlation between SHA-512 bits and stream[0]?
    print(f"  Collected {len(results)} data points")

    # Distribution of stream[0]
    from collections import Counter
    s0_dist = Counter(r["stream0"] for r in results)
    print(f"  Unique stream[0] values: {len(s0_dist)}")
    print(f"  Most common: {s0_dist.most_common(5)}")

    # Check: do keys with same SHA-512 first byte give same stream[0]?
    by_sha_byte = {}
    for r in results:
        b = r["sha_idx"] >> 8  # first byte
        by_sha_byte.setdefault(b, []).append(r["stream0"])

    collisions = {b: vals for b, vals in by_sha_byte.items() if len(vals) >= 2}
    if collisions:
        print(f"\n  Keys sharing SHA-512 first byte:")
        for b, vals in sorted(collisions.items()):
            unique = len(set(vals))
            print(f"    byte=0x{b:02x}: stream[0] values={vals} "
                  f"({'SAME' if unique == 1 else 'DIFFER'})")


def main():
    tests = {
        "secret99": verify_secret99,
        "blocks": verify_block_structure,
        "crosskey": verify_cross_key,
    }

    if len(sys.argv) > 1:
        selected = sys.argv[1:]
        if selected == ["all"]:
            selected = list(tests.keys())
    else:
        selected = ["secret99", "blocks"]

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
