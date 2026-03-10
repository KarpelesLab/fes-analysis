"""
Reverse-navigate from the known Secret99 Fractal Portal back through
the key bytes to find the Entry Portal (silo entry + offsets).

Known:
- Key: "Secret99" = [83, 101, 99, 114, 101, 116, 57, 57]
- Fractal Portal: (-2.08907476180957704082504287877, -0.08680597208354758390593279988)
- V3 Spec formula for key mapping:
    angle = cv mod 360  (degrees)
    hyp = ms * (key_byte / ascii_range)  where ms=0.01
    x += hyp * cos(angle_rad)
    y += hyp * sin(angle_rad)

Strategy: If we know the FINAL position (Fractal Portal) and the key bytes,
we can reverse-navigate IF the FV doesn't change much between adjacent positions.
Since the step sizes are ~0.002 and FV is ~5874 at that location, the FV
changes very slowly, so iterative refinement should converge.
"""

import base64
import hashlib
import json
import math
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


def mandelbrot_fv(cx, cy, n_iters=6):
    """Compute |z_n| at point (cx, cy)."""
    zx, zy = Decimal(0), Decimal(0)
    for _ in range(n_iters):
        zx, zy = zx * zx - zy * zy + cx, 2 * zx * zy + cy
    return (zx * zx + zy * zy).sqrt()


def forward_navigate(entry_x, entry_y, key_bytes, ms=Decimal("0.01"),
                     ascii_range=256, n_iters=6, angle_mod=360):
    """Navigate forward through key bytes from entry portal."""
    x, y = entry_x, entry_y
    positions = [(x, y)]

    for byte_val in key_bytes:
        fv = mandelbrot_fv(x, y, n_iters)
        angle_deg = float(fv) % angle_mod
        angle_rad = math.radians(angle_deg)
        hyp = float(ms) * byte_val / ascii_range

        x = x + Decimal(str(hyp * math.cos(angle_rad)))
        y = y + Decimal(str(hyp * math.sin(angle_rad)))
        positions.append((x, y))

    return positions


def reverse_navigate(portal_x, portal_y, key_bytes, ms=Decimal("0.01"),
                     ascii_range=256, n_iters=6, angle_mod=360, iters=5):
    """
    Reverse-navigate from Fractal Portal to Entry Portal.

    Since the angle at position P_i depends on FV(P_i), and we're going backwards,
    we use iterative refinement:
    1. Approximate FV(P_i) ≈ FV(P_{i+1}) (since positions are close)
    2. Compute approximate P_i
    3. Refine by computing FV(P_i) and re-estimating
    """
    x, y = portal_x, portal_y
    path = [(x, y)]

    # Go backwards through key bytes
    for byte_val in reversed(key_bytes):
        hyp = float(ms) * byte_val / ascii_range

        # Iterative refinement
        est_x, est_y = x, y
        for _ in range(iters):
            fv = mandelbrot_fv(est_x, est_y, n_iters)
            angle_deg = float(fv) % angle_mod
            angle_rad = math.radians(angle_deg)

            # Previous position = current - step
            est_x = x - Decimal(str(hyp * math.cos(angle_rad)))
            est_y = y - Decimal(str(hyp * math.sin(angle_rad)))

        x, y = est_x, est_y
        path.append((x, y))

    return list(reversed(path))


def main():
    portal_x = Decimal("-2.08907476180957704082504287877")
    portal_y = Decimal("-0.08680597208354758390593279988")

    key = "Secret99"
    key_bytes = list(key.encode('ascii'))
    print(f"Key: '{key}' = {key_bytes}")
    print(f"Portal: ({portal_x}, {portal_y})")

    # Test different iteration counts and angle moduli
    print("\n" + "=" * 80)
    print("EXPERIMENT 1: Reverse navigation with V3 spec formula")
    print("  angle = FV mod 360, hyp = 0.01 * byte/256")
    print("=" * 80)

    for n_iters in [5, 6, 7, 8]:
        fv = mandelbrot_fv(portal_x, portal_y, n_iters)
        print(f"\n  FV at portal (iter={n_iters}): {float(fv):.10f}")
        print(f"  FV mod 360 = {float(fv) % 360:.6f} degrees")

    # Reverse navigate with different parameters
    for n_iters in [5, 6, 7]:
        for angle_mod in [360]:
            path = reverse_navigate(portal_x, portal_y, key_bytes,
                                    n_iters=n_iters, angle_mod=angle_mod)
            entry_x, entry_y = path[0]
            print(f"\n  Reverse path (iter={n_iters}, mod={angle_mod}):")
            print(f"    Entry Portal: ({float(entry_x):.20f}, {float(entry_y):.20f})")
            print(f"    Final Portal: ({float(path[-1][0]):.20f}, {float(path[-1][1]):.20f})")

            # Verify by forward-navigating from the found entry
            fwd = forward_navigate(entry_x, entry_y, key_bytes,
                                   n_iters=n_iters, angle_mod=angle_mod)
            final_x, final_y = fwd[-1]
            err_x = abs(float(final_x - portal_x))
            err_y = abs(float(final_y - portal_y))
            print(f"    Forward check error: ({err_x:.2e}, {err_y:.2e})")

    # Also test with angle = FV mod prime (as found empirically for stream gen)
    print("\n" + "=" * 80)
    print("EXPERIMENT 2: Reverse navigation with FV mod prime")
    print("  (using prime 19, as confirmed for stream generation)")
    print("=" * 80)

    for n_iters in [5, 6, 7]:
        for prime in [19, 103, 167, 571]:
            path = reverse_navigate(portal_x, portal_y, key_bytes,
                                    n_iters=n_iters, angle_mod=prime)
            entry_x, entry_y = path[0]

            # Verify roundtrip
            fwd = forward_navigate(entry_x, entry_y, key_bytes,
                                   n_iters=n_iters, angle_mod=prime)
            err_x = abs(float(fwd[-1][0] - portal_x))
            err_y = abs(float(fwd[-1][1] - portal_y))
            print(f"  iter={n_iters}, prime={prime}: Entry=({float(entry_x):.15f}, {float(entry_y):.15f})"
                  f" err=({err_x:.2e}, {err_y:.2e})")

    # EXPERIMENT 3: Test SHA-512 of key and see what silo index it gives
    print("\n" + "=" * 80)
    print("EXPERIMENT 3: SHA-512 analysis of 'Secret99'")
    print("=" * 80)

    for hash_fn_name, hash_fn in [
        ("SHA-512", hashlib.sha512),
        ("SHA-256", hashlib.sha256),
        ("SHA-384", hashlib.sha384),
        ("SHA-1", hashlib.sha1),
        ("MD5", hashlib.md5),
    ]:
        h = hash_fn(key.encode()).hexdigest()
        # First 4 hex chars → silo index (2 bytes → 0..65535)
        idx_4hex = int(h[:4], 16)
        # First 8 hex chars → silo index if 4 bytes
        idx_8hex = int(h[:8], 16) % 65536
        print(f"  {hash_fn_name}('{key}') = {h[:32]}...")
        print(f"    First 4 hex chars = 0x{h[:4]} → silo idx = {idx_4hex}")
        print(f"    First 8 hex chars mod 65536 → silo idx = {idx_8hex}")
        print(f"    Offset x (hex[4:18]) = {h[4:18]}")
        print(f"    Offset y (hex[18:32]) = {h[18:32]}")

    # EXPERIMENT 4: Check navigation step sizes for "Secret99"
    print("\n" + "=" * 80)
    print("EXPERIMENT 4: Key navigation step analysis")
    print("=" * 80)

    n_iters = 6
    fv_portal = mandelbrot_fv(portal_x, portal_y, n_iters)
    print(f"  FV at portal (iter={n_iters}): {fv_portal}")

    for byte_val in key_bytes:
        hyp = 0.01 * byte_val / 256
        print(f"  Byte {byte_val:3d} ('{chr(byte_val)}'): hyp = {hyp:.8f}")

    # EXPERIMENT 5: Test key expansion hypothesis
    # If SHA-512("Secret99") gives the expanded key, and the first 2 bytes
    # give the silo index, then different keys sharing the same first 2 SHA-512 bytes
    # should share the same silo base vector (but different offsets)
    print("\n" + "=" * 80)
    print("EXPERIMENT 5: Hash function comparison via server probing")
    print("=" * 80)

    # Get streams for keys that share SHA-512 properties
    test_keys = ["Secret99", "Secret98", "Secret97", "a", "b", "ab", "abc"]
    for k in test_keys:
        sha512 = hashlib.sha512(k.encode()).hexdigest()
        sha256 = hashlib.sha256(k.encode()).hexdigest()
        try:
            result = fes_request(k, payload='A' * 4)
            ct = b64_decode(result.get("trans", ""))
            stream = list(reversed([c ^ 0x41 for c in ct]))
            print(f"  Key '{k:12s}': stream[:4]={stream[:4]}, "
                  f"sha512[:8]={sha512[:8]}, sha256[:8]={sha256[:8]}")
        except Exception as e:
            print(f"  Key '{k}': ERROR {e}")

    # EXPERIMENT 6: Verify if the key bytes are used directly for navigation
    # If we truncate or extend the key, the portal should change
    print("\n" + "=" * 80)
    print("EXPERIMENT 6: Key length sensitivity")
    print("=" * 80)

    # Keys that are prefixes/extensions of each other
    length_keys = ["S", "Se", "Sec", "Secr", "Secre", "Secret", "Secret9", "Secret99",
                   "Secret99x", "Secret99xy"]
    for k in length_keys:
        try:
            result = fes_request(k, payload='A' * 4)
            ct = b64_decode(result.get("trans", ""))
            stream = list(reversed([c ^ 0x41 for c in ct]))
            sha512_prefix = hashlib.sha512(k.encode()).hexdigest()[:8]
            print(f"  Key '{k:12s}' (len={len(k):2d}): stream[:4]={stream[:4]}, sha512[:8]={sha512_prefix}")
        except Exception as e:
            print(f"  Key '{k}': ERROR {e}")


if __name__ == "__main__":
    main()
