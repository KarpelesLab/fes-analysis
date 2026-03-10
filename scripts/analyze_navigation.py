"""
Analyze the per-byte navigation steps from FT-Explained portal positions.

Compute:
1. Delta between consecutive portal positions → actual hypotenuse and angle
2. Compare actual angles against FV mod prime formula
3. Derive the hypotenuse formula from the actual step sizes
4. Test key mapping via differential server queries
"""

import base64
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

# FT-Explained table values (from page 18)
FT_ANGLES = [3.72743512971, 190.45487025943, 29.90974051886, 164.81948103772,
             329.63896207544, None, None, None, None, None, None, None]
# Only first 5 angles are clearly documented

FT_FV = 5874.727  # Approximate FV at all portal positions


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


def mandelbrot_z(cx, cy, n_iters):
    zx, zy = Decimal(0), Decimal(0)
    for _ in range(n_iters):
        zx, zy = zx * zx - zy * zy + cx, 2 * zx * zy + cy
    return zx, zy


def main():
    print("=" * 90)
    print("PART 1: Navigation deltas from FT-Explained portal positions")
    print("=" * 90)

    # Compute deltas between consecutive positions
    positions = [(Decimal(x), Decimal(y)) for _, x, y in PORTALS]

    print(f"\n{'From':>4} {'→':>1} {'To':>3} {'delta_x':>20} {'delta_y':>20} {'hyp':>15} {'angle(°)':>12}")
    print("-" * 80)

    hyps = []
    angles = []
    for i in range(len(positions) - 1):
        dx = float(positions[i+1][0] - positions[i][0])
        dy = float(positions[i+1][1] - positions[i][1])
        hyp = math.sqrt(dx*dx + dy*dy)
        angle_rad = math.atan2(dy, dx)
        angle_deg = math.degrees(angle_rad)
        if angle_deg < 0:
            angle_deg += 360

        hyps.append(hyp)
        angles.append(angle_deg)

        ch_from = PORTALS[i][0]
        ch_to = PORTALS[i+1][0]
        print(f"  {ch_from:>3} → {ch_to:>3}: dx={dx:+.15e} dy={dy:+.15e} "
              f"hyp={hyp:.8e} angle={angle_deg:.6f}°")

    # Compare angles with FT-Explained
    print(f"\n  Angle comparison with FT-Explained:")
    for i in range(min(5, len(angles))):
        if i < len(FT_ANGLES) and FT_ANGLES[i] is not None:
            # The FT-Explained angle at byte i is the ARRIVAL angle
            # The delta angle (from position i to i+1) should match the angle at position i+1
            print(f"    FT angle[{i}] = {FT_ANGLES[i]:15.8f}°, "
                  f"delta angle[{i}→{i+1}] = {angles[i]:15.8f}°")

    # Check: angle at byte[i+1] should be the navigation angle used at position i+1
    # Actually, the angle at position i is computed from FV at position i
    # And it's used to navigate FROM position i TO position i+1
    # So: delta angle from i to i+1 should match FT_ANGLES[i+1] (the angle at arrival position)

    # Wait - let me re-read FT-Explained. The angle for byte 'D' (position 0) is 3.727°.
    # This is the angle used to navigate FROM position 0 (byte 'D') to position 1 (byte 'e').
    # So delta[0→1] should match FT_ANGLES[0] = 3.727°.

    # But delta[0→1] computed above was the atan2 angle of the step vector.
    # Let me check if it matches.

    print(f"\n  Corrected comparison (angle at position i → step to i+1):")
    for i in range(min(5, len(angles))):
        if i < len(FT_ANGLES) and FT_ANGLES[i] is not None:
            # FT angle at position i should be the direction of the step from i to i+1
            ft_angle = FT_ANGLES[i]
            computed_angle = angles[i]
            diff = abs(ft_angle - computed_angle)
            if diff > 180:
                diff = 360 - diff
            match = "MATCH" if diff < 0.01 else f"DIFF={diff:.4f}°"
            print(f"    Step {i}→{i+1}: FT_angle={ft_angle:12.6f}° "
                  f"computed={computed_angle:12.6f}° {match}")

    # Analyze hypotenuse values
    print(f"\n  Hypotenuse values:")
    for i, h in enumerate(hyps):
        if i < len(PORTALS) - 1:
            ch = PORTALS[i][0]
            print(f"    Step {i} (from '{ch}'): hyp = {h:.15e}")

    # Check: is hypotenuse constant?
    print(f"\n  Hyp ratio analysis:")
    for i in range(1, len(hyps)):
        ratio = hyps[i] / hyps[0] if hyps[0] != 0 else 0
        print(f"    hyp[{i}]/hyp[0] = {ratio:.10f}")

    # Check: does hypotenuse relate to FV somehow?
    print(f"\n  Hypotenuse vs FV analysis:")
    for i in range(min(6, len(hyps))):
        cx, cy = positions[i]
        for n_iter in [5, 6]:
            zx, zy = mandelbrot_z(cx, cy, n_iter)
            fv_mag = float((zx * zx + zy * zy).sqrt())
            fv_sq = float(zx * zx + zy * zy)
            # Check various relationships
            if fv_sq > 0:
                # hyp = fv_sq mod something?
                # hyp = 1/fv_sq?
                # hyp = ms / fv_sq?
                ratio_sq = hyps[i] / fv_sq
                ratio_mag = hyps[i] / fv_mag
                print(f"    Step {i}, iter={n_iter}: hyp/FV²={ratio_sq:.6e}, "
                      f"hyp/|z|={ratio_mag:.6e}, "
                      f"hyp*FV²={hyps[i]*fv_sq:.6e}")

    # PART 2: Differential key testing
    print("\n" + "=" * 90)
    print("PART 2: Differential key testing (keys with common prefix)")
    print("=" * 90)

    # Keys "Secret9X" differ only in last character
    # If they share the same key mapping path through first 7 bytes,
    # only the last step differs
    print("\n  Keys 'Secret9X' for X = 0-9, a-f:")
    base_streams = {}
    for suffix in "0123456789abcdef":
        key = f"Secret9{suffix}"
        try:
            stream = extract_stream(key, 8)
            if stream:
                base_streams[suffix] = list(stream[:8])
                print(f"    '{key}': stream[:8]={list(stream[:8])}")
        except Exception as e:
            print(f"    '{key}': ERROR {e}")

    # Check if streams for similar keys have any pattern
    if '8' in base_streams and '9' in base_streams:
        s8 = base_streams['8']
        s9 = base_streams['9']
        xor_diff = [a ^ b for a, b in zip(s8, s9)]
        print(f"\n    XOR('Secret98', 'Secret99') = {xor_diff}")

    # PART 3: Test key mapping by trying different key lengths
    # that would change the number of navigation steps
    print("\n" + "=" * 90)
    print("PART 3: Empty key and minimal keys")
    print("=" * 90)

    for key in ["", "A", "AA", "AAA", "AAAA"]:
        try:
            stream = extract_stream(key, 4)
            if stream:
                print(f"  Key '{key:4s}' (len={len(key)}): stream[:4]={list(stream[:4])}")
        except Exception as e:
            print(f"  Key '{key}': ERROR {e}")

    # PART 4: Check if key "Secret99" and "Secret99" repeated gives same stream
    # (verify determinism and that all key bytes are used)
    print("\n" + "=" * 90)
    print("PART 4: Key repetition test")
    print("=" * 90)

    for key in ["Secret99", "Secret99Secret99", "99Secret", "99terceS"]:
        try:
            stream = extract_stream(key, 4)
            if stream:
                print(f"  Key '{key:20s}': stream[:4]={list(stream[:4])}")
        except Exception as e:
            print(f"  Key '{key}': ERROR {e}")


if __name__ == "__main__":
    main()
