"""
For each of the 12 stream bytes, search across ALL iterations (1-20) and
ALL digit counts (1-40) of ALL components (|z|, zx, zy, |z|²) at each
portal position to find which (iteration, component, digits) produces the
correct stream byte.
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


def frac_digits(val):
    """Get fractional digit string of |val|."""
    v = abs(val)
    frac = v - int(v)
    s = str(frac)
    return s.split('.')[1] if '.' in s else '0'


def main():
    # Get actual XOR stream at length 12
    result = fes_request("Secret99", payload='A' * 12)
    ct = b64_decode(result.get("trans", ""))
    stream = list(reversed([c ^ 0x41 for c in ct]))
    print(f"XOR stream (len=12): {stream}")

    # For each byte position, find ALL (iter, component, ndigits) matches
    print("\n" + "=" * 80)
    print("EXHAUSTIVE SEARCH: iter x component x digit_count")
    print("=" * 80)

    # First, compute all z values at all portal positions for all iterations
    all_z = {}  # (portal_idx, iter) -> (zx, zy)
    for pidx, (ch, fx_str, fy_str) in enumerate(PORTALS):
        cx = Decimal(fx_str)
        cy = Decimal(fy_str)
        zx, zy = Decimal(0), Decimal(0)
        for n in range(1, 16):
            zx, zy = zx * zx - zy * zy + cx, 2 * zx * zy + cy
            all_z[(pidx, n)] = (zx, zy)

    # For each stream byte, search
    for byte_idx in range(12):
        actual = stream[byte_idx]
        ch = PORTALS[byte_idx][0]
        print(f"\n  Byte [{byte_idx:2d}] '{ch}' = {actual:3d}:")

        found = []
        for n in range(1, 16):
            zx, zy = all_z[(byte_idx, n)]
            mag = (zx * zx + zy * zy).sqrt()
            mag_sq = zx * zx + zy * zy

            components = [
                ("|z|", mag),
                ("zx", abs(zx)),
                ("zy", abs(zy)),
                ("|z|²", mag_sq),
            ]

            for comp_name, comp_val in components:
                fd = frac_digits(comp_val)
                for nd in range(1, min(45, len(fd) + 1)):
                    cv = int(fd[:nd])
                    if cv % 256 == actual:
                        found.append((n, comp_name, nd, cv))
                        break  # Only first match per component per iter

        # Show matches, grouped by iteration
        if found:
            for n, comp, nd, cv in found[:15]:  # Limit output
                print(f"    iter={n:2d}, {comp:4s} frac[:{nd:2d}] = {cv} → {cv%256}")
        else:
            print(f"    NO MATCHES FOUND")

    # Now check: is there a CONSISTENT formula?
    # e.g., all bytes use the same (iter, component, ndigits)?
    print("\n" + "=" * 80)
    print("PATTERN SEARCH: Same (iter, component) for all bytes?")
    print("=" * 80)

    # For each (iter, component), check how many bytes match at ANY digit count
    for n in range(1, 12):
        for comp_name in ["|z|", "zx", "zy", "|z|²"]:
            match_count = 0
            match_details = []
            for byte_idx in range(12):
                actual = stream[byte_idx]
                zx, zy = all_z[(byte_idx, n)]
                if comp_name == "|z|":
                    val = (zx * zx + zy * zy).sqrt()
                elif comp_name == "zx":
                    val = abs(zx)
                elif comp_name == "zy":
                    val = abs(zy)
                else:
                    val = zx * zx + zy * zy

                fd = frac_digits(val)
                matched = False
                for nd in range(1, min(45, len(fd) + 1)):
                    cv = int(fd[:nd])
                    if cv % 256 == actual:
                        match_count += 1
                        match_details.append((byte_idx, nd))
                        matched = True
                        break

            if match_count >= 4:
                print(f"  iter={n:2d}, {comp_name:4s}: {match_count}/12 matches: {match_details}")

    # Check if the digit count follows a pattern
    print("\n" + "=" * 80)
    print("DIGIT COUNT PATTERN for iter=6, |z|")
    print("=" * 80)

    for byte_idx in range(12):
        actual = stream[byte_idx]
        ch = PORTALS[byte_idx][0]
        zx, zy = all_z[(byte_idx, 6)]
        mag = (zx * zx + zy * zy).sqrt()
        fd = frac_digits(mag)

        all_matches = []
        for nd in range(1, min(50, len(fd) + 1)):
            cv = int(fd[:nd])
            if cv % 256 == actual:
                all_matches.append(nd)

        print(f"  [{byte_idx:2d}] '{ch}': stream={actual:3d}, "
              f"digit counts that work: {all_matches[:10] if all_matches else 'NONE'}")

    # NEW: Check if ALL portal positions use the SAME portal (the initial one)
    # and different iterations give different bytes
    print("\n" + "=" * 80)
    print("TEST: All bytes from INITIAL portal, different iterations")
    print("=" * 80)

    cx0 = Decimal(PORTALS[0][1])
    cy0 = Decimal(PORTALS[0][2])

    zx, zy = Decimal(0), Decimal(0)
    for n in range(1, 20):
        zx, zy = zx * zx - zy * zy + cx0, 2 * zx * zy + cy0
        mag = (zx * zx + zy * zy).sqrt()
        fd = frac_digits(mag)

        # Check which stream byte(s) this iteration matches
        for byte_idx in range(12):
            actual = stream[byte_idx]
            for nd in range(1, min(20, len(fd) + 1)):
                cv = int(fd[:nd])
                if cv % 256 == actual:
                    print(f"  iter={n:2d}: |z| frac[:{nd}]={cv}, %256={cv%256} "
                          f"= stream[{byte_idx}]={actual} ('{PORTALS[byte_idx][0]}')")
                    break


if __name__ == "__main__":
    main()
