"""
Test whether 14-byte blocks are raw Re||Im fixed-point values (no mixing).

If blocks ARE raw extraction, then consecutive blocks represent consecutive
Mandelbrot iterations: z_{n+1} = z_n^2 + c

For fixed-point 7-byte (56-bit) signed values:
  Re(z_{n+1}) = Re(z_n)^2 - Im(z_n)^2 + Re(c)
  Im(z_{n+1}) = 2*Re(z_n)*Im(z_n) + Im(c)

Tests:
1. Interpret blocks as 56-bit signed fixed-point numbers
2. Check if Mandelbrot recurrence holds between consecutive blocks
3. If it holds, extract the portal c = (Re(c), Im(c))
4. Compare extracted portal with known portal for Secret99
"""

import base64
import json
import urllib.request
import urllib.parse
import time
from decimal import Decimal, getcontext

# High precision
getcontext().prec = 50

API_URL = "https://portalz.solutions/fes.dna"
HEADERS = {
    "Content-Type": "application/x-www-form-urlencoded",
    "Referer": "https://portalz.solutions/fractalTransform.html",
    "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36",
}


def fes_request(key, payload="", dimensions=8, scramble=""):
    data = urllib.parse.urlencode({
        "mode": "1", "key": key, "payload": payload, "trans": "",
        "dimensions": str(dimensions), "depth": "1", "scramble": scramble,
        "xor": "on", "whirl": "", "asciiRange": "256",
    }).encode()
    req = urllib.request.Request(API_URL, data=data, headers=HEADERS)
    with urllib.request.urlopen(req) as resp:
        return json.loads(resp.read())


def get_stream(key, length, dimensions=8):
    known = 'A' * length
    result = fes_request(key, payload=known, dimensions=dimensions)
    ct_b64 = result.get("trans", "")
    if not ct_b64:
        return None
    padded = ct_b64 + '=' * (4 - len(ct_b64) % 4) if len(ct_b64) % 4 else ct_b64
    ct = base64.b64decode(padded)
    stream_rev = bytes(c ^ 0x41 for c in ct)
    return list(reversed(list(stream_rev)))


def bytes_to_signed_int(byte_list):
    """Convert 7-byte big-endian to signed 56-bit integer."""
    val = 0
    for b in byte_list:
        val = (val << 8) | b
    # Sign extension (56-bit signed)
    if val >= (1 << 55):
        val -= (1 << 56)
    return val


def bytes_to_unsigned_int(byte_list):
    """Convert 7-byte big-endian to unsigned 56-bit integer."""
    val = 0
    for b in byte_list:
        val = (val << 8) | b
    return val


def int_to_fixed_point(val, int_bits=3, frac_bits=53):
    """Convert signed integer to fixed-point decimal.
    Assumes format: int_bits.frac_bits with sign.
    Total = 56 bits = 1 sign + int_bits + frac_bits (adjustable)
    """
    return Decimal(val) / Decimal(2 ** frac_bits)


def main():
    # =========================================================================
    print("=" * 80)
    print("TEST 1: INTERPRET BLOCKS AS SIGNED 56-BIT FIXED-POINT")
    print("=" * 80)

    key = "Secret99"

    # Use dim=2 for cleanest signal (single pair, no XOR combination)
    s = get_stream(key, 70, dimensions=2)
    time.sleep(0.3)

    if not s:
        print("  Failed to get stream")
        return

    blocks = [s[i:i+14] for i in range(0, len(s) - 13, 14)]
    print(f"\n  Key '{key}', dim=2, {len(blocks)} blocks:")

    # Try different fixed-point interpretations
    for label, int_bits in [("1.55 (range ±1)", 1), ("2.54 (range ±2)", 2),
                             ("3.53 (range ±4)", 3), ("4.52 (range ±8)", 4),
                             ("8.48 (range ±128)", 8)]:
        frac_bits = 56 - int_bits
        print(f"\n  === Fixed-point format: {label} ===")
        for bi, block in enumerate(blocks[:4]):
            re_bytes = block[:7]
            im_bytes = block[7:]
            re_int = bytes_to_signed_int(re_bytes)
            im_int = bytes_to_signed_int(im_bytes)
            re_fp = int_to_fixed_point(re_int, int_bits, frac_bits)
            im_fp = int_to_fixed_point(im_int, int_bits, frac_bits)
            print(f"    Block {bi}: Re={float(re_fp):>20.12f}  Im={float(im_fp):>20.12f}")

    # Also try unsigned interpretation
    print(f"\n  === Unsigned 56-bit / 2^48 (range 0-256) ===")
    for bi, block in enumerate(blocks[:4]):
        re_bytes = block[:7]
        im_bytes = block[7:]
        re_uint = bytes_to_unsigned_int(re_bytes)
        im_uint = bytes_to_unsigned_int(im_bytes)
        re_fp = Decimal(re_uint) / Decimal(2 ** 48)
        im_fp = Decimal(im_uint) / Decimal(2 ** 48)
        print(f"    Block {bi}: Re={float(re_fp):>20.12f}  Im={float(im_fp):>20.12f}")

    # =========================================================================
    print(f"\n{'=' * 80}")
    print("TEST 2: CHECK MANDELBROT RECURRENCE z_{n+1} = z_n^2 + c")
    print("=" * 80)

    # Try the 2.54 format (range ±2, common for Mandelbrot)
    # which means 2 integer bits + 54 fractional bits
    for int_bits in [2, 3, 4, 8]:
        frac_bits = 56 - int_bits
        scale = Decimal(2 ** frac_bits)

        print(f"\n  === Format: {int_bits}.{frac_bits} ===")

        z_values = []
        for block in blocks[:4]:
            re_int = bytes_to_signed_int(block[:7])
            im_int = bytes_to_signed_int(block[7:])
            re = Decimal(re_int) / scale
            im = Decimal(im_int) / scale
            z_values.append((re, im))

        # If z1 = z0^2 + c, then c = z1 - z0^2
        for i in range(len(z_values) - 1):
            re0, im0 = z_values[i]
            re1, im1 = z_values[i + 1]

            # z0^2 = (re0 + im0*j)^2 = (re0^2 - im0^2) + (2*re0*im0)*j
            re_sq = re0 * re0 - im0 * im0
            im_sq = 2 * re0 * im0

            # c = z1 - z0^2
            c_re = re1 - re_sq
            c_im = im1 - im_sq

            print(f"    z_{i} → z_{i+1}: c_re={float(c_re):>20.12f}  "
                  f"c_im={float(c_im):>20.12f}")

        # If c is constant (same for all transitions), the blocks are Mandelbrot iterates
        if len(z_values) >= 3:
            c_vals = []
            for i in range(len(z_values) - 1):
                re0, im0 = z_values[i]
                re1, im1 = z_values[i + 1]
                re_sq = re0 * re0 - im0 * im0
                im_sq = 2 * re0 * im0
                c_re = re1 - re_sq
                c_im = im1 - im_sq
                c_vals.append((c_re, c_im))

            # Check if c is constant
            if len(c_vals) >= 2:
                c_diff_re = abs(float(c_vals[0][0] - c_vals[1][0]))
                c_diff_im = abs(float(c_vals[0][1] - c_vals[1][1]))
                print(f"    c consistency: |Δc_re|={c_diff_re:.6e}  "
                      f"|Δc_im|={c_diff_im:.6e}"
                      f"  {'CONSISTENT!' if c_diff_re < 0.001 and c_diff_im < 0.001 else 'NOT consistent'}")

    # =========================================================================
    print(f"\n{'=' * 80}")
    print("TEST 3: KNOWN PORTAL COMPARISON")
    print("=" * 80)

    # Secret99 known portal: (-2.0890747618..., -0.0868059720...)
    # If the first block is z_0 (portal), check which format matches
    known_re = Decimal("-2.0890747618")
    known_im = Decimal("-0.0868059720")

    block0 = blocks[0]
    re_bytes = block0[:7]
    im_bytes = block0[7:]

    print(f"  Known portal: Re={float(known_re)}, Im={float(known_im)}")
    print(f"  Block 0 bytes: Re={re_bytes}  Im={im_bytes}")

    for int_bits in range(1, 16):
        frac_bits = 56 - int_bits
        scale = Decimal(2 ** frac_bits)
        re_int = bytes_to_signed_int(re_bytes)
        im_int = bytes_to_signed_int(im_bytes)
        re_fp = Decimal(re_int) / scale
        im_fp = Decimal(im_int) / scale

        re_diff = abs(float(re_fp - known_re))
        im_diff = abs(float(im_fp - known_im))

        if re_diff < 1.0 and im_diff < 1.0:
            print(f"    {int_bits}.{frac_bits}: Re={float(re_fp):>20.12f} "
                  f"(Δ={re_diff:.6f})  "
                  f"Im={float(im_fp):>20.12f} (Δ={im_diff:.6f})")

    # Also try unsigned with different base
    print(f"\n  Unsigned interpretations:")
    re_uint = bytes_to_unsigned_int(re_bytes)
    im_uint = bytes_to_unsigned_int(im_bytes)
    for divisor_exp in range(40, 58):
        scale = Decimal(10 ** (divisor_exp // 4)) * Decimal(2 ** (divisor_exp % 4))
        re_fp = Decimal(re_uint) / scale - Decimal(2)
        im_fp = Decimal(im_uint) / scale - Decimal(0)
        re_diff = abs(float(re_fp - known_re))
        im_diff = abs(float(im_fp - known_im))
        if re_diff < 0.1 and im_diff < 0.1:
            print(f"    divisor=10^{divisor_exp//4}*2^{divisor_exp%4}: "
                  f"Re={float(re_fp):.12f} Im={float(im_fp):.12f}"
                  f" (ΔRe={re_diff:.6f}, ΔIm={im_diff:.6f})")

    # =========================================================================
    print(f"\n{'=' * 80}")
    print("TEST 4: dim=8 — SAME ANALYSIS (XOR-COMBINED)")
    print("=" * 80)

    s8 = get_stream(key, 70, dimensions=8)
    if s8:
        blocks8 = [s8[i:i+14] for i in range(0, len(s8) - 13, 14)]
        print(f"\n  Key '{key}', dim=8, {len(blocks8)} blocks:")

        # Try 2.54 format
        int_bits = 2
        frac_bits = 54
        scale = Decimal(2 ** frac_bits)
        for bi, block in enumerate(blocks8[:4]):
            re_int = bytes_to_signed_int(block[:7])
            im_int = bytes_to_signed_int(block[7:])
            re_fp = Decimal(re_int) / scale
            im_fp = Decimal(im_int) / scale
            print(f"    Block {bi}: Re={float(re_fp):>20.12f}  Im={float(im_fp):>20.12f}")

        # Check Mandelbrot recurrence
        z8 = []
        for block in blocks8[:4]:
            re_int = bytes_to_signed_int(block[:7])
            im_int = bytes_to_signed_int(block[7:])
            z8.append((Decimal(re_int) / scale, Decimal(im_int) / scale))

        for i in range(len(z8) - 1):
            re0, im0 = z8[i]
            re1, im1 = z8[i + 1]
            re_sq = re0 * re0 - im0 * im0
            im_sq = 2 * re0 * im0
            c_re = re1 - re_sq
            c_im = im1 - im_sq
            print(f"    z_{i} → z_{i+1}: c_re={float(c_re):>20.12f}  "
                  f"c_im={float(c_im):>20.12f}")

    # =========================================================================
    print(f"\n{'=' * 80}")
    print("TEST 5: BLOCK[11]==BLOCK[12] IN FIXED-POINT CONTEXT")
    print("=" * 80)

    # block[11] = Im[4], block[12] = Im[5]
    # In a 7-byte Im value, bytes 4 and 5 are the 5th and 6th bytes (0-indexed)
    # i.e., bits 23-16 and bits 15-8 of the 56-bit value
    # If they're equal, it means those two bytes of Im are the same
    # If they differ by 128, bit 7 of byte 4 differs from bit 7 of byte 5

    print("\n  Im bytes analysis for dim=2, Secret99:")
    for bi, block in enumerate(blocks[:5]):
        im_bytes = block[7:]
        print(f"    Block {bi} Im bytes: {im_bytes}")
        print(f"      Im[4]={im_bytes[4]:3d} ({im_bytes[4]:08b})  "
              f"Im[5]={im_bytes[5]:3d} ({im_bytes[5]:08b})  "
              f"XOR={im_bytes[4] ^ im_bytes[5]:3d} ({im_bytes[4] ^ im_bytes[5]:08b})")


if __name__ == "__main__":
    main()
