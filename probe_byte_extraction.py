"""
Probe stream byte extraction by:
1. Getting long streams for dim=2 (1 pair) at different lengths
2. Finding where individual pair bytes appear in multi-pair streams
3. Testing the Secret98 portal (second test vector from FT-Explained)
4. Testing the "cv as integer from fractional digits" hypothesis
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


def fes_request(key, payload="", dimensions=8, scramble=False, depth=3,
                xor=True, add=False, split=False):
    data = {
        "mode": "1",
        "key": key,
        "payload": payload,
        "trans": "",
        "dimensions": str(dimensions),
        "depth": str(depth),
        "scramble": "on" if scramble else "",
        "xor": "on" if xor else "",
        "whirl": "",
        "asciiRange": "256",
    }
    if add:
        data["add"] = "on"
    if split:
        data["split"] = "on"
    encoded = urllib.parse.urlencode(data).encode()
    req = urllib.request.Request(API_URL, encoded, headers=HEADERS)
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


def experiment_long_streams():
    """Get long streams for dim=2,4,6,8 and find byte interleaving pattern."""
    print("=" * 70)
    print("EXPERIMENT: Long Streams for Byte Interleaving Analysis")
    print("=" * 70)

    key = "Secret99"
    target_len = 42  # Within first phase for dim=2 (transitions at 44)

    streams = {}
    for dim in [2, 4, 6, 8]:
        stream = extract_stream(key, target_len, dimensions=dim)
        if stream:
            streams[dim] = list(stream)
            print(f"\n  dim={dim} ({target_len} bytes):")
            for i in range(0, len(stream), 7):
                chunk = list(stream[i:i+7])
                print(f"    [{i:2d}-{i+len(chunk)-1:2d}]: {chunk}")
        time.sleep(0.15)

    if not streams:
        return

    # Find shared bytes between dimensions at each position
    dims = sorted(streams.keys())
    print(f"\n  Position-by-position comparison:")
    print(f"  {'Pos':>4s}", end="")
    for d in dims:
        print(f"  dim={d:2d}", end="")
    print("  Shared?")

    for pos in range(target_len):
        vals = {}
        for d in dims:
            if pos < len(streams[d]):
                vals[d] = streams[d][pos]
        print(f"  {pos:4d}", end="")
        for d in dims:
            v = vals.get(d, None)
            print(f"  {v:6d}" if v is not None else "       ", end="")

        # Check which dimensions share the same value
        unique_vals = set(vals.values())
        if len(unique_vals) == 1:
            print("  ALL SAME", end="")
        else:
            groups = {}
            for d, v in vals.items():
                groups.setdefault(v, []).append(d)
            for v, ds in groups.items():
                if len(ds) > 1:
                    print(f"  dim{ds}={v}", end="")
        print()

    # Look for dim=2 bytes appearing in dim=4 at specific offsets
    s2 = streams.get(2, [])
    s4 = streams.get(4, [])
    if s2 and s4:
        print(f"\n  Searching for dim=2 bytes within dim=4 stream:")
        # Check every other position
        for stride in [2, 3, 4, 7, 14]:
            for offset in range(stride):
                extracted = s4[offset::stride][:len(s2)]
                match = sum(1 for a, b in zip(s2, extracted) if a == b)
                if match > 3:
                    print(f"    stride={stride} offset={offset}: "
                          f"{match}/{min(len(s2), len(extracted))} match")


def experiment_secret98_portal():
    """Test the Secret98 portal from FT-Explained.

    Known: key "Secret98", portal: x=-0.8740665189989865438765865,
                                    y=-0.6719779089859625926216622
    """
    print("\n" + "=" * 70)
    print("EXPERIMENT: Secret98 Portal Verification")
    print("=" * 70)

    cx = Decimal("-0.8740665189989865438765865")
    cy = Decimal("-0.6719779089859625926216622")

    print(f"  Portal: ({cx}, {cy})")

    # Compute Mandelbrot iterations
    zx, zy = Decimal(0), Decimal(0)
    for i in range(20):
        new_zx = zx * zx - zy * zy + cx
        new_zy = 2 * zx * zy + cy
        zx, zy = new_zx, new_zy
        mag_sq = float(zx * zx + zy * zy)
        mag = math.sqrt(mag_sq) if mag_sq > 0 else 0
        if mag_sq > 4 or i >= 6:
            print(f"  iter {i+1}: |z|²={mag_sq:.6f}  |z|={mag:.6f}")
            if mag_sq > 4:
                print(f"    ESCAPED at iteration {i+1}")
                break

    # Get server stream for Secret98
    print(f"\n  Getting server stream for Secret98:")
    for dim in [2, 8]:
        stream = extract_stream("Secret98", 20, dimensions=dim)
        if stream:
            print(f"    dim={dim}: {list(stream)}")
        time.sleep(0.1)

    # Compare SHA-512 of Secret98 vs Secret99
    for key in ["Secret98", "Secret99"]:
        sha = hashlib.sha512(key.encode()).digest()
        idx = (sha[0] << 8) | sha[1]
        print(f"\n  SHA-512('{key}'): idx={idx}, first bytes={sha[:8].hex()}")


def experiment_cv_integer_formula():
    """Test the spec's "make cv an integer by removing decimal point" formula.

    If FV = 5874.7274351297 and we "remove the decimal point keeping
    fractional digits", we get cv = 7274351297 (10 digits) or
    cv = 72743512970090... (more digits depending on precision).

    Then angle = cv mod prime, transform_byte = cv mod 256.
    """
    print("\n" + "=" * 70)
    print("EXPERIMENT: CV Integer Formula Test")
    print("=" * 70)

    cx = Decimal("-2.0890747618095770104082504287")
    cy = Decimal("-0.0868059720835475839205932798")

    zx, zy = Decimal(0), Decimal(0)
    for i in range(6):
        new_zx = zx * zx - zy * zy + cx
        new_zy = 2 * zx * zy + cy
        zx, zy = new_zx, new_zy

    mag = (zx * zx + zy * zy).sqrt()
    print(f"  |z_6| = {mag}")

    # Extract fractional digits
    frac = mag - int(mag)
    frac_str = str(frac)[2:]  # Remove "0."
    print(f"  Fractional part: 0.{frac_str}")
    print(f"  Fractional digits: {frac_str}")

    # Convert to integer (various precisions)
    for n_digits in [4, 7, 8, 10, 13, 15, 20, 28]:
        if n_digits <= len(frac_str):
            cv = int(frac_str[:n_digits])
            byte_val = cv % 256
            angle_mod360 = cv % 360
            print(f"  {n_digits} digits: cv={cv}, "
                  f"cv%256={byte_val}, cv%360={angle_mod360}, "
                  f"cv%19={cv%19}, cv%103={cv%103}")

    # Get actual server stream
    stream = extract_stream("Secret99", 20, dimensions=8)
    if stream:
        print(f"\n  Actual stream[0] = {stream[0]}")
        # Check which cv gives stream[0]
        for n_digits in range(1, 30):
            if n_digits <= len(frac_str):
                cv = int(frac_str[:n_digits])
                if cv % 256 == stream[0]:
                    print(f"  *** MATCH at {n_digits} digits: "
                          f"cv={cv}, cv%256={cv%256} == stream[0]={stream[0]}")

    # Also try with different z iterations
    zx, zy = Decimal(0), Decimal(0)
    for iter_n in range(1, 10):
        new_zx = zx * zx - zy * zy + cx
        new_zy = 2 * zx * zy + cy
        zx, zy = new_zx, new_zy

        if iter_n >= 5:
            for component in [("zx", zx), ("zy", zy), ("|z|", (zx*zx+zy*zy).sqrt()),
                              ("zx²+zy²", zx*zx+zy*zy)]:
                name, val = component
                val_abs = abs(val)
                frac_part = val_abs - int(val_abs)
                frac_digits = str(frac_part)[2:30] if frac_part > 0 else "0"
                for n_d in [7, 10, 13, 15]:
                    if n_d <= len(frac_digits):
                        cv = int(frac_digits[:n_d])
                        b = cv % 256
                        if stream and b == stream[0]:
                            print(f"  *** MATCH: iter={iter_n} {name}: "
                                  f"{n_d} frac digits → cv%256={b}")


def experiment_demo_payload_verification():
    """Encrypt "Demo Payload" with "Secret99" using ADD mode (as in FT-Explained)
    and verify against the expected transform values."""
    print("\n" + "=" * 70)
    print("EXPERIMENT: Demo Payload Verification")
    print("=" * 70)

    key = "Secret99"
    payload = "Demo Payload"

    # Get ciphertext with XOR mode (server default)
    result_xor = fes_request(key, payload=payload, dimensions=8)
    ct_xor = b64_decode(result_xor.get("trans", ""))
    pt_bytes = payload.encode()

    # Extract stream
    stream_rev = bytes(c ^ p for c, p in zip(ct_xor, pt_bytes))
    stream = bytes(reversed(stream_rev))

    print(f"  Payload: '{payload}' = {list(pt_bytes)}")
    print(f"  XOR ciphertext: {list(ct_xor)}")
    print(f"  Extracted stream (XOR): {list(stream)}")

    # Get ciphertext with ADD mode
    result_add = fes_request(key, payload=payload, dimensions=8, xor=False, add=True)
    ct_add = b64_decode(result_add.get("trans", ""))

    # If ADD: cipher[i] = (pt[i] + stream[N-1-i]) mod 256
    # Then stream[N-1-i] = (cipher[i] - pt[i]) mod 256
    stream_add_rev = bytes((c - p) % 256 for c, p in zip(ct_add, pt_bytes))
    stream_add = bytes(reversed(stream_add_rev))

    print(f"  ADD ciphertext: {list(ct_add)}")
    print(f"  Extracted stream (ADD): {list(stream_add)}")

    # Compare XOR and ADD streams
    print(f"  XOR stream == ADD stream: {stream == stream_add}")

    # FT-Explained shows FV values for each byte:
    # D: 5874.7274351297, e: 5874.7274364270, m: 5874.7274350390
    # If transform_byte = int(FV) mod 256 = 5874 mod 256 = 242
    # Then all transform bytes would be 242 (since int(FV) is always 5874)
    fv_mod256 = 5874 % 256
    print(f"\n  int(FV) mod 256 = {fv_mod256} for all bytes")
    print(f"  stream[0] = {stream[0]} ({'matches!' if stream[0] == fv_mod256 else 'DIFFERS'})")

    # Show the relationship between each stream byte and FV
    print(f"\n  Stream bytes vs 242 (5874 mod 256):")
    for i, s in enumerate(stream):
        diff = (s - fv_mod256) % 256
        print(f"    stream[{i:2d}] = {s:3d}  diff_from_242 = {diff:3d}  "
              f"(stream XOR 242 = {s ^ fv_mod256})")


def experiment_dim2_pair_consistency():
    """Get dim=2 stream for multiple keys and compare with their dim=4,8 tails.

    If pair 0 produces the dim=2 stream AND the tail of dim=4,8,
    the bytes should match (possibly at different positions).
    """
    print("\n" + "=" * 70)
    print("EXPERIMENT: dim=2 vs dim=4/8 Tail Consistency")
    print("=" * 70)

    keys = ["Secret99", "TestKey1", "probe_0001", "ABC", "xyz123"]

    for key in keys:
        print(f"\n  Key: '{key}'")
        streams = {}
        for dim in [2, 4, 8]:
            stream = extract_stream(key, 42, dimensions=dim)
            if stream:
                streams[dim] = list(stream)
                print(f"    dim={dim}: first7={list(stream[:7])} "
                      f"last7={list(stream[-7:])}")
            time.sleep(0.1)

        if 2 in streams and 4 in streams:
            s2 = streams[2]
            s4 = streams[4]
            # Check if dim=2 bytes appear anywhere in dim=4
            # Try: dim=2[i] == dim=4[2*i] (pair_0 at even positions)
            # Or: dim=2[i] == dim=4[i+N] (pair_0 at the end)
            # Or any other mapping
            for offset in range(len(s4)):
                match = 0
                pairs = 0
                for i in range(min(len(s2), len(s4) - offset)):
                    if s2[i] == s4[offset + i]:
                        match += 1
                    pairs += 1
                if match > 5 and pairs > 0:
                    pct = match / pairs * 100
                    print(f"    dim2[0:] vs dim4[{offset}:]: "
                          f"{match}/{pairs} match ({pct:.0f}%)")


def main():
    tests = {
        "long": experiment_long_streams,
        "secret98": experiment_secret98_portal,
        "cv": experiment_cv_integer_formula,
        "demo": experiment_demo_payload_verification,
        "pair": experiment_dim2_pair_consistency,
    }

    if len(sys.argv) > 1:
        selected = sys.argv[1:]
        if selected == ["all"]:
            selected = list(tests.keys())
    else:
        selected = ["cv", "demo"]

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
