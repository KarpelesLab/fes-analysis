"""
Analyze how streams from different dimension counts combine.
Test whether dim=2n = f(dim=2(n-1), pair_n) for XOR, ADD, or other combination.
Also verify whether key expansion is dimension-independent for common pairs.
"""

import base64
import json
import urllib.request
import urllib.parse

API_URL = "https://portalz.solutions/fes.dna"
HEADERS = {
    "Content-Type": "application/x-www-form-urlencoded",
    "Referer": "https://portalz.solutions/fractalTransform.html",
    "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36",
}


def fes_request(key, payload="", dimensions=8):
    data = urllib.parse.urlencode({
        "mode": "1", "key": key, "payload": payload, "trans": "",
        "dimensions": str(dimensions), "depth": "1", "scramble": "",
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
    ct = base64.b64decode(ct_b64 + '=' * (4 - len(ct_b64) % 4) if len(ct_b64) % 4 else ct_b64)
    stream_rev = bytes(c ^ 0x41 for c in ct)
    return list(reversed(list(stream_rev)))


def main():
    key = "Secret99"
    length = 24

    # Get streams for all even dimensions 2-16
    streams = {}
    for dim in [2, 4, 6, 8, 10, 12, 14, 16]:
        s = get_stream(key, length, dim)
        if s:
            streams[dim] = s
            print(f"dim={dim:2d}: {s[:16]}")

    print(f"\n{'='*80}")
    print("COMBINATION ANALYSIS: How do dimension pair contributions combine?")
    print(f"{'='*80}")

    # For each pair of consecutive dimensions, compute the "delta"
    for dim_a, dim_b in [(2, 4), (4, 6), (6, 8), (8, 10), (10, 12)]:
        if dim_a in streams and dim_b in streams:
            sa = streams[dim_a]
            sb = streams[dim_b]

            # Test XOR
            xor_delta = [a ^ b for a, b in zip(sa, sb)]
            # Test ADD mod 256
            add_delta = [(b - a) % 256 for a, b in zip(sa, sb)]
            # Test SUB mod 256
            sub_delta = [(a - b) % 256 for a, b in zip(sa, sb)]

            print(f"\n  dim={dim_a}→{dim_b}:")
            print(f"    XOR delta: {xor_delta[:16]}")
            print(f"    ADD delta: {add_delta[:16]}")
            print(f"    SUB delta: {sub_delta[:16]}")

            # Count zeros in each delta
            xor_zeros = sum(1 for x in xor_delta if x == 0)
            add_zeros = sum(1 for x in add_delta if x == 0)
            print(f"    XOR zeros: {xor_zeros}/{len(xor_delta)}, ADD zeros: {add_zeros}/{len(add_delta)}")

    # Test: does the combination reconstruct?
    # If dim=8 = combine(dim=2, pair2, pair3, pair4)
    # Test XOR reconstruction
    print(f"\n{'='*80}")
    print("RECONSTRUCTION TEST")
    print(f"{'='*80}")

    if 2 in streams and 4 in streams and 6 in streams and 8 in streams:
        s2, s4, s6, s8 = streams[2], streams[4], streams[6], streams[8]

        # XOR reconstruction: dim=8 should = dim=2 XOR delta24 XOR delta46 XOR delta68
        d24 = [a ^ b for a, b in zip(s2, s4)]
        d46 = [a ^ b for a, b in zip(s4, s6)]
        d68 = [a ^ b for a, b in zip(s6, s8)]

        # s2 XOR d24 = s4 (trivially true)
        # s2 XOR d24 XOR d46 = s6 (trivially true)
        # s2 XOR d24 XOR d46 XOR d68 = s8 (trivially true)
        # This is just s2 XOR (s2 XOR s4) XOR (s4 XOR s6) XOR (s6 XOR s8) = s8

        # More useful: check if deltas have structure
        print(f"  XOR deltas:")
        print(f"    d(2→4):  {d24[:16]}")
        print(f"    d(4→6):  {d46[:16]}")
        print(f"    d(6→8):  {d68[:16]}")

        # Check: are deltas related? (e.g., d46 = transform(d24)?)
        xor_d24_d46 = [a ^ b for a, b in zip(d24, d46)]
        xor_d46_d68 = [a ^ b for a, b in zip(d46, d68)]
        print(f"    d24⊕d46: {xor_d24_d46[:16]}")
        print(f"    d46⊕d68: {xor_d46_d68[:16]}")

    # Test with a DIFFERENT key to see if the cross-dimension pattern is key-dependent
    print(f"\n{'='*80}")
    print("CROSS-KEY COMPARISON")
    print(f"{'='*80}")

    for k in ["Secret99", "TestKey1", "abc"]:
        print(f"\n  Key: '{k}'")
        for dim in [2, 4, 6, 8]:
            try:
                s = get_stream(k, 16, dim)
                if s:
                    print(f"    dim={dim}: {s[:12]}")
            except Exception as e:
                print(f"    dim={dim}: ERROR {e}")

    # Test odd dimensions (does server accept them?)
    print(f"\n{'='*80}")
    print("ODD DIMENSION TEST")
    print(f"{'='*80}")

    for dim in [1, 3, 5, 7, 9]:
        try:
            s = get_stream(key, 12, dim)
            if s:
                print(f"  dim={dim}: {s[:12]}")
            else:
                print(f"  dim={dim}: empty response")
        except Exception as e:
            print(f"  dim={dim}: ERROR {e}")

    # Test: is dim=2 stream consistent with a single dimension pair?
    # If dim=2 = 1 pair, and each pair gives 12 bytes per iteration,
    # then a 12-byte payload needs exactly 1 iteration.
    # For a 24-byte payload, it needs 2 iterations.
    print(f"\n{'='*80}")
    print("DIM=2 STREAM LENGTH ANALYSIS")
    print(f"{'='*80}")

    for length in [6, 12, 13, 24, 25, 36, 48]:
        try:
            s = get_stream(key, length, 2)
            if s:
                print(f"  len={length:3d}: {s[:min(length, 24)]}")
        except Exception as e:
            print(f"  len={length}: ERROR {e}")


if __name__ == "__main__":
    main()
