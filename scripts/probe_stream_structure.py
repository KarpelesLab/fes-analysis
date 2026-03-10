"""
Probe stream structure to understand:
1. How many bytes per dimension pair per iteration
2. Phase transition intervals for different dimensions
3. How the fractal value maps to stream bytes
4. The byte extraction formula

Key finding so far: fractal value = |z_6| at the portal (magnitude at iteration 6)
But stream[0] for Secret99 is 215, not int(|z_6|) % 256 = 242.
"""

import base64
import hashlib
import json
import math
import sys
import time
import urllib.request
import urllib.parse

API_URL = "https://portalz.solutions/fes.dna"
HEADERS = {
    "Content-Type": "application/x-www-form-urlencoded",
    "Referer": "https://portalz.solutions/fractalTransform.html",
    "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36",
}


def fes_request(key, payload="", dimensions=8, scramble=False, depth=3):
    data = urllib.parse.urlencode({
        "mode": "1",
        "key": key,
        "payload": payload,
        "trans": "",
        "dimensions": str(dimensions),
        "depth": str(depth),
        "scramble": "on" if scramble else "",
        "xor": "on",
        "whirl": "",
        "asciiRange": "256",
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


def probe_phase_transitions_precise():
    """Find exact phase transitions for dim=2,4,6,8,10,12 to determine
    bytes per pair per phase."""
    print("=" * 70)
    print("PROBE 1: Phase Transition Intervals by Dimension")
    print("=" * 70)
    print("  (Looking for bytes_per_pair = transition_interval / num_pairs)")

    key = "SecretKey99"

    for dim in [2, 4, 6, 8, 10, 12]:
        pairs = dim // 2 if dim % 2 == 0 else (dim + 1) // 2
        print(f"\n  dim={dim} ({pairs} pairs):")

        prev_stream = None
        transitions = []

        for length in range(4, 200):
            stream = extract_stream(key, length, dimensions=dim)
            if stream is None:
                continue

            if prev_stream is not None:
                # Check if stream[0] changed
                if stream[0] != prev_stream[0]:
                    transitions.append(length)
                    if len(transitions) <= 5:
                        print(f"    TRANSITION at length {length}: "
                              f"stream[0] {prev_stream[0]} → {stream[0]}")

            prev_stream = stream
            time.sleep(0.03)

        if transitions:
            intervals = [transitions[i] - transitions[i-1]
                         for i in range(1, len(transitions))]
            print(f"    Transitions: {transitions[:8]}...")
            if intervals:
                print(f"    Intervals: {intervals[:8]}")
                avg_interval = sum(intervals) / len(intervals) if intervals else 0
                bpp = avg_interval / pairs if pairs else 0
                print(f"    Avg interval: {avg_interval:.1f}")
                print(f"    Bytes per pair: {bpp:.2f}")
        else:
            print(f"    No transitions found in range 4-200")


def probe_stream_stability():
    """For a fixed key and dim, check which stream bytes are stable
    (same value regardless of length) and which change at phase boundaries.

    Within a phase, stream[0] should be constant. This tells us the
    phase boundaries."""
    print("\n" + "=" * 70)
    print("PROBE 2: Stream Byte Stability Within Phases")
    print("=" * 70)

    key = "SecretKey99"
    dim = 8

    # Get streams for lengths 4 through 60
    streams = {}
    for length in range(4, 61):
        stream = extract_stream(key, length, dimensions=dim)
        if stream:
            streams[length] = stream
        time.sleep(0.03)

    # For each position, show the value across lengths
    print(f"\n  dim={dim}, key='{key}'")
    print(f"  Stream position values across lengths:")

    # Find phase boundaries
    phase_starts = [4]
    for length in range(5, 61):
        if length in streams and (length - 1) in streams:
            if streams[length][0] != streams[length-1][0]:
                phase_starts.append(length)

    print(f"  Phase starts: {phase_starts}")

    # Within each phase, check if the stream prefix is constant
    for p_idx in range(len(phase_starts)):
        p_start = phase_starts[p_idx]
        p_end = phase_starts[p_idx + 1] - 1 if p_idx + 1 < len(phase_starts) else 60

        print(f"\n  Phase {p_idx}: lengths {p_start}-{p_end}")

        # Get the stream at the start and end of the phase
        s_start = streams.get(p_start)
        s_end = streams.get(p_end)
        if s_start and s_end:
            # Find how many bytes from the start are identical
            common = 0
            for i in range(min(len(s_start), len(s_end))):
                if s_start[i] == s_end[i]:
                    common += 1
                else:
                    break
            print(f"    First {common} bytes stable across phase")
            print(f"    stream[0:12] at length={p_start}: {list(s_start[:12])}")
            print(f"    stream[0:12] at length={p_end}: {list(s_end[:12])}")

            # Check if ALL lengths in phase give same stream prefix
            all_same = True
            for l in range(p_start, p_end + 1):
                if l in streams:
                    for i in range(min(common, len(streams[l]))):
                        if streams[l][i] != s_start[i]:
                            all_same = False
                            break
            print(f"    All lengths in phase agree on prefix: {all_same}")


def probe_stream_byte_extraction():
    """Try to determine how stream bytes are extracted from Mandelbrot values.

    For Secret99, portal at (-2.0890747618..., -0.0868059720...)
    |z_6| = 5874.7274351297 (exact match with FT-Explained)

    Server stream[0:20] = [215, 27, 210, 179, 226, 199, 7, 46, 14, 223,
                            201, 97, 97, 134, 101, 95, 240, 25, 204, 122]

    Try to figure out which bytes come from which part of z.
    """
    print("\n" + "=" * 70)
    print("PROBE 3: Stream Byte Extraction Formula")
    print("=" * 70)

    from decimal import Decimal, getcontext
    getcontext().prec = 80

    cx = Decimal("-2.0890747618095770104082504287")
    cy = Decimal("-0.0868059720835475839205932798")

    # Compute Mandelbrot iterations
    zx = Decimal(0)
    zy = Decimal(0)

    for i in range(8):
        new_zx = zx * zx - zy * zy + cx
        new_zy = 2 * zx * zy + cy
        zx, zy = new_zx, new_zy

        # Show the full values
        if i >= 4:  # Focus on iterations 5-8
            print(f"\n  Iteration {i+1}:")
            print(f"    zx = {zx}")
            print(f"    zy = {zy}")

            # Extract various byte representations
            # The spec says fixed-point decimal arithmetic
            # "12 significant bytes per dimension per iteration"
            # "interpret Re and Im as signed fixed-point integers"

            # Try: take the mantissa of zx and zy
            # Remove the integer part, multiply by 10^N
            zx_frac = abs(zx) - int(abs(zx))
            zy_frac = abs(zy) - int(abs(zy))

            print(f"    |zx| frac = {zx_frac}")
            print(f"    |zy| frac = {zy_frac}")

            # Convert fractional parts to bytes
            # Method 1: multiply by 256^N and take bytes
            zx_bytes = []
            zy_bytes = []
            frac_x = zx_frac
            frac_y = zy_frac
            for j in range(8):
                frac_x *= 256
                frac_y *= 256
                zx_bytes.append(int(frac_x) % 256)
                zy_bytes.append(int(frac_y) % 256)
                frac_x -= int(frac_x)
                frac_y -= int(frac_y)

            print(f"    zx frac bytes: {zx_bytes}")
            print(f"    zy frac bytes: {zy_bytes}")

            # Method 2: full value as fixed-point
            # If the decimal has 28 digits, treat all digits as integer
            zx_str = str(abs(zx))
            zy_str = str(abs(zy))
            print(f"    zx_str: {zx_str[:40]}")
            print(f"    zy_str: {zy_str[:40]}")

    # Get actual server stream for comparison
    stream = extract_stream("Secret99", 20, dimensions=8)
    if stream:
        print(f"\n  Actual server stream (dim=8): {list(stream)}")

    # Also get dim=2 stream (only 1 pair, simpler)
    stream2 = extract_stream("Secret99", 20, dimensions=2)
    if stream2:
        print(f"  Actual server stream (dim=2): {list(stream2)}")

    # Get dim=4 and dim=6 for comparison
    for d in [4, 6]:
        s = extract_stream("Secret99", 20, dimensions=d)
        if s:
            print(f"  Actual server stream (dim={d}): {list(s)}")
        time.sleep(0.1)


def probe_stream_length_dependence():
    """Get streams of various lengths to see how bytes accumulate.

    Key question: for dim=2, does stream[0] at length=5 match stream[0]
    at length=10? If not, which iteration are they from?"""
    print("\n" + "=" * 70)
    print("PROBE 4: Stream Growth with Length")
    print("=" * 70)

    key = "Secret99"

    for dim in [2, 4, 8]:
        print(f"\n  dim={dim}:")
        streams = {}
        for length in [4, 5, 6, 7, 8, 10, 12, 14, 16, 20, 25, 30, 40]:
            stream = extract_stream(key, length, dimensions=dim)
            if stream:
                streams[length] = stream
                # Show first 8 and last 4 bytes
                prefix = list(stream[:8])
                suffix = list(stream[-4:]) if len(stream) >= 4 else []
                print(f"    len={length:3d}: first8={prefix}  last4={suffix}")
            time.sleep(0.05)

        # Check: is stream[0] the same across all lengths in same phase?
        if streams:
            first_vals = [(l, s[0]) for l, s in sorted(streams.items())]
            print(f"    stream[0] values: {first_vals}")


def probe_bytes_per_iteration():
    """Determine how many stream bytes come from each fractal iteration.

    Within a phase, the stream should grow by a fixed amount per iteration.
    If we look at how the stream at position P changes when we go from
    length N to length N+K, we can determine K = bytes per iteration.
    """
    print("\n" + "=" * 70)
    print("PROBE 5: Bytes Per Fractal Iteration")
    print("=" * 70)

    key = "TestKey42"

    for dim in [2, 8]:
        print(f"\n  dim={dim}:")
        # Get stream at various lengths within the first phase
        streams = {}
        for length in range(4, 45):
            stream = extract_stream(key, length, dimensions=dim)
            if stream:
                streams[length] = stream
            time.sleep(0.03)

        if not streams:
            continue

        # Find the first phase boundary
        phase_end = None
        for l in range(5, 45):
            if l in streams and (l-1) in streams:
                if streams[l][0] != streams[l-1][0]:
                    phase_end = l
                    break

        if phase_end:
            print(f"    First phase: 4 to {phase_end - 1}")
        else:
            print(f"    No phase transition found in range 4-44")
            phase_end = 45

        # Within the first phase, check if stream prefix grows
        # stream[0] should be the same. Does stream[N-1] (last byte) change?
        print(f"    Checking stream stability within first phase:")
        ref = streams.get(4)
        if not ref:
            continue

        for l in sorted(streams.keys()):
            if l >= phase_end:
                break
            s = streams[l]
            # Count how many bytes from position 0 match the reference
            common = 0
            for i in range(min(len(ref), len(s))):
                if ref[i] == s[i]:
                    common += 1
                else:
                    break
            # Also check: does stream[N-1] at length N equal anything at length N+1?
            print(f"    len={l:3d}: stream[0]={s[0]:3d}  "
                  f"common_with_len4={common}  "
                  f"last={s[-1]:3d}")


def main():
    tests = {
        "phase": probe_phase_transitions_precise,
        "stability": probe_stream_stability,
        "extraction": probe_stream_byte_extraction,
        "growth": probe_stream_length_dependence,
        "bpi": probe_bytes_per_iteration,
    }

    if len(sys.argv) > 1:
        selected = sys.argv[1:]
        if selected == ["all"]:
            selected = list(tests.keys())
    else:
        selected = ["extraction", "growth"]

    for name in selected:
        if name not in tests:
            print(f"Unknown test: {name}. Available: {', '.join(tests.keys())}")
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
