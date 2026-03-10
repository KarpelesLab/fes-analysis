"""
Probe server with different dimensions to understand stream structure.
If dim=2 (1 dimension pair) gives 12 bytes per iteration, the stream
structure might be clearer. Also test dim=4, dim=6.
"""

import base64
import json
import urllib.request
import urllib.parse
from collections import Counter

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


def b64_decode(s):
    padded = s + '=' * (4 - len(s) % 4) if len(s) % 4 else s
    return base64.b64decode(padded)


def get_stream(key, length, dimensions=8):
    known = 'A' * length
    result = fes_request(key, payload=known, dimensions=dimensions)
    ct_b64 = result.get("trans", "")
    if not ct_b64:
        return None
    ct = b64_decode(ct_b64)
    stream_rev = bytes(c ^ 0x41 for c in ct)
    return bytes(reversed(stream_rev))


def main():
    key = "Secret99"

    # Get streams at different dimensions
    print("=" * 80)
    print("STREAM COMPARISON ACROSS DIMENSIONS")
    print("=" * 80)

    for length in [48, 96]:
        print(f"\n  Payload length = {length}:")
        for dim in [2, 4, 6, 8, 10, 12]:
            try:
                stream = get_stream(key, length, dimensions=dim)
                if stream:
                    # Show first 24 bytes
                    print(f"    dim={dim:3d}: {list(stream[:24])}")
            except Exception as e:
                print(f"    dim={dim:3d}: ERROR {e}")

    # Detailed analysis of dim=8 stream at length 48
    print(f"\n{'=' * 80}")
    print("DETAILED dim=8 STREAM (length=96)")
    print("=" * 80)

    stream_96 = get_stream(key, 96, dimensions=8)
    if stream_96:
        print(f"  Full stream (96 bytes):")
        for i in range(0, len(stream_96), 12):
            chunk = list(stream_96[i:i+12])
            print(f"    [{i:3d}:{i+12:3d}] {chunk}")

        # Check for repeating patterns
        print(f"\n  Auto-correlation (check for period):")
        for period in [4, 6, 8, 12, 16, 24, 28, 48]:
            matches = 0
            total = 0
            for i in range(len(stream_96) - period):
                if stream_96[i] == stream_96[i + period]:
                    matches += 1
                total += 1
            if total > 0:
                print(f"    period={period:3d}: {matches}/{total} = {matches/total:.3f}")

        # Byte frequency
        print(f"\n  Byte value frequency (first 48):")
        freq = Counter(stream_96[:48])
        most_common = freq.most_common(10)
        print(f"    Most common: {most_common}")

        # Check if consecutive bytes have any relationship
        print(f"\n  Consecutive byte relationships (first 24):")
        for i in range(min(23, len(stream_96) - 1)):
            diff = (stream_96[i+1] - stream_96[i]) % 256
            xor = stream_96[i] ^ stream_96[i+1]
            print(f"    [{i:2d}→{i+1:2d}]: {stream_96[i]:3d} → {stream_96[i+1]:3d}  "
                  f"diff={diff:3d}  xor={xor:3d}")

    # Compare dim=2 streams at different lengths to find phase transitions
    print(f"\n{'=' * 80}")
    print("DIM=2 PHASE TRANSITIONS")
    print("=" * 80)

    prev_stream = None
    for length in range(10, 100, 2):
        try:
            stream = get_stream(key, length, dimensions=2)
            if stream and prev_stream:
                # Check if first byte changed
                if stream[0] != prev_stream[0]:
                    print(f"  TRANSITION at length {length}: "
                          f"stream[0] changed from {prev_stream[0]} to {stream[0]}")
                    print(f"    stream[:8] = {list(stream[:8])}")
            prev_stream = stream
        except Exception as e:
            print(f"  length={length}: ERROR {e}")

    # Get dim=2 stream at length 12 and compare with dim=8
    print(f"\n{'=' * 80}")
    print("DIM=2 vs DIM=8 STREAMS")
    print("=" * 80)

    for length in [12, 24, 36, 48]:
        s2 = get_stream(key, length, dimensions=2)
        s8 = get_stream(key, length, dimensions=8)
        if s2 and s8:
            print(f"\n  length={length}:")
            print(f"    dim=2: {list(s2[:min(24, length)])}")
            print(f"    dim=8: {list(s8[:min(24, length)])}")

            # XOR comparison
            xor_result = [a ^ b for a, b in zip(s2[:min(24, length)], s8[:min(24, length)])]
            print(f"    xor:   {xor_result}")


if __name__ == "__main__":
    main()
