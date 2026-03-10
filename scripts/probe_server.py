"""
Advanced probing of the FES server to extract algorithm details.

Uses knowledge from the Peer Review Guide and other documents to:
1. Determine the number of passes and phase boundaries
2. Extract raw keystreams for analysis
3. Test the multi-dimensional stream extraction hypothesis
4. Probe FOTP and other parameters
5. Check if the stream extraction produces 12 bytes per dimension per iteration
"""

import base64
import urllib.request
import urllib.parse
import json
import sys
import time


API_URL = "https://portalz.solutions/fes.dna"
HEADERS = {
    "Content-Type": "application/x-www-form-urlencoded",
    "Referer": "https://portalz.solutions/fractalTransform.html",
    "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36",
}


def fes_request(key, payload="", trans="", dimensions=8, scramble=False,
                mode=1, xor=True, depth=3):
    """Call the live FES server."""
    data = urllib.parse.urlencode({
        "mode": str(mode),
        "key": key,
        "payload": payload,
        "trans": trans,
        "dimensions": str(dimensions),
        "depth": str(depth),
        "scramble": "on" if scramble else "",
        "xor": "on" if xor else "",
        "whirl": "",
        "asciiRange": "256",
    }).encode()
    req = urllib.request.Request(API_URL, data=data, headers=HEADERS)
    with urllib.request.urlopen(req) as resp:
        result = json.loads(resp.read())
    return result


def b64_decode(s):
    padded = s + '=' * (4 - len(s) % 4) if len(s) % 4 else s
    return base64.b64decode(padded)


def b64_encode(data):
    return base64.b64encode(data).rstrip(b'=').decode()


def extract_stream(key, length, dimensions=8, scramble=False, xor=True):
    """Extract the keystream by encrypting known plaintext."""
    known = 'A' * length
    result = fes_request(key, payload=known, dimensions=dimensions,
                         scramble=scramble, xor=xor)
    ct_b64 = result.get("trans", "")
    if not ct_b64:
        return None
    ct = b64_decode(ct_b64)
    # cipher[i] = pt[i] XOR stream[N-1-i]
    # stream[N-1-i] = cipher[i] XOR 0x41
    stream_rev = bytes(c ^ 0x41 for c in ct)
    return bytes(reversed(stream_rev))


def probe_phase_transitions():
    """Find exact phase transition boundaries for different dimension counts."""
    print("=" * 70)
    print("PROBE 1: Phase Transition Boundaries")
    print("=" * 70)

    key = "SecretKey99"

    for dim in [8, 12, 16]:
        print(f"\n  Dimensions = {dim}:")
        prev_stream = None
        transitions = []

        for length in range(4, 120):
            stream = extract_stream(key, length, dimensions=dim)
            if stream is None:
                continue

            if prev_stream is not None:
                # Check if stream[0] changed
                if stream[0] != prev_stream[0]:
                    transitions.append(length)
                    print(f"    TRANSITION at length {length}: "
                          f"stream[0] changed from {prev_stream[0]} to {stream[0]}")

            prev_stream = stream
            time.sleep(0.05)  # Rate limit

        print(f"    Transitions: {transitions}")
        if len(transitions) >= 2:
            intervals = [transitions[i] - transitions[i-1]
                         for i in range(1, len(transitions))]
            print(f"    Intervals: {intervals}")


def probe_stream_bytes_per_iteration():
    """Test if stream extraction produces 12 bytes per dimension per iteration.

    For dim=8 (4 pairs): 48 bytes per iteration
    For dim=12 (6 pairs): 72 bytes per iteration
    For dim=16 (8 pairs): 96 bytes per iteration

    Within a phase, if this is true, we'd expect certain patterns.
    """
    print("\n" + "=" * 70)
    print("PROBE 2: Bytes Per Iteration Analysis")
    print("=" * 70)

    key = "TestKeyAlpha"

    for dim in [8, 12, 16]:
        bytes_per_iter = (dim // 2) * 12
        print(f"\n  Dimensions = {dim} → expected {bytes_per_iter} bytes/iteration:")

        # Get a stream long enough to see patterns
        stream = extract_stream(key, 40, dimensions=dim)
        if stream is None:
            print("    Failed to extract stream")
            continue

        print(f"    Stream (first 48): {list(stream[:48])}")

        # Check if there's periodicity at bytes_per_iter boundaries
        if len(stream) >= 2 * bytes_per_iter:
            block1 = stream[:bytes_per_iter]
            block2 = stream[bytes_per_iter:2*bytes_per_iter]
            matching = sum(1 for a, b in zip(block1, block2) if a == b)
            print(f"    Block1 vs Block2 ({bytes_per_iter} bytes each): "
                  f"{matching}/{bytes_per_iter} match")

        time.sleep(0.1)


def probe_add_mode():
    """Test if add mode (XOR off) uses addition mod 256."""
    print("\n" + "=" * 70)
    print("PROBE 3: XOR=off Mode (Addition mod 256?)")
    print("=" * 70)

    key = "SecretKey99"
    length = 20

    # Extract with XOR on
    stream_xor = extract_stream(key, length, xor=True)

    # Try with XOR off - if it's addition, we need a different extraction
    known = 'A' * length
    result = fes_request(key, payload=known, xor=False)
    ct_b64 = result.get("trans", "")
    if not ct_b64:
        print("  Server returned empty for xor=off")
        return

    ct = b64_decode(ct_b64)

    # If addition: cipher[i] = (pt[i] + stream[N-1-i]) mod 256
    # stream[N-1-i] = (cipher[i] - pt[i]) mod 256
    stream_add_rev = bytes((c - 0x41) % 256 for c in ct)
    stream_add = bytes(reversed(stream_add_rev))

    # If XOR: stream[N-1-i] = cipher[i] XOR pt[i]
    stream_xor_rev = bytes(c ^ 0x41 for c in ct)
    stream_xor2 = bytes(reversed(stream_xor_rev))

    print(f"  XOR-on stream:  {list(stream_xor[:16])}")
    print(f"  XOR-off (as XOR): {list(stream_xor2[:16])}")
    print(f"  XOR-off (as ADD): {list(stream_add[:16])}")
    print(f"  XOR-on == XOR-off(XOR): {stream_xor == stream_xor2}")
    print(f"  XOR-on == XOR-off(ADD): {stream_xor == stream_add}")

    if stream_xor == stream_xor2:
        print("  >>> Server uses XOR regardless of the xor parameter!")
    elif stream_xor == stream_add:
        print("  >>> XOR-off mode uses addition mod 256 with same stream")
    else:
        print("  >>> XOR-off produces a completely different stream!")


def probe_depth_parameter():
    """Test if the depth parameter affects encryption."""
    print("\n" + "=" * 70)
    print("PROBE 4: Depth Parameter Effect")
    print("=" * 70)

    key = "SecretKey99"
    payload = "AAAAAAAAAA"

    results = {}
    for depth in [1, 2, 3, 5, 10, 50, 100, 256]:
        result = fes_request(key, payload=payload, depth=depth)
        ct = result.get("trans", "")
        results[depth] = ct
        print(f"  depth={depth:>3d}: ct={ct[:30]}...")
        time.sleep(0.05)

    unique = len(set(results.values()))
    print(f"\n  Unique ciphertexts: {unique}/{len(results)}")
    if unique == 1:
        print("  >>> Depth parameter has NO effect on encryption!")
    else:
        # Show which depths produce different results
        by_ct = {}
        for d, ct in results.items():
            by_ct.setdefault(ct, []).append(d)
        for ct, depths in by_ct.items():
            print(f"  Group: depths {depths}")


def probe_dimension_stream_relationship():
    """Check if different dimension counts produce related streams.

    If the stream is extracted from dimension pairs independently,
    dim=12 might contain dim=8's stream as a subset.
    """
    print("\n" + "=" * 70)
    print("PROBE 5: Cross-Dimension Stream Relationship")
    print("=" * 70)

    key = "SecretKey99"
    length = 32

    streams = {}
    for dim in [8, 10, 12, 16, 20]:
        stream = extract_stream(key, length, dimensions=dim)
        if stream:
            streams[dim] = stream
            print(f"  dim={dim:>2d}: stream[0:16] = {list(stream[:16])}")
        time.sleep(0.1)

    # Check pairwise relationships
    dims = sorted(streams.keys())
    for i in range(len(dims)):
        for j in range(i+1, len(dims)):
            d1, d2 = dims[i], dims[j]
            s1, s2 = streams[d1], streams[d2]
            matching = sum(1 for a, b in zip(s1, s2) if a == b)
            print(f"  dim={d1} vs dim={d2}: {matching}/{min(len(s1),len(s2))} bytes match")


def probe_fotp():
    """Test the FOTP (Filename/Session Portal Migration) parameter.

    The online demo might support this via an undiscovered form parameter.
    """
    print("\n" + "=" * 70)
    print("PROBE 6: FOTP Parameter Discovery")
    print("=" * 70)

    key = "SecretKey99"
    payload = "AAAAAAAAAA"

    # Try various parameter names that might be FOTP
    base_result = fes_request(key, payload=payload)
    base_ct = base_result.get("trans", "")
    print(f"  Baseline: {base_ct}")

    for param_name in ["fotp", "FOTP", "filename", "session", "salt", "nonce", "iv"]:
        data = urllib.parse.urlencode({
            "mode": "1",
            "key": key,
            "payload": payload,
            "trans": "",
            "dimensions": "8",
            "depth": "3",
            "scramble": "",
            "xor": "on",
            "whirl": "",
            "asciiRange": "256",
            param_name: "test_value",
        }).encode()
        req = urllib.request.Request(API_URL, data=data, headers=HEADERS)
        try:
            with urllib.request.urlopen(req) as resp:
                result = json.loads(resp.read())
            ct = result.get("trans", "")
            changed = "DIFFERENT!" if ct != base_ct else "same"
            print(f"  {param_name}='test_value': {changed}")
        except Exception as e:
            print(f"  {param_name}: error - {e}")
        time.sleep(0.05)


def probe_server_response_fields():
    """Check what fields the server returns (might contain debug info)."""
    print("\n" + "=" * 70)
    print("PROBE 7: Server Response Fields")
    print("=" * 70)

    key = "Secret99"
    payload = "Demo Payload"

    result = fes_request(key, payload=payload)
    print(f"  Full response for encrypt:")
    for k, v in sorted(result.items()):
        val_str = str(v)
        if len(val_str) > 80:
            val_str = val_str[:80] + "..."
        print(f"    {k}: {val_str}")

    # Try decrypt
    ct = result.get("trans", "")
    if ct:
        result2 = fes_request(key, trans=ct, mode=2)
        print(f"\n  Full response for decrypt:")
        for k, v in sorted(result2.items()):
            val_str = str(v)
            if len(val_str) > 80:
                val_str = val_str[:80] + "..."
            print(f"    {k}: {val_str}")


def probe_secret99_test_vector():
    """Validate the Secret99 / 'Demo Payload' test vector from FT-Explained.pdf."""
    print("\n" + "=" * 70)
    print("PROBE 8: Secret99 / 'Demo Payload' Test Vector")
    print("=" * 70)

    key = "Secret99"
    payload = "Demo Payload"

    # Encrypt on server
    result = fes_request(key, payload=payload)
    ct_b64 = result.get("trans", "")
    print(f"  Key: {key}")
    print(f"  Payload: {payload}")
    print(f"  Ciphertext (b64): {ct_b64}")

    if ct_b64:
        ct = b64_decode(ct_b64)
        print(f"  Ciphertext bytes: {list(ct)}")

        # Extract stream
        pt_bytes = payload.encode('utf-8')
        N = len(pt_bytes)
        stream_rev = bytes(c ^ p for c, p in zip(ct, pt_bytes))
        stream = bytes(reversed(stream_rev))
        print(f"  Extracted stream: {list(stream)}")

        # The FT-Explained.pdf says fractal value ≈ 5874.727
        # Stream byte should be 5874.727 mod 256 = 5874 mod 256 = 242
        # (since 5874 = 22*256 + 242)
        print(f"\n  Expected from FV≈5874: stream byte = 5874 mod 256 = {5874 % 256}")
        print(f"  Actual stream[0] = {stream[0]}")

        # If the fractal value is 5874.727, the integer part is 5874
        # But the "12 bytes per dimension" extraction is different from simple mod 256
        # Let's see what 5874.727 looks like in various extractions:
        fv = 5874.727
        print(f"\n  Fractal value analysis (FV = {fv}):")
        print(f"    FV mod 256 = {int(fv) % 256}")
        print(f"    FV mod 360 (angle) = {int(fv) % 360}")
        print(f"    int(frac(FV) * 1e15) mod 256 = {int((fv - int(fv)) * 1e15) % 256}")

    # Also try with add mode
    result_add = fes_request(key, payload=payload, xor=False)
    ct_add_b64 = result_add.get("trans", "")
    if ct_add_b64:
        ct_add = b64_decode(ct_add_b64)
        print(f"\n  Add mode ciphertext bytes: {list(ct_add)}")
        # If add: cipher[i] = (pt[i] + stream[N-1-i]) mod 256
        stream_add_rev = bytes((c - p) % 256 for c, p in zip(ct_add, pt_bytes))
        stream_add = bytes(reversed(stream_add_rev))
        print(f"  Add mode stream: {list(stream_add)}")


def main():
    tests = [
        ("phase", probe_phase_transitions),
        ("bytes_per_iter", probe_stream_bytes_per_iteration),
        ("add_mode", probe_add_mode),
        ("depth", probe_depth_parameter),
        ("cross_dim", probe_dimension_stream_relationship),
        ("fotp", probe_fotp),
        ("response", probe_server_response_fields),
        ("secret99", probe_secret99_test_vector),
    ]

    if len(sys.argv) > 1:
        selected = sys.argv[1:]
        tests = [(name, fn) for name, fn in tests if name in selected]
        if not tests:
            print(f"Available tests: {', '.join(name for name, _ in tests)}")
            sys.exit(1)

    for name, fn in tests:
        try:
            fn()
        except Exception as e:
            print(f"\n  ERROR in {name}: {e}")
        print()


if __name__ == "__main__":
    main()
