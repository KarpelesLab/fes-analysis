"""
Probe very large dimensions to find key material exhaustion.

If the KDF produces N bytes, then at some dimension count the server
must either: error, reuse material, or extend the hash chain.

dim=8 = 4 pairs, needs ~64 bytes (matches SHA-512 output)
dim=16 = 8 pairs, needs ~128 bytes (needs 2 SHA-512 outputs)
dim=32 = 16 pairs, needs ~256 bytes
dim=100 = 50 pairs, needs ~800 bytes

Tests:
1. Does the server accept very large dimensions?
2. XOR constant K across large dims — does it cycle?
3. Block structure still 14 bytes at large dims?
4. Stream comparison across large dims — any reuse?
5. Timing scaling with dimension (reveals KDF cost?)
"""

import base64
import json
import urllib.request
import urllib.parse
import time as time_mod

API_URL = "https://portalz.solutions/fes.dna"
HEADERS = {
    "Content-Type": "application/x-www-form-urlencoded",
    "Referer": "https://portalz.solutions/fractalTransform.html",
    "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36",
}


def get_stream(key, length, dimensions=8):
    data = urllib.parse.urlencode({
        "mode": "1", "key": key, "payload": 'A' * length, "trans": "",
        "dimensions": str(dimensions), "depth": "1", "scramble": "",
        "xor": "on", "whirl": "", "asciiRange": "256",
    }).encode()
    req = urllib.request.Request(API_URL, data=data, headers=HEADERS)
    start = time_mod.time()
    with urllib.request.urlopen(req, timeout=30) as resp:
        result = json.loads(resp.read())
    elapsed = time_mod.time() - start
    ct_b64 = result.get("trans", "")
    if not ct_b64:
        return None, elapsed
    padded = ct_b64 + '=' * (4 - len(ct_b64) % 4) if len(ct_b64) % 4 else ct_b64
    ct = base64.b64decode(padded)
    stream_rev = bytes(c ^ 0x41 for c in ct)
    return list(reversed(list(stream_rev))), elapsed


def get_xor_constant(stream):
    if not stream or len(stream) < 28:
        return None
    blocks = [stream[i:i+14] for i in range(0, len(stream) - 13, 14)]
    if len(blocks) < 2:
        return None
    xor_vals = [b[0] ^ b[13] for b in blocks]
    if len(set(xor_vals)) == 1:
        return xor_vals[0]
    return f"VARIES:{xor_vals}"


def main():
    key = "Secret99"

    # =========================================================================
    print("=" * 80)
    print("TEST 1: LARGE DIMENSION SUPPORT AND TIMING")
    print("=" * 80)

    print(f"\n  Key '{key}', payload=42 chars:")
    print(f"  {'dim':>6s}  {'pairs':>5s}  {'bytes_needed':>12s}  {'time_ms':>8s}  {'stream_len':>10s}  {'K':>6s}")

    k_values = {}
    for dim in [2, 4, 8, 10, 16, 20, 32, 50, 64, 100, 128, 200, 256, 500, 1000]:
        try:
            s, elapsed = get_stream(key, 42, dimensions=dim)
            if s:
                K = get_xor_constant(s)
                pairs = (dim + 1) // 2
                bytes_needed = pairs * 16  # estimated
                k_values[dim] = K
                print(f"  {dim:6d}  {pairs:5d}  {bytes_needed:12d}  {elapsed*1000:8.0f}  {len(s):10d}  {K}")
            else:
                print(f"  {dim:6d}  —  —  {elapsed*1000:8.0f}  NO STREAM")
        except Exception as e:
            print(f"  {dim:6d}  ERROR: {e}")
        time_mod.sleep(0.2)

    # =========================================================================
    print(f"\n{'=' * 80}")
    print("TEST 2: K VALUES — DO THEY CYCLE AT HIGH DIMS?")
    print("=" * 80)

    # Collect K for consecutive even dimensions
    print(f"\n  Key '{key}', consecutive dims:")
    prev_k = None
    for dim in range(2, 52, 2):
        s, _ = get_stream(key, 42, dimensions=dim)
        if s:
            K = get_xor_constant(s)
            delta_k = f"  ΔK={prev_k ^ K}" if prev_k is not None and isinstance(K, int) and isinstance(prev_k, int) else ""
            print(f"    dim={dim:3d}: K={K}{delta_k}")
            if isinstance(K, int):
                prev_k = K
        time_mod.sleep(0.15)

    # =========================================================================
    print(f"\n{'=' * 80}")
    print("TEST 3: STREAM COMPARISON — HIGH DIMS vs LOW DIMS")
    print("=" * 80)

    # Get streams at various dims and check overlap
    streams = {}
    for dim in [8, 16, 32, 64]:
        s, _ = get_stream(key, 42, dimensions=dim)
        if s:
            streams[dim] = s
        time_mod.sleep(0.2)

    for d1 in sorted(streams.keys()):
        for d2 in sorted(streams.keys()):
            if d1 >= d2:
                continue
            s1, s2 = streams[d1], streams[d2]
            min_len = min(len(s1), len(s2))
            matches = sum(1 for i in range(min_len) if s1[i] == s2[i])
            # Check block-by-block
            block_status = []
            for b in range(0, min_len - 13, 14):
                if s1[b:b+14] == s2[b:b+14]:
                    block_status.append("SAME")
                else:
                    block_status.append("DIFF")
            print(f"  dim={d1} vs dim={d2}: {matches}/{min_len} match  "
                  f"blocks=[{', '.join(block_status)}]")

    # =========================================================================
    print(f"\n{'=' * 80}")
    print("TEST 4: PER-PAIR K AT HIGH DIMS")
    print("=" * 80)

    # Compute per-pair K constants for higher dimensions
    print(f"\n  Key '{key}', per-pair K values:")
    prev_k_val = None
    for dim in range(2, 26, 2):
        s, _ = get_stream(key, 42, dimensions=dim)
        if not s:
            continue
        K = get_xor_constant(s)
        if isinstance(K, int):
            if prev_k_val is not None:
                k_pair = prev_k_val ^ K
                pair_idx = dim // 2 - 1
                print(f"    K_pair{pair_idx} = K(dim={dim-2}) XOR K(dim={dim}) = "
                      f"{prev_k_val} XOR {K} = {k_pair}")
            prev_k_val = K
        time_mod.sleep(0.15)

    # =========================================================================
    print(f"\n{'=' * 80}")
    print("TEST 5: DOES dim AFFECT THE BLOCK STRUCTURE?")
    print("=" * 80)

    for dim in [2, 8, 32, 100]:
        s, _ = get_stream(key, 70, dimensions=dim)
        if not s:
            print(f"  dim={dim}: no stream")
            continue

        # Check equal-adjacent-byte positions
        equal_pos = [i for i in range(len(s) - 1) if s[i] == s[i + 1]]
        print(f"  dim={dim:3d}: len={len(s)}  equal_adj_at={equal_pos[:10]}"
              f"{'...' if len(equal_pos) > 10 else ''}")
        time_mod.sleep(0.2)

    # =========================================================================
    print(f"\n{'=' * 80}")
    print("TEST 6: DIFFERENT KEY AT HIGH DIMS")
    print("=" * 80)

    for key2 in ["hello", "AB"]:
        print(f"\n  Key '{key2}':")
        for dim in [2, 8, 16, 32, 64]:
            s, elapsed = get_stream(key2, 42, dimensions=dim)
            if s:
                K = get_xor_constant(s)
                print(f"    dim={dim:3d}: K={K}  time={elapsed*1000:.0f}ms  "
                      f"stream[:7]={s[:7]}")
            time_mod.sleep(0.15)


if __name__ == "__main__":
    main()
