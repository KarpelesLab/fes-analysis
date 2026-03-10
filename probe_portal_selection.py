"""
Probe the FES portal selection mechanism.

The spec says: Z_0 = Phi(Password, Config, Silo, FOTP)
- Password material selects from Silo S (2^16 entries) using 4 hex bytes per dimension pair
- Then adds x offset (14 hex bytes) and y offset (14 hex bytes)
- For dim=8: 4 dimension pairs, each needing 32 hex chars = 16 bytes
- Total: 64 bytes of key material for dim=8
- SHA-512 produces exactly 64 bytes -- suspicious match!

This script probes HOW the password produces these hex bytes.
"""

import base64
import json
import urllib.request
import urllib.parse
import time
import hashlib
import sys

API_URL = "https://portalz.solutions/fes.dna"
HEADERS = {
    "Content-Type": "application/x-www-form-urlencoded",
    "Referer": "https://portalz.solutions/fractalTransform.html",
    "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36",
}

call_count = 0


def fes_request(key, payload="", dimensions=8, scramble="", fotp="", depth="1"):
    """Call the live FES server to encrypt."""
    global call_count
    call_count += 1
    data = urllib.parse.urlencode({
        "mode": "1",
        "key": key,
        "payload": payload,
        "trans": "",
        "dimensions": str(dimensions),
        "depth": depth,
        "scramble": scramble,
        "xor": "on",
        "whirl": "",
        "asciiRange": "256",
        "FOTP": fotp,
    }).encode()
    req = urllib.request.Request(API_URL, data=data, headers=HEADERS)
    with urllib.request.urlopen(req) as resp:
        return json.loads(resp.read())


def get_stream(key, length, dimensions=8, fotp="", depth="1"):
    """Extract the keystream by encrypting known plaintext (all 'A's)."""
    known = 'A' * length
    result = fes_request(key, payload=known, dimensions=dimensions, fotp=fotp, depth=depth)
    ct_b64 = result.get("trans", "")
    if not ct_b64:
        return None
    padded = ct_b64 + '=' * (4 - len(ct_b64) % 4) if len(ct_b64) % 4 else ct_b64
    ct = base64.b64decode(padded)
    # cipher[i] = plaintext[i] XOR stream[N-1-i]
    stream_rev = bytes(c ^ 0x41 for c in ct)
    return list(reversed(list(stream_rev)))


def stream_diff(s1, s2):
    """Count differing bytes between two streams."""
    if s1 is None or s2 is None:
        return -1
    return sum(1 for a, b in zip(s1, s2) if a != b)


def stream_hex(s, n=32):
    """Show first n bytes of stream as hex."""
    if s is None:
        return "None"
    return ' '.join(f'{b:02x}' for b in s[:n])


def separator(title):
    print(f"\n{'='*70}")
    print(f"  {title}")
    print(f"{'='*70}\n")


# ============================================================================
#  TEST 1: Password length vs hex byte requirement
# ============================================================================

def test1_password_length():
    separator("TEST 1: Password Length vs Key Material Requirement")
    print("dim=8 needs 64 bytes of key material (4 pairs x 16 bytes each)")
    print("SHA-512 produces exactly 64 bytes. Coincidence?")
    print("Testing if all password lengths work and produce different streams.\n")

    test_keys = [
        ("a", "single char"),
        ("ab", "2 chars"),
        ("abcd", "4 chars"),
        ("abcdefgh", "8 chars"),
        ("a" * 16, "16 chars"),
        ("a" * 32, "32 chars"),
        ("a" * 64, "64 chars (= SHA-512 output size)"),
        ("a" * 100, "100 chars"),
        ("a" * 200, "200 chars"),
    ]

    length = 20  # stream extraction length
    streams = {}

    for key, desc in test_keys:
        s = get_stream(key, length, dimensions=8)
        streams[key] = s
        print(f"  key={desc:40s} stream: {stream_hex(s, 20)}")
        time.sleep(0.25)

    # Check that all single-char-repeated keys differ (proving hashing happens)
    print(f"\n  All streams are unique: {len(set(tuple(s) for s in streams.values() if s)) == len(streams)}")

    # Check: does "a"*64 == "a"*100? (they shouldn't, but if raw truncation happened...)
    d = stream_diff(streams["a" * 64], streams["a" * 100])
    print(f"  'a'*64 vs 'a'*100 differ in {d}/{length} bytes (should differ if hashed)")

    return streams


# ============================================================================
#  TEST 2: SHA-512 chain hypothesis
# ============================================================================

def test2_sha512_chain():
    separator("TEST 2: SHA-512 Chain Hypothesis")
    print("Testing if key_material = SHA512(password) or iterated SHA512.")
    print("We can't verify the silo lookup, but we can check if keys with")
    print("identical SHA-512 prefixes produce related streams.\n")

    key = "Secret99"
    sha = hashlib.sha512(key.encode()).digest()
    print(f"  SHA-512('{key}') = {sha.hex()}")
    print(f"  Length: {len(sha)} bytes (exactly 64 -- matches dim=8 requirement!)")

    # Show the hypothetical partition
    print(f"\n  Hypothetical dim=8 partition (4 pairs x 16 bytes):")
    for i in range(4):
        chunk = sha[i*16:(i+1)*16]
        silo_idx = int.from_bytes(chunk[0:2], 'big') % 65536
        x_offset = chunk[2:9].hex()
        y_offset = chunk[9:16].hex()
        print(f"    Pair {i}: silo={silo_idx:5d}  x_off=0x{x_offset}  y_off=0x{y_offset}")

    # Test iterated SHA-512
    print(f"\n  Testing iterated SHA-512:")
    h = key.encode()
    for i in range(5):
        h = hashlib.sha512(h).digest()
        print(f"    SHA512^{i+1}('{key}') = {h[:16].hex()}...")

    # Now test: does appending config to the hash input matter?
    print(f"\n  SHA-512 with config appended:")
    variants = [
        ("Secret99", "raw password"),
        ("Secret998", "password + dim"),
        ("Secret99_8", "password + '_' + dim"),
        ("8Secret99", "dim + password"),
    ]
    for v, desc in variants:
        h = hashlib.sha512(v.encode()).digest()
        print(f"    SHA512('{desc}') = {h[:16].hex()}...")


# ============================================================================
#  TEST 3: Per-byte password sensitivity across dimensions
# ============================================================================

def test3_byte_sensitivity():
    separator("TEST 3: Per-Byte Password Sensitivity")
    print("If key material is hashed, changing ANY byte should change ALL stream bytes.")
    print("If key bytes map directly to dimension pairs, changes might be localized.\n")

    base_key = "abcdefgh"
    length = 20

    # Get base streams at dim=2 and dim=8
    print("  Getting base streams...")
    base_d2 = get_stream(base_key, length, dimensions=2)
    time.sleep(0.25)
    base_d8 = get_stream(base_key, length, dimensions=8)
    time.sleep(0.25)
    base_d10 = get_stream(base_key, length, dimensions=10)
    time.sleep(0.25)

    print(f"  Base '{base_key}' dim=2:  {stream_hex(base_d2, 20)}")
    print(f"  Base '{base_key}' dim=8:  {stream_hex(base_d8, 20)}")
    print(f"  Base '{base_key}' dim=10: {stream_hex(base_d10, 20)}")

    # Change each byte position and measure impact
    print(f"\n  Changing each byte of '{base_key}' to uppercase:")
    print(f"  {'Variant':20s} {'dim=2 diff':>12s} {'dim=8 diff':>12s} {'dim=10 diff':>12s}")
    print(f"  {'-'*20} {'-'*12} {'-'*12} {'-'*12}")

    for pos in range(len(base_key)):
        variant = list(base_key)
        variant[pos] = variant[pos].upper()
        variant = ''.join(variant)

        s2 = get_stream(variant, length, dimensions=2)
        time.sleep(0.25)
        s8 = get_stream(variant, length, dimensions=8)
        time.sleep(0.25)
        s10 = get_stream(variant, length, dimensions=10)
        time.sleep(0.25)

        d2 = stream_diff(base_d2, s2)
        d8 = stream_diff(base_d8, s8)
        d10 = stream_diff(base_d10, s10)

        print(f"  {variant:20s} {d2:>8d}/{length:<3d} {d8:>8d}/{length:<3d} {d10:>8d}/{length:<3d}")

    print(f"\n  If ALL bytes change for every single-char mutation → hashing (avalanche effect)")
    print(f"  If only SOME bytes change → direct byte mapping to dimension pairs")


# ============================================================================
#  TEST 4: SHA-512 partitioning — same silo index test
# ============================================================================

def test4_silo_index():
    separator("TEST 4: SHA-512 Silo Index Collision Test")
    print("If SHA512(password) is split into chunks, and first 2 bytes → silo index,")
    print("then passwords whose SHA512 shares the first 2 bytes of a chunk should")
    print("produce portals from the SAME silo entry.\n")

    # Find pairs of passwords with same SHA-512 prefix bytes
    # This is hard to brute force, so instead test a different approach:
    # Check if the stream changes in a structured way when we vary keys

    # Instead: compare stream correlation structure
    print("  Approach: Compare stream structure across many simple keys.")
    print("  If SHA-512 partitioning is used, the portal for each pair is:")
    print("    silo[sha[0:2]] + offsets_from_sha[2:16]")
    print("  Since silo entries are presumably spaced across the Mandelbrot set,")
    print("  keys with different silo indices should produce completely unrelated streams.\n")

    keys = ["key01", "key02", "key03", "key04", "key05",
            "key06", "key07", "key08", "key09", "key10"]
    length = 20
    streams = {}

    for k in keys:
        sha = hashlib.sha512(k.encode()).digest()
        silo_idx = int.from_bytes(sha[0:2], 'big') % 65536
        s = get_stream(k, length, dimensions=8)
        streams[k] = s
        print(f"  {k}: SHA512 prefix={sha[:4].hex()} hypothetical_silo={silo_idx:5d}  stream={stream_hex(s, 16)}")
        time.sleep(0.25)

    # Cross-correlation: are any streams related?
    print(f"\n  Pairwise stream differences (out of {length} bytes):")
    key_list = list(keys)
    for i in range(len(key_list)):
        for j in range(i + 1, len(key_list)):
            d = stream_diff(streams[key_list[i]], streams[key_list[j]])
            if d < length * 0.5:  # notable similarity
                print(f"    {key_list[i]} vs {key_list[j]}: {d}/{length} SIMILAR!")
            # Only print notable ones to reduce noise


# ============================================================================
#  TEST 5: Config binding — does dimension string enter the hash?
# ============================================================================

def test5_config_binding():
    separator("TEST 5: Config Binding — Dimension in Hash Input")
    print("Z_0 = Phi(Password, Config, ...) — Config includes dimensions.")
    print("Test: is the dimension number part of the hash input?\n")

    key = "TestKey42"
    length = 16

    # Get streams at different dimensions
    dims = [2, 4, 6, 8, 10, 12, 14]
    streams = {}

    for d in dims:
        s = get_stream(key, length, dimensions=d)
        streams[d] = s
        print(f"  dim={d:2d}: {stream_hex(s, 16)}")
        time.sleep(0.25)

    # Check: do any dimension pairs share stream tails? (we know dim>=10 share tails)
    print(f"\n  Pairwise differences:")
    for i in range(len(dims)):
        for j in range(i + 1, len(dims)):
            d1, d2_val = dims[i], dims[j]
            diff = stream_diff(streams[d1], streams[d2_val])
            tag = ""
            if diff < length * 0.5:
                tag = " *** SIMILAR ***"
            if diff == 0:
                tag = " *** IDENTICAL ***"
            print(f"    dim={d1:2d} vs dim={d2_val:2d}: {diff:2d}/{length} bytes differ{tag}")

    # Test if dimension enters the SHA-512 input
    print(f"\n  SHA-512 with dimension in input:")
    for d in dims:
        h1 = hashlib.sha512(f"{key}{d}".encode()).hexdigest()[:32]
        h2 = hashlib.sha512(f"{key}_{d}".encode()).hexdigest()[:32]
        h3 = hashlib.sha512(f"{d}_{key}".encode()).hexdigest()[:32]
        print(f"    dim={d:2d}: SHA512(key+dim)={h1}  SHA512(key_dim)={h2}")


# ============================================================================
#  TEST 6: FOTP binding
# ============================================================================

def test6_fotp_binding():
    separator("TEST 6: FOTP Binding Test")
    print("Spec says FOTP is part of Phi. We know FOTP is boolean (any >=2 chars → same).")
    print("Test: does FOTP affect the hash input, and can we predict the alternate stream?\n")

    key = "Secret99"
    length = 20

    s_no_fotp = get_stream(key, length, fotp="")
    time.sleep(0.25)
    s_fotp_ab = get_stream(key, length, fotp="ab")
    time.sleep(0.25)
    s_fotp_xy = get_stream(key, length, fotp="xy")
    time.sleep(0.25)
    s_fotp_long = get_stream(key, length, fotp="this_is_a_long_fotp_value")
    time.sleep(0.25)

    print(f"  No FOTP:     {stream_hex(s_no_fotp, 20)}")
    print(f"  FOTP='ab':   {stream_hex(s_fotp_ab, 20)}")
    print(f"  FOTP='xy':   {stream_hex(s_fotp_xy, 20)}")
    print(f"  FOTP='long': {stream_hex(s_fotp_long, 20)}")

    d1 = stream_diff(s_no_fotp, s_fotp_ab)
    d2 = stream_diff(s_fotp_ab, s_fotp_xy)
    d3 = stream_diff(s_fotp_ab, s_fotp_long)

    print(f"\n  no_fotp vs fotp='ab':   {d1}/{length} bytes differ")
    print(f"  fotp='ab' vs fotp='xy': {d2}/{length} bytes differ")
    print(f"  fotp='ab' vs fotp='long': {d3}/{length} bytes differ")

    if d2 == 0 and d3 == 0:
        print("  CONFIRMED: All FOTP values produce identical stream (boolean behavior)")

    # Test if SHA512(key + "fotp_flag") matches
    print(f"\n  SHA-512 with FOTP flag:")
    h_plain = hashlib.sha512(key.encode()).hexdigest()[:32]
    h_fotp1 = hashlib.sha512((key + "1").encode()).hexdigest()[:32]
    h_fotp_true = hashlib.sha512((key + "true").encode()).hexdigest()[:32]
    h_fotp_on = hashlib.sha512((key + "on").encode()).hexdigest()[:32]
    print(f"    SHA512('{key}')         = {h_plain}")
    print(f"    SHA512('{key}1')        = {h_fotp1}")
    print(f"    SHA512('{key}true')     = {h_fotp_true}")
    print(f"    SHA512('{key}on')       = {h_fotp_on}")
    print(f"  (These are hypothetical; we can't verify without the silo table)")


# ============================================================================
#  TEST 7: Key material exhaustion — dim=2 vs dim=8 sensitivity
# ============================================================================

def test7_key_material_exhaustion():
    separator("TEST 7: Key Material Exhaustion Across Dimensions")
    print("dim=2 needs only 16 bytes of key material (1 pair).")
    print("dim=8 needs 64 bytes (4 pairs).")
    print("If SHA-512 is used: dim=2 uses bytes[0:16], dim=8 uses all 64.")
    print("Question: do dim=2 and dim=8 share the FIRST dimension pair?\n")

    key = "SharedPairTest"
    length = 20

    s2 = get_stream(key, length, dimensions=2)
    time.sleep(0.25)
    s4 = get_stream(key, length, dimensions=4)
    time.sleep(0.25)
    s8 = get_stream(key, length, dimensions=8)
    time.sleep(0.25)

    print(f"  dim=2:  {stream_hex(s2, 20)}")
    print(f"  dim=4:  {stream_hex(s4, 20)}")
    print(f"  dim=8:  {stream_hex(s8, 20)}")

    # XOR streams to look for patterns
    if s2 and s8:
        xor_2_8 = [a ^ b for a, b in zip(s2, s8)]
        print(f"\n  dim=2 XOR dim=8: {stream_hex(xor_2_8, 20)}")
        print(f"  (If all zeros → identical streams → same first pair)")
        print(f"  (If random → completely different generation)")

    if s2 and s4:
        xor_2_4 = [a ^ b for a, b in zip(s2, s4)]
        print(f"  dim=2 XOR dim=4: {stream_hex(xor_2_4, 20)}")

    if s4 and s8:
        xor_4_8 = [a ^ b for a, b in zip(s4, s8)]
        print(f"  dim=4 XOR dim=8: {stream_hex(xor_4_8, 20)}")

    # Check if any pairs have byte-level correlations
    if s2 and s8:
        matches = sum(1 for a, b in zip(s2, s8) if a == b)
        expected = length / 256  # random expectation
        print(f"\n  dim=2 vs dim=8: {matches}/{length} bytes match (random expectation: ~{expected:.1f})")


# ============================================================================
#  TEST 8: Dimension pair count vs SHA iterations
# ============================================================================

def test8_dim_pair_hash_iterations():
    separator("TEST 8: Dimension Pairs and Hash Iteration Count")
    print("The spec says 'iterations of SHA-512 hashes'. Maybe each pair needs")
    print("a separate SHA-512 iteration? i.e.:")
    print("  pair_0 = SHA512(password + config + '0')")
    print("  pair_1 = SHA512(password + config + '1')")
    print("  etc.")
    print("Or maybe: pair_n = SHA512^(n+1)(password + config)\n")

    key = "IterTest"

    # Show iterated SHA-512 values
    h = hashlib.sha512(key.encode()).digest()
    print(f"  SHA512^1('{key}') = {h.hex()[:64]}...")
    for i in range(2, 6):
        h = hashlib.sha512(h).digest()
        print(f"  SHA512^{i}('{key}') = {h.hex()[:64]}...")

    # Show SHA-512 with counter appended
    print()
    for i in range(5):
        h = hashlib.sha512(f"{key}{i}".encode()).digest()
        print(f"  SHA512('{key}{i}') = {h.hex()[:64]}...")

    # Show SHA-512 with dim appended
    print()
    for d in [2, 4, 6, 8]:
        h = hashlib.sha512(f"{key}{d}".encode()).digest()
        print(f"  SHA512('{key}{d}') = {h.hex()[:64]}...")

    print(f"\n  Note: Without the silo table, we cannot directly verify which")
    print(f"  SHA-512 scheme maps to the observed portals. But the 64-byte")
    print(f"  match for dim=8 is highly suggestive of single SHA-512.")


# ============================================================================
#  TEST 9: Prefix stability — does extending the key preserve stream prefix?
# ============================================================================

def test9_prefix_stability():
    separator("TEST 9: Prefix Stability Under Key Extension")
    print("If key material is SHA512(password), changing password changes everything.")
    print("If key material is raw bytes (padded), extending might preserve prefix.\n")

    length = 20
    base = "test"
    extensions = ["test", "test1", "test12", "test123", "test1234",
                  "testAAAA", "testBBBB"]

    streams = {}
    for k in extensions:
        s = get_stream(k, length, dimensions=8)
        streams[k] = s
        print(f"  key='{k:12s}': {stream_hex(s, 20)}")
        time.sleep(0.25)

    # Check if extending preserves any prefix bytes
    base_stream = streams["test"]
    print(f"\n  Differences from base 'test':")
    for k in extensions[1:]:
        d = stream_diff(base_stream, streams[k])
        # Check first N bytes
        if streams[k] and base_stream:
            prefix_match = 0
            for a, b in zip(base_stream, streams[k]):
                if a == b:
                    prefix_match += 1
                else:
                    break
            print(f"    '{k}': {d}/{length} differ, longest prefix match: {prefix_match} bytes")

    print(f"\n  If prefix match > 0: raw bytes might be used (no hashing)")
    print(f"  If all ~{length} bytes differ: avalanche effect confirms hashing")


# ============================================================================
#  TEST 10: Higher dimensions — does dim>8 need more than 64 bytes?
# ============================================================================

def test10_higher_dimensions():
    separator("TEST 10: Higher Dimensions — Beyond 64 Bytes?")
    print("dim=8 → 4 pairs → 64 bytes (= 1 SHA-512)")
    print("dim=10 → 5 pairs → 80 bytes (> 1 SHA-512!)")
    print("dim=12 → 6 pairs → 96 bytes")
    print("If single SHA-512 is used, dim>8 would need a second hash.\n")

    key = "Secret99"
    length = 16

    dims_to_test = [8, 10, 12, 14, 16]
    streams = {}

    for d in dims_to_test:
        s = get_stream(key, length, dimensions=d)
        streams[d] = s
        n_pairs = d // 2
        n_bytes = n_pairs * 16
        n_sha = (n_bytes + 63) // 64
        print(f"  dim={d:2d}: {n_pairs} pairs, {n_bytes} bytes needed ({n_sha} SHA-512s), stream={stream_hex(s, 16)}")
        time.sleep(0.25)

    # We already know dim>=10 share tails — confirm
    print(f"\n  Pairwise differences (confirming dim>=10 tail sharing):")
    dim_list = list(dims_to_test)
    for i in range(len(dim_list)):
        for j in range(i + 1, len(dim_list)):
            d1, d2_val = dim_list[i], dim_list[j]
            diff = stream_diff(streams[d1], streams[d2_val])
            tag = ""
            if diff < length // 2:
                tag = " *** SIMILAR ***"
            if diff == 0:
                tag = " *** IDENTICAL ***"
            print(f"    dim={d1:2d} vs dim={d2_val:2d}: {diff:2d}/{length} bytes differ{tag}")

    # Find exactly where streams diverge for dim>=10
    if streams[10] and streams[12]:
        first_diff = -1
        for idx, (a, b) in enumerate(zip(streams[10], streams[12])):
            if a != b:
                first_diff = idx
                break
        print(f"\n  dim=10 vs dim=12: first difference at byte {first_diff}")


# ============================================================================
#  MAIN
# ============================================================================

def main():
    print("=" * 70)
    print("  FES Portal Selection Mechanism Probe")
    print("  Testing how password → key material → portal selection works")
    print("=" * 70)

    test1_password_length()
    test2_sha512_chain()
    test3_byte_sensitivity()
    test4_silo_index()
    test5_config_binding()
    test6_fotp_binding()
    test7_key_material_exhaustion()
    test8_dim_pair_hash_iterations()
    test9_prefix_stability()
    test10_higher_dimensions()

    separator("SUMMARY")
    print(f"  Total API calls made: {call_count}")
    print()
    print("  Key observations to check in the output above:")
    print("  1. Do all password lengths produce valid streams? → Key expansion exists")
    print("  2. Does every single-byte password change cause full stream avalanche?")
    print("     → Hashing confirmed (vs. direct byte mapping)")
    print("  3. Do dim=2 and dim=8 share any stream structure?")
    print("     → Would indicate shared first dimension pair")
    print("  4. Do dim>=10 still share tails? → Different code path for dim=8 vs dim>=10")
    print("  5. Does extending a key preserve any stream prefix?")
    print("     → Would indicate raw bytes, not hashing")
    print("  6. SHA-512 output size (64 bytes) exactly matches dim=8 requirement")
    print("     → Strong circumstantial evidence for SHA-512 key expansion")
    print()


if __name__ == "__main__":
    main()
