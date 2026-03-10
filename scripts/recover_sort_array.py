"""
Recover the Sort Array permutation from the scramble mode.

Strategy:
1. Get stream WITHOUT scramble (known from KPA with uniform bytes)
2. Get ciphertext WITH scramble + known plaintext
3. The scramble reorders the plaintext BEFORE XOR with stream
4. By comparing, we can recover the permutation π

The permutation π comes from ranking the Sort Array S = [s_0, ..., s_{n-1}]
where s_i are "raw decimal z values" at each byte position.

If we recover π, we know the relative ordering of the z values,
which constrains the possible z values at each position.
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


def fes_request(key, payload="", dimensions=8, scramble="", depth="1"):
    data = urllib.parse.urlencode({
        "mode": "1", "key": key, "payload": payload, "trans": "",
        "dimensions": str(dimensions), "depth": depth, "scramble": scramble,
        "xor": "on", "whirl": "", "asciiRange": "256",
    }).encode()
    req = urllib.request.Request(API_URL, data=data, headers=HEADERS)
    with urllib.request.urlopen(req) as resp:
        return json.loads(resp.read())


def b64_decode(s):
    padded = s + '=' * (4 - len(s) % 4) if len(s) % 4 else s
    return base64.b64decode(padded)


def get_stream_no_scramble(key, length, dimensions=8):
    """Get XOR stream without scramble."""
    known = bytes([0x41] * length)  # All 'A'
    result = fes_request(key, payload=known.decode(), dimensions=dimensions,
                         scramble="", depth="1")
    ct = b64_decode(result.get("trans", ""))
    # stream[N-1-i] = ct[i] XOR pt[i]
    stream = [0] * length
    for i in range(length):
        stream[length - 1 - i] = ct[i] ^ known[i]
    return stream


def recover_scramble_permutation(key, length, dimensions=8):
    """
    Recover the scramble permutation π.

    Without scramble: ct[i] = pt[i] XOR stream[N-1-i]
    With scramble: ct[i] = pt_scr[i] XOR stream_scr[N-1-i]
    where pt_scr[j] = pt[π(j)]

    Strategy: use plaintext with unique byte values so we can identify
    which position each byte came from.
    """
    # Step 1: Get stream without scramble
    stream = get_stream_no_scramble(key, length, dimensions)

    # Step 2: Encrypt unique bytes with scramble
    # Use bytes 0, 1, 2, ..., length-1 as plaintext
    if length <= 256:
        unique_pt = bytes(range(length))
    else:
        return None  # Can't have unique bytes for length > 256

    # Need to send as a string... the server expects text payload
    # But we need arbitrary bytes. Let's use a different approach:
    # Send ALL 'A' with scramble to get the scrambled stream

    # Actually, the scramble reorders the payload bytes, then XORs with a
    # potentially different stream. Let me think about this differently.

    # With scramble ON, the server:
    # 1. Generates stream K and Sort Array S
    # 2. Computes permutation π = rank(S)
    # 3. Reorders payload: P_scr[j] = P[π(j)]
    # 4. Encrypts: C[i] = P_scr[i] XOR K[N-1-i]

    # The stream K might be different with scramble! From our earlier research,
    # scramble changes the stream entirely.

    # Approach: with scramble, encrypt two known plaintexts
    # pt1 = all 0x41 ('A') → ct1[i] = 0x41 XOR K_scr[N-1-i] (since all bytes are same, scramble has no effect on uniform input!)
    # pt2 = bytes with unique values → ct2 tells us the permutation

    # Step 1: Get scrambled stream using uniform input
    result1 = fes_request(key, payload='A' * length, dimensions=dimensions,
                          scramble="on", depth="1")
    ct1 = b64_decode(result1.get("trans", ""))
    stream_scr = [0] * length
    for i in range(length):
        stream_scr[length - 1 - i] = ct1[i] ^ 0x41

    # Step 2: Encrypt bytes 1,2,3,...,length with scramble
    # But these need to be valid text... use ASCII printable characters
    if length <= 95:
        # Use ASCII 32-126 (printable)
        unique_chars = ''.join(chr(32 + i) for i in range(length))
    elif length <= 190:
        # Use a wider range but might hit encoding issues
        unique_chars = ''.join(chr(33 + i) for i in range(min(length, 93)))
        # Pad if needed
        unique_chars += ''.join(chr(33 + i) for i in range(length - 93))
    else:
        return None

    result2 = fes_request(key, payload=unique_chars, dimensions=dimensions,
                          scramble="on", depth="1")
    ct2 = b64_decode(result2.get("trans", ""))

    # Decrypt ct2 using stream_scr:
    # ct2[i] = P_scr[i] XOR K_scr[N-1-i]
    # P_scr[i] = ct2[i] XOR K_scr[N-1-i] = ct2[i] XOR stream_scr[N-1-i]
    decrypted_scr = [0] * length
    for i in range(length):
        decrypted_scr[i] = ct2[i] ^ stream_scr[length - 1 - i]

    # P_scr[j] = P[π(j)], so decrypted_scr[j] = unique_chars[π(j)]
    # We know unique_chars, so π(j) = index of decrypted_scr[j] in unique_chars

    permutation = [0] * length
    pt_bytes = [ord(c) for c in unique_chars]
    for j in range(length):
        try:
            perm_idx = pt_bytes.index(decrypted_scr[j])
            permutation[j] = perm_idx
        except ValueError:
            permutation[j] = -1  # Not found

    return stream, stream_scr, permutation, decrypted_scr


def main():
    key = "Secret99"

    for length in [12, 24, 32]:
        print(f"\n{'='*80}")
        print(f"SCRAMBLE PERMUTATION RECOVERY: key='{key}', length={length}")
        print(f"{'='*80}")

        result = recover_scramble_permutation(key, length)
        if result is None:
            print("  Failed")
            continue

        stream, stream_scr, perm, decrypted = result

        print(f"  Stream (no scramble): {stream[:min(length, 24)]}")
        print(f"  Stream (scramble):    {stream_scr[:min(length, 24)]}")
        print(f"  Permutation π:        {perm[:min(length, 24)]}")
        print(f"  Decrypted (scrambled): {decrypted[:min(length, 24)]}")

        # Check if permutation is valid (bijection)
        if -1 not in perm and len(set(perm)) == length:
            print(f"  ✓ Valid permutation (bijection)")
        else:
            print(f"  ✗ Invalid permutation: {-1 in perm=}, {len(set(perm))=}")

        # Compute inverse permutation (useful for understanding Sort Array ordering)
        if -1 not in perm:
            inv_perm = [0] * length
            for j in range(length):
                inv_perm[perm[j]] = j
            print(f"  Inverse π⁻¹:         {inv_perm[:min(length, 24)]}")

            # The permutation ranks the Sort Array values
            # π(j) = rank of s_j among all s_i
            # The position with the smallest z value gets mapped to position 0
            # So: inv_perm[0] = index of the smallest z value
            #     inv_perm[1] = index of the 2nd smallest z value

            print(f"\n  Sort Array ordering (smallest to largest z values):")
            for rank in range(min(length, 24)):
                orig_pos = inv_perm[rank]
                print(f"    rank {rank:2d} → original position {orig_pos:2d}")

        # Compare streams (scramble vs no-scramble)
        if stream and stream_scr:
            xor_diff = [a ^ b for a, b in zip(stream, stream_scr)]
            same_count = sum(1 for a, b in zip(stream, stream_scr) if a == b)
            print(f"\n  Stream comparison: {same_count}/{length} bytes match")
            if same_count < length:
                print(f"  XOR diff: {xor_diff[:min(length, 24)]}")

    # Also test with different keys
    print(f"\n{'='*80}")
    print("PERMUTATIONS FOR DIFFERENT KEYS")
    print(f"{'='*80}")

    for k in ["Secret99", "Secret98", "TestKey1"]:
        result = recover_scramble_permutation(k, 12)
        if result:
            _, _, perm, _ = result
            if -1 not in perm:
                print(f"  Key '{k:12s}': π = {perm}")


if __name__ == "__main__":
    main()
