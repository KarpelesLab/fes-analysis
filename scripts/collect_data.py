"""
Collect experimental data from the FES server to analyze the SHA-512 → stream relationship.

Strategy:
- Generate many keys, compute their SHA-512 hashes
- Encrypt a fixed short payload (10 bytes, well within phase 1 for dim=8)
- Extract the keystream for each
- Save everything to JSON for offline analysis
- No scramble, dim=8, short messages = single pass

We also precompute keys that share the same first 16 bits of SHA-512
(same mapping region index) to isolate the effect of the offset bits.
"""

import hashlib
import json
import os
import struct
import sys
import time
import urllib.request
import urllib.parse
import base64

API_URL = "https://portalz.solutions/fes.dna"
HEADERS = {
    "Content-Type": "application/x-www-form-urlencoded",
    "Referer": "https://portalz.solutions/fractalTransform.html",
    "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36",
}

PAYLOAD = "A" * 20  # 20 bytes, safely in phase 1 (<44 for dim=8)
PAYLOAD_BYTES = [0x41] * 20
DATA_FILE = "data/stream_data.json"


def fes_encrypt(key, payload=PAYLOAD, dimensions=8):
    """Call the live FES server to encrypt."""
    data = urllib.parse.urlencode({
        "mode": "1",
        "key": key,
        "payload": payload,
        "trans": "",
        "dimensions": str(dimensions),
        "depth": "3",
        "scramble": "",
        "xor": "on",
        "whirl": "",
        "asciiRange": "256",
    }).encode()
    req = urllib.request.Request(API_URL, data=data, headers=HEADERS)
    with urllib.request.urlopen(req, timeout=30) as resp:
        result = json.loads(resp.read())
    return result.get("trans", "")


def b64_decode(s):
    padded = s + "=" * (4 - len(s) % 4) if len(s) % 4 else s
    return list(base64.b64decode(padded))


def extract_stream(ct_bytes, pt_bytes=PAYLOAD_BYTES):
    """Extract stream given cipher[i] = pt[i] XOR stream[N-1-i]"""
    N = len(ct_bytes)
    # stream[N-1-i] = ct[i] XOR pt[i], so reverse to get stream in generation order
    stream_rev = [ct_bytes[i] ^ pt_bytes[i] for i in range(N)]
    return list(reversed(stream_rev))


def sha512_hex(key):
    return hashlib.sha512(key.encode()).hexdigest()


def sha512_bytes(key):
    return list(hashlib.sha512(key.encode()).digest())


def expand_key(key_str, dimensions=8):
    """Expand key via iterated SHA-512 to fill dimensions * 112 bits."""
    key_bytes = key_str.encode()
    bytes_needed = dimensions * 112 // 8  # 112 bytes for dim=8
    expanded = hashlib.sha512(key_bytes).digest()
    while len(expanded) < bytes_needed:
        expanded += hashlib.sha512(expanded[-64:]).digest()
    return list(expanded[:bytes_needed])


def mapping_index(key_str, dimensions=8):
    """Get the 16-bit mapping region index from the expanded key."""
    exp = expand_key(key_str, dimensions)
    return (exp[0] << 8) | exp[1]


def main():
    os.makedirs("data", exist_ok=True)

    # Load existing data if any
    if os.path.exists(DATA_FILE):
        with open(DATA_FILE) as f:
            all_data = json.load(f)
        print(f"Loaded {len(all_data['keys'])} existing entries from {DATA_FILE}")
    else:
        all_data = {"payload": PAYLOAD, "payload_bytes": PAYLOAD_BYTES,
                    "dimensions": 8, "keys": []}

    existing_keys = {entry["key"] for entry in all_data["keys"]}

    # Phase 1: Generate a spread of keys covering different mapping indices
    print("\n=== Phase 1: Random keys for broad coverage ===")
    random_keys = []
    for i in range(500):
        key = f"probe_{i:04d}"
        if key not in existing_keys:
            random_keys.append(key)

    # Phase 2: Find keys that share mapping indices (same first 16 bits of expanded key)
    # to isolate the effect of offset bits
    print("=== Phase 2: Finding keys sharing mapping indices ===")
    index_to_keys = {}
    for i in range(10000):
        key = f"idx_{i:05d}"
        idx = mapping_index(key)
        if idx not in index_to_keys:
            index_to_keys[idx] = []
        index_to_keys[idx].append(key)

    # Find indices with multiple keys
    shared_groups = {idx: keys for idx, keys in index_to_keys.items() if len(keys) >= 3}
    print(f"  Found {len(shared_groups)} mapping indices with 3+ keys")

    # Pick top groups and add their keys
    shared_keys = []
    groups_used = []
    for idx, keys in sorted(shared_groups.items(), key=lambda x: -len(x[1]))[:10]:
        group_keys = keys[:5]  # up to 5 keys per group
        for k in group_keys:
            if k not in existing_keys:
                shared_keys.append(k)
        groups_used.append({"mapping_index": idx, "keys": group_keys})

    # Phase 3: Keys with sequential names to study small changes
    sequential_keys = []
    for base in ["SecretKey", "TestKey", "Key"]:
        for i in range(20):
            key = f"{base}{i}"
            if key not in existing_keys:
                sequential_keys.append(key)

    # Combine all keys to test
    all_keys = random_keys + shared_keys + sequential_keys
    # Remove duplicates
    all_keys = [k for k in all_keys if k not in existing_keys]
    # Remove already collected
    all_keys = list(dict.fromkeys(all_keys))

    print(f"\nTotal new keys to test: {len(all_keys)}")
    print(f"  Random: {len(random_keys)}, Shared-index: {len(shared_keys)}, Sequential: {len(sequential_keys)}")

    # Collect data from server
    errors = 0
    for i, key in enumerate(all_keys):
        try:
            ct_b64 = fes_encrypt(key)
            if not ct_b64:
                print(f"  [{i+1}/{len(all_keys)}] Key '{key}': empty response, skipping")
                continue

            ct_bytes = b64_decode(ct_b64)
            stream = extract_stream(ct_bytes)
            exp_key = expand_key(key)
            idx = mapping_index(key)

            entry = {
                "key": key,
                "sha512": sha512_hex(key),
                "expanded_key": exp_key,
                "mapping_index": idx,
                "ciphertext_b64": ct_b64,
                "ciphertext": ct_bytes,
                "stream": stream,
            }
            all_data["keys"].append(entry)
            existing_keys.add(key)

            if (i + 1) % 50 == 0:
                print(f"  [{i+1}/{len(all_keys)}] Collected, saving checkpoint...")
                with open(DATA_FILE, "w") as f:
                    json.dump(all_data, f, indent=1)

        except Exception as e:
            errors += 1
            print(f"  [{i+1}/{len(all_keys)}] Key '{key}': ERROR: {e}")
            if errors > 10:
                print("  Too many errors, stopping")
                break
            time.sleep(1)
            continue

    # Final save
    with open(DATA_FILE, "w") as f:
        json.dump(all_data, f, indent=1)
    print(f"\nSaved {len(all_data['keys'])} total entries to {DATA_FILE}")

    # Save the shared-index groups for reference
    with open("data/shared_index_groups.json", "w") as f:
        json.dump(groups_used, f, indent=2)
    print(f"Saved {len(groups_used)} shared-index groups to data/shared_index_groups.json")

    # Quick summary
    print("\n=== Quick Summary ===")
    indices_seen = set()
    for entry in all_data["keys"]:
        indices_seen.add(entry["mapping_index"])
    print(f"  Unique mapping indices covered: {len(indices_seen)}")
    print(f"  Total entries: {len(all_data['keys'])}")


if __name__ == "__main__":
    main()
