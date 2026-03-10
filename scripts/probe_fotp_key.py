"""
FOTP + key derivation deep dive.

Key discovery: FOTP='test' + key='A' = key='A' (no FOTP)
This means FOTP is "transparent" for K=0 keys.

Hypothesis: FOTP modifies the key derivation by:
A) Concatenating FOTP to the key before hashing
B) Using FOTP as a "salt" that changes the portal selection
C) Switching to a different Silo table with K=0 portals only
D) Zeroing out the Re[MSB]-Im[LSB] asymmetry post-derivation

Tests:
1. Does FOTP+multi-char-key produce same stream as some other single-char key?
2. Does FOTP+'AB' relate to FOTP+'A' + something about 'B'?
3. Is the FOTP stream a function of key+FOTP concatenation?
4. Test FOTP with various key lengths — at what length does FOTP stop being transparent?
5. Is there a key whose normal K=0 but whose FOTP stream differs?
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


def get_stream(key, length=42, dimensions=2, extra_params=None):
    params = {
        "mode": "1", "key": key, "payload": 'A' * length, "trans": "",
        "dimensions": str(dimensions), "depth": "1", "scramble": "",
        "xor": "on", "whirl": "", "asciiRange": "256",
    }
    if extra_params:
        params.update(extra_params)
    data = urllib.parse.urlencode(params).encode()
    req = urllib.request.Request(API_URL, data=data, headers=HEADERS)
    with urllib.request.urlopen(req, timeout=30) as resp:
        result = json.loads(resp.read())
    ct_b64 = result.get("trans", "")
    if not ct_b64:
        return None
    padded = ct_b64 + '=' * (4 - len(ct_b64) % 4) if len(ct_b64) % 4 else ct_b64
    ct = base64.b64decode(padded)
    stream_rev = bytes(c ^ 0x41 for c in ct)
    return list(reversed(list(stream_rev)))


def stream_eq(s1, s2):
    if s1 is None or s2 is None:
        return False
    return s1 == s2


def get_k(s):
    if not s or len(s) < 28:
        return None
    return s[0] ^ s[13]


def main():
    # =========================================================================
    print("=" * 80)
    print("TEST 1: FOTP TRANSPARENCY — WHICH KEYS ARE TRANSPARENT?")
    print("=" * 80)

    # FOTP is transparent for single-char keys (K=0). Is it transparent for
    # ALL K=0 keys, or only single-char ones?

    # First, find a multi-char key with K=0 (if any exist)
    # From memory: single-char keys always K=0, multi-char keys usually K≠0
    # But there might be rare multi-char keys with K=0

    print("\n  Testing FOTP transparency for various keys:")
    for key in ["A", "B", "AB", "AA", "Secret99", " ", "0"]:
        s_no = get_stream(key)
        time_mod.sleep(0.12)
        s_fotp = get_stream(key, extra_params={"fotp": "test"})
        time_mod.sleep(0.12)
        K_no = get_k(s_no)
        K_fotp = get_k(s_fotp)
        transparent = stream_eq(s_no, s_fotp)
        print(f"    '{key:10s}': K_no={K_no:3d}  K_fotp={K_fotp:3d}  "
              f"{'TRANSPARENT' if transparent else 'DIFFERENT'}")

    # =========================================================================
    print(f"\n{'=' * 80}")
    print("TEST 2: FOTP STREAMS — ARE THEY KEY-CONCATENATION BASED?")
    print("=" * 80)

    # If FOTP modifies the key by concatenation, then:
    # FOTP='test', key='A' → hash('Atest') or hash('testA')
    # Let's check if FOTP stream for key='A' equals normal stream for 'Atest' or 'testA'

    s_a_fotp = get_stream("A", extra_params={"fotp": "test"})
    time_mod.sleep(0.12)
    s_atest = get_stream("Atest")
    time_mod.sleep(0.12)
    s_testa = get_stream("testA")
    time_mod.sleep(0.12)
    s_a = get_stream("A")
    time_mod.sleep(0.12)

    print(f"\n  FOTP='test', key='A':")
    print(f"    vs key='Atest':  {'SAME' if stream_eq(s_a_fotp, s_atest) else 'DIFFERENT'}")
    print(f"    vs key='testA':  {'SAME' if stream_eq(s_a_fotp, s_testa) else 'DIFFERENT'}")
    print(f"    vs key='A':      {'SAME' if stream_eq(s_a_fotp, s_a) else 'DIFFERENT'}")

    # Also check: does 'Secret99' with FOTP='test' equal 'Secret99test'?
    s_s99_fotp = get_stream("Secret99", extra_params={"fotp": "test"})
    time_mod.sleep(0.12)
    s_s99test = get_stream("Secret99test")
    time_mod.sleep(0.12)
    s_tests99 = get_stream("testSecret99")
    time_mod.sleep(0.12)

    print(f"\n  FOTP='test', key='Secret99':")
    print(f"    vs key='Secret99test':  {'SAME' if stream_eq(s_s99_fotp, s_s99test) else 'DIFFERENT'}")
    print(f"    vs key='testSecret99':  {'SAME' if stream_eq(s_s99_fotp, s_tests99) else 'DIFFERENT'}")

    # =========================================================================
    print(f"\n{'=' * 80}")
    print("TEST 3: FOTP='test' STREAMS — DO DIFFERENT KEYS PRODUCE CORRELATED STREAMS?")
    print("=" * 80)

    # All FOTP streams have K=0. Are they otherwise independent?
    fotp_streams = {}
    for key in ["A", "B", "C", "AB", "AC", "Secret99", "hello"]:
        s = get_stream(key, extra_params={"fotp": "test"})
        fotp_streams[key] = s
        time_mod.sleep(0.12)

    keys = list(fotp_streams.keys())
    print(f"\n  Pairwise comparison of FOTP='test' streams:")
    for i in range(len(keys)):
        for j in range(i+1, len(keys)):
            s1 = fotp_streams[keys[i]]
            s2 = fotp_streams[keys[j]]
            if s1 and s2:
                matches = sum(1 for k in range(min(len(s1), len(s2))) if s1[k] == s2[k])
                total = min(len(s1), len(s2))
                print(f"    '{keys[i]:10s}' vs '{keys[j]:10s}': "
                      f"{matches}/{total} match")

    # =========================================================================
    print(f"\n{'=' * 80}")
    print("TEST 4: FOTP LENGTH — IS THERE A THRESHOLD?")
    print("=" * 80)

    # We know single-char FOTP has no effect. Multi-char FOTP does.
    # What about 2-char FOTP? Is there a minimum FOTP length?
    key = "Secret99"
    s_no = get_stream(key)
    time_mod.sleep(0.12)

    print(f"\n  Key '{key}', varying FOTP length:")
    for fotp_len in range(0, 8):
        fotp = "x" * fotp_len
        s = get_stream(key, extra_params={"fotp": fotp})
        same = stream_eq(s, s_no)
        K = get_k(s)
        print(f"    FOTP='{fotp:6s}' (len={fotp_len}): K={K:3d}  "
              f"{'SAME (transparent)' if same else 'DIFFERENT'}")
        time_mod.sleep(0.12)

    # =========================================================================
    print(f"\n{'=' * 80}")
    print("TEST 5: DOES FOTP VALUE MATTER (FOR len>=2)?")
    print("=" * 80)

    key = "Secret99"
    print(f"\n  Key '{key}', various FOTP values (all len>=2):")
    ref_fotp = get_stream(key, extra_params={"fotp": "xx"})
    time_mod.sleep(0.12)

    for fotp in ["xx", "yy", "ab", "zz", "11", "test", "longFOTP123"]:
        s = get_stream(key, extra_params={"fotp": fotp})
        same = stream_eq(s, ref_fotp)
        K = get_k(s)
        print(f"    FOTP='{fotp:14s}': K={K:3d}  "
              f"{'SAME as xx' if same else 'DIFFERENT from xx'}  "
              f"first3={s[:3] if s else 'None'}")
        time_mod.sleep(0.12)

    # =========================================================================
    print(f"\n{'=' * 80}")
    print("TEST 6: FOTP AT DIFFERENT DIMENSIONS")
    print("=" * 80)

    key = "Secret99"
    print(f"\n  Key '{key}', FOTP='test' at various dims:")
    for dim in [2, 4, 8, 10]:
        s_no = get_stream(key, dimensions=dim)
        time_mod.sleep(0.12)
        s_fotp = get_stream(key, dimensions=dim, extra_params={"fotp": "test"})
        time_mod.sleep(0.12)
        K_no = get_k(s_no)
        K_fotp = get_k(s_fotp)
        print(f"    dim={dim:2d}: K_no={K_no:3d}  K_fotp={K_fotp:3d}")

    # =========================================================================
    print(f"\n{'=' * 80}")
    print("TEST 7: KEY+FOTP BEHAVIOR — IS FOTP JUST A KEY MODIFIER?")
    print("=" * 80)

    # Theory: FOTP modifies the key before hashing. If so, we might find that
    # key='AB' with FOTP='test' produces the same stream as some other key
    # without FOTP. But the K=0 constraint makes this unlikely unless the
    # modified key naturally maps to K=0.

    # Instead, let's check: does key='A' with FOTP='B' differ from key='AB'?
    s_a_fotp_b = get_stream("A", extra_params={"fotp": "BB"})
    time_mod.sleep(0.12)
    s_ab = get_stream("AB")
    time_mod.sleep(0.12)
    s_a_fotp_b2 = get_stream("A", extra_params={"FOTP": "BB"})
    time_mod.sleep(0.12)

    print(f"\n  key='A' FOTP='BB' vs key='AB': "
          f"{'SAME' if stream_eq(s_a_fotp_b, s_ab) else 'DIFFERENT'}")
    print(f"  key='A' fotp='BB' vs FOTP='BB': "
          f"{'SAME' if stream_eq(s_a_fotp_b, s_a_fotp_b2) else 'DIFFERENT'}")

    # =========================================================================
    print(f"\n{'=' * 80}")
    print("TEST 8: SINGLE-CHAR FOTP VALUES — WHICH ARE TRANSPARENT?")
    print("=" * 80)

    key = "Secret99"
    s_ref = get_stream(key)
    time_mod.sleep(0.12)

    print(f"\n  Key '{key}', single-char FOTP values:")
    for fotp_char in [' ', 'a', 'z', '0', '9', '!', '\x01', '\t']:
        s = get_stream(key, extra_params={"fotp": fotp_char})
        same = stream_eq(s, s_ref)
        K = get_k(s)
        repr_c = repr(fotp_char)
        print(f"    FOTP={repr_c:6s}: K={K:3d}  "
              f"{'TRANSPARENT' if same else 'DIFFERENT'}")
        time_mod.sleep(0.12)


if __name__ == "__main__":
    main()
