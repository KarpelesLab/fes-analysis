# FES (Fractal Encryption Standard) — Investigation & Findings

## Overview

FES is the "Fractal Encryption Standard" by Portalz PTY LTD (Wolfgang Flatow, Conondale QLD, Australia). It claims to be "a standardised specification of Fractal Transformation engineered to replace quantum vulnerable AES encryption."

This document presents our findings from:
- Reading the published specification (FractalTransformationProcessSpecificationV3.pdf)
- Reading the detailed presentation (docs/FT-Explained.pdf)
- Reading the marketing materials at portalz.solutions/fes.html
- Reading the European patent EP4388438A1
- Reverse-engineering the algorithm via the live demo at portalz.solutions/fractalTransform.html
- Building a Python implementation based on the spec
- Benchmarking FES against AES-256
- Demonstrating practical attacks against the live server
- Collecting and analyzing 592 experimental data points from the live server

**TL;DR**: FES is a simple XOR stream cipher using Mandelbrot iterations as a PRNG. It is trivially broken by known-plaintext attacks, has no authentication, no nonce, and is hundreds of times slower than AES. Every major security claim on the website is false or misleading.

---

## What FES Actually Is

Despite the elaborate "fractal" terminology, FES reduces to:

```
ciphertext[i] = plaintext[i] XOR keystream[N-1-i]
```

That's it. The entire "fractal transformation" is just a way to generate the keystream bytes. The actual encryption is a single XOR — the simplest possible stream cipher construction, applied in reverse byte order.

### Algorithm Steps (Reverse-Engineered)

1. **Key expansion**: The user's key is hashed with iterated SHA-512 to fill `dimensions × 112` bits.

2. **Key → Fractal Portal**: The expanded hash is split into:
   - 16 bits selecting a pre-computed Mandelbrot boundary region
   - Remaining bits split into x,y offsets scaled to [0, 0.01]
   - The key bytes then "navigate" through the Mandelbrot set via polar coordinate steps, arriving at a final (x,y) coordinate called the "fractal portal."

3. **Keystream generation**: Starting at the portal, for each byte of payload:
   - Compute a Mandelbrot iteration at the current (x,y) position
   - Extract the fractional digits of the result's magnitude
   - `stream_byte = fractional_integer mod 256`
   - Navigate to the next (x,y) position using angle and hypotenuse derived from the same value

4. **Encryption**: `cipher[i] = plaintext[i] XOR stream[N-1-i]` (the stream is applied in **reverse** order — the first generated stream byte is XORed with the last plaintext byte).

5. **Decryption**: Identical operation (XOR is self-inverse).

### The "Scramble" Option

The online demo offers a "scramble" toggle. Testing with identical-byte payloads proves that scramble modifies the keystream itself (not just byte ordering), since `encrypt("AAA...") with scramble` produces different ciphertext values than without. However, the scrambled stream is equally deterministic and equally vulnerable to the same attacks.

---

## Attacks Demonstrated Against the Live Server

All attacks were performed against the production server at `portalz.solutions/fes.dna`.

### Attack 1: Keystream Recovery via Known Plaintext

By encrypting known plaintexts of different lengths with the same key, we confirmed:

- The keystream is **fully deterministic** for a given key
- The keystream is **consistent** across message lengths (the stream for an 8-byte message is a prefix of the stream for a 16-byte message)
- A single known-plaintext/ciphertext pair reveals the complete keystream

```
Key: SecretKey99, dimensions=8, no scramble

Stream(8)  = [109, 84, 124, 87, 119, 51, 133, 129]
Stream(16) = [109, 84, 124, 87, 119, 51, 133, 129, 157, 12, 20, 206, 206, 154, 27, 145]
Stream(32) = [109, 84, 124, 87, 119, 51, 133, 129, 157, 12, 20, ...]

Stream(8) == Stream(16)[:8]: True
Stream(16) == Stream(32)[:16]: True
```

### Attack 2: Decrypting Unknown Messages

Using the keystream recovered from Attack 1, we decrypted a message without knowing the key:

```
Secret message:  "Attack works!!"
Ciphertext (b64): 27q6dW/2ofJcBTwPdUw

Using recovered keystream:
Decrypted:       "Attack works!!"
MATCH: True
```

### Attack 3: Ciphertext Forgery

We crafted a ciphertext that the server decrypts to an arbitrary chosen message:

```
Desired message:  "Forged msg!!!!"
Crafted ciphertext: [computed using recovered keystream]

Server decrypted to: "Forged msg!!!!"
FORGERY MATCH: True
```

This means an attacker who has recovered the keystream can:
- Forge messages that appear to come from legitimate senders
- Modify ciphertext in transit to change the decrypted content
- Impersonate any party in a communication

### Attack 4: Scramble Mode Equally Vulnerable

```
Scramble stream (from 'B'*16): [87, 10, 178, 157, ...]
Scramble stream (from 'C'*16): [87, 10, 178, 157, ...]
Streams match: True
```

The scramble option does NOT prevent any of these attacks.

---

## Performance Comparison: FES vs AES

Benchmarked on the same hardware (Python implementation for FES, PyCryptodome for AES):

| Data Size | FES Encrypt | AES-256-CTR | AES-256-GCM | AES-CTR Speedup |
|-----------|-------------|-------------|-------------|-----------------|
| 16 bytes  | 487 KB/s    | 6.3 MB/s    | 1.5 MB/s    | 13x faster      |
| 64 bytes  | 885 KB/s    | 55 MB/s     | 9.7 MB/s    | 62x faster      |
| 256 bytes | 1.1 MB/s    | 225 MB/s    | 41 MB/s     | 205x faster     |
| 1 KB      | 1.1 MB/s    | 570 MB/s    | 138 MB/s    | 528x faster     |
| 64 KB     | —           | 1.45 GB/s   | 1.18 GB/s   | —               |
| 1 MB      | —           | 1.21 GB/s   | 1.09 GB/s   | ~1000x faster   |

**FES estimated time for 1 MB: ~0.97 seconds**
**FES claimed time for 1 MB: 0.05 seconds** (19x slower than claimed)

Note: Our FES implementation is in pure Python, which disadvantages it. However, FES requires a full Mandelbrot iteration *per byte* of payload — this is inherently expensive. Even a C implementation would be far slower than AES, which benefits from hardware acceleration (AES-NI instructions) on all modern x86 CPUs.

### Why FES Cannot Match AES Performance

- AES processes 16 bytes per round in a block cipher; FES processes 1 byte per Mandelbrot iteration
- AES-CTR mode is trivially parallelizable; FES stream generation is inherently sequential
- AES has dedicated hardware instructions on modern CPUs (AES-NI); FES requires floating-point Mandelbrot math
- The FES spec touts sequential processing as a feature ("defeats parallelism") — this is actually a performance flaw being marketed as a security benefit

---

## Claim-by-Claim Analysis

### Claim 1: "AES encryption is quantum vulnerable"

**VERDICT: FALSE**

The website states FES is "engineered to replace quantum vulnerable AES encryption." This is the foundational claim, and it is wrong.

- **Grover's algorithm** is the relevant quantum attack against symmetric ciphers. It provides a quadratic speedup to brute-force search, effectively halving the key length.
- AES-256 under Grover's attack has **128-bit security** — still astronomically beyond any feasible attack.
- **NIST explicitly states** that AES-256 is quantum-resistant and recommends it for post-quantum security.
- The FES website conflates RSA/ECC vulnerability (which ARE threatened by Shor's algorithm) with AES vulnerability. These are completely different classes of cryptography.
- No credible cryptographer considers AES-256 quantum-vulnerable.

### Claim 2: "Infinite key-space starting at 832 bits"

**VERDICT: MISLEADING**

- FES expands keys via iterated SHA-512 hashing to fill the required bit count.
- **Hashing cannot create entropy.** A 10-character password hashed to 832 bits still has ~10 characters of entropy (~50-65 bits). The attacker just needs to try passwords, not the expanded hash space.
- AES-256's key space (2^256) already contains more possibilities than atoms in the observable universe (~2^266). Making the number bigger provides zero practical benefit.
- The claim confuses key *length* with key *entropy*. Security depends on entropy, not on how many bits you stretch it to.

### Claim 3: "Impenetrable — a world-first in cryptography"

**VERDICT: FALSE**

We demonstrated three successful attacks against the live server:
1. **Keystream recovery** from any known plaintext/ciphertext pair
2. **Decryption of unknown messages** using the recovered keystream
3. **Ciphertext forgery** — crafting ciphertexts that decrypt to chosen messages

These are not exotic attacks. They are the *first thing* any cryptographer checks when evaluating a stream cipher. The vulnerability is fundamental to the XOR construction without nonces.

Additionally:
- FES has **no authentication** (no MAC, no AEAD). Any bit flipped in the ciphertext flips the corresponding bit in the plaintext. An attacker can modify messages in transit without detection.
- The "impenetrability proof" referenced on the website was generated by ChatGPT, as stated in the spec document itself.

### Claim 4: "The payload no longer exists in the ciphertext in any form"

**VERDICT: FALSE**

The encryption is `cipher[i] = plaintext[i] XOR stream[i]` (or `(plaintext[i] + stream[i]) mod 256` in addition mode). The payload is trivially recoverable given the stream, which is deterministic for a given key. The payload is "hidden" exactly as much as any XOR cipher hides it — which is to say, not at all if the keystream is known.

The spec's statement that "addition is a one-way function — it is impossible to determine the added 2 numbers that resulted in each tdv" is mathematically incorrect. Given one of the two addends (the keystream, which is deterministic), the other (the plaintext) is trivially recovered.

### Claim 7: "Non-deterministic Fractal Transforms"

**VERDICT: FALSE**

FT-Explained.pdf (slide 2) claims: "Our patent pending fractal transform formulas for data security are non-deterministic at every stage of the process."

This is demonstrably false — we proved the system is **completely deterministic**:
- Same key → same stream, every time
- Same key + same payload → same ciphertext, every time
- The keystream is consistent across message lengths (within the same phase)

The authors appear to confuse "unpredictable" (hard to compute the stream from the key without the full Mandelbrot iteration) with "non-deterministic" (producing different results each time). The system IS deterministic — that's what makes decryption possible. A truly non-deterministic cipher couldn't be decrypted.

### Claim 8: "Fractal Portals break Key Determinism"

**VERDICT: MEANINGLESS**

FT-Explained.pdf (slide 11) claims that because the stream values "are entirely separate from and unpredictable by the Key," this "breaks Key Determinism." This is not a recognized cryptographic property. In standard cryptography, a stream cipher where the keystream is unpredictable from the key would be useless — you couldn't decrypt. What they actually mean is that the keystream is a complex function of the key, which is true of ALL cryptographic primitives (AES's S-box is equally "unpredictable" in this sense).

### Claim 9: "Step 4 shifts the possible portals from 2^512 to infinity"

**VERDICT: MISLEADING**

FT-Explained.pdf (slide 10) describes how after the hash selects an entry portal, the raw key bytes are used to navigate to the final fractal portal, claiming this expands the keyspace from 2^512 to infinity. In reality:
- The raw key bytes add entropy proportional to the key length, not "infinity"
- A 10-character key adds at most ~65 bits of entropy from key byte navigation
- The total entropy is still bounded by the original key entropy (SHA-512 of the key)
- "Infinity" is mathematically meaningless as a key space size

### Claim 5: "Defeats the parallelism of GPU and Quantum Computers"

**VERDICT: MISLEADING**

- The sequential nature of FES stream generation is a **performance disadvantage**, not a security feature.
- AES-CTR's parallelizability is a *feature* that enables high throughput. It does not weaken security.
- A brute-force attack on AES-256 requires 2^256 operations regardless of parallelism — the total work is what matters, not whether individual operations are sequential.
- FES does not need to "defeat parallelism" because the attacks that work against it (known-plaintext, keystream recovery) don't require any brute force at all.

### Claim 6: "Industrial strength performance — 0.05 seconds per megabyte"

**VERDICT: DUBIOUS**

- Our measurement: ~0.97 seconds per MB (19x slower than claimed), and this is just for the encryption step, not including the mapping table initialization.
- AES-256-CTR achieves ~1.2 GB/s on the same hardware — roughly **1,200x faster** than FES.
- The per-byte Mandelbrot iteration requirement makes FES fundamentally slower than block ciphers.

### Attack 5: Multi-Pass XOR Provides Zero Security

```
depth=1 (1 pass):  stream = [109, 84, 124, 87, ...] → normal encryption
depth=2 (2 passes): stream = [0, 0, 0, 0, ...]      → null encryption!
depth=3 (3 passes): stream = [109, 84, 124, 87, ...] → same as depth=1
depth=4 (4 passes): stream = [0, 0, 0, 0, ...]      → null encryption!
```

All passes use the **same stream**. With XOR, even passes cancel out (P XOR K XOR K = P), and any remaining odd pass is identical to a single pass. The server's default "3 passes" is equivalent to 1 pass.

### Attack 6: FOTP (Nonce) Is a Boolean, Not a Nonce

```
fotp=''         → stream[0:5] = [109, 84, 124, 87, 119]  (default)
fotp='test'     → stream[0:5] = [239, 226, 84, 242, 188]  (alternate)
fotp='file.txt' → stream[0:5] = [239, 226, 84, 242, 188]  (SAME alternate!)
fotp='session1' → stream[0:5] = [239, 226, 84, 242, 188]  (SAME alternate!)
fotp='a'        → stream[0:5] = [109, 84, 124, 87, 119]  (no effect!)
```

The FOTP parameter that was supposed to provide nonce-like functionality:
- Is binary: any value ≥2 chars triggers the **same** alternate stream
- Different FOTP values produce **identical** ciphertext
- Decryption with wrong FOTP still succeeds

This means FOTP provides at most 1 extra bit of keyspace (on/off), not the filename/session-dependent variation claimed in the documentation.

### Attack 7: Overwrite Operator Ordering Recovered

We fully reverse-engineered the overwrite operator pipeline from the live server:

1. **Operator application order**: XOR → ADD → SPLIT (verified with all combinations)
2. **XOR formula**: `cipher[i] = plaintext[i] XOR stream[N-1-i]`
3. **ADD formula**: `cipher[i] = (plaintext[i] + stream[N-1-i]) mod 256` (same stream index as XOR)
4. **SPLIT formula**: `cipher[i] = rotate_left(plaintext[i], stream[N+1-i] mod 7)` (stream index offset by +2)
5. **When no operator is checked**: XOR is used as default
6. **The `xor` checkbox is ignored**: server always uses XOR regardless of checkbox state

---

## Fundamental Design Flaws

### 1. No Nonce / Initialization Vector

FES generates the same keystream for the same key, regardless of message content or context. This means:
- Encrypting the same message twice produces identical ciphertext (enables detection of repeated messages)
- Two messages encrypted with the same key can be XORed together to eliminate the keystream, revealing the XOR of the two plaintexts (a classic "two-time pad" attack)

Every modern cipher uses a nonce or IV to ensure unique keystreams per encryption. FES does not.

### 2. No Authentication

FES provides no integrity protection. An attacker can:
- Flip any bit in the ciphertext, which flips the corresponding bit in the plaintext
- Modify messages in transit without detection
- Forge valid ciphertexts

Modern standards (TLS 1.3, etc.) require authenticated encryption (e.g., AES-GCM, ChaCha20-Poly1305). FES provides only confidentiality, and even that is weak.

### 3. Floating-Point Determinism and String-Dependent Computation

The algorithm has a fatal portability flaw that goes beyond normal floating-point concerns.

**The stream byte computation depends on the string representation of a float.**

Analysis of the client-side JavaScript source (`portalz.solutions/qb/js/fractal.js`) reveals the core computation:

```javascript
// The "fractal value" is zx² + zy² (squared magnitude of final z)
return [zx*zx+zy*zy, ...];

// Stream byte extraction:
var stripped = v[0].toString().replace('.', '');
var streamByte = stripped % 256;
```

The algorithm converts the floating-point result to a **string**, removes the decimal point, converts back to an integer, and takes mod 256. This means:

- **Different languages produce different results for the same input.** JavaScript's `(4.912345678901234).toString()` may produce a different number of digits than Python's `repr(4.912345678901234)` or Java's `Double.toString(4.912345678901234)`. Even a single extra digit changes the mod 256 result completely.
- **Different runtime versions can break compatibility.** V8, SpiderMonkey, and JavaScriptCore may format floats differently. Python changed its float repr algorithm in version 3.1.
- **The algorithm is not mathematically defined.** It depends on an implementation artifact (string formatting) rather than a mathematical operation. This makes it impossible to write an interoperable implementation from the specification.

Even the IEEE 754 Mandelbrot computation itself compounds this problem:
- Different CPUs, compilers, or floating-point modes may produce different intermediate z values
- Extended precision registers (x87 80-bit) vs SSE 64-bit produce different results
- Fused multiply-add (FMA) instructions change rounding behavior

Well-designed ciphers use exclusively integer arithmetic precisely to avoid these issues. AES is defined entirely in terms of byte operations and finite field arithmetic — it produces identical results on every platform, every language, every CPU.

### 4. No Peer Review

- The specification was "driven by a collaboration between ChatGBT AI and Wolfgang Flatow" (sic — the spec misspells "ChatGPT")
- No independent cryptanalysis has been published
- No academic papers, no conference presentations, no formal security proofs
- The "impenetrability proof" is ChatGPT output, not a mathematical proof

### 5. The "Fractal" Aspect Is Cosmetic

The Mandelbrot iteration is just a deterministic function that maps (x,y) coordinates to values. It could be replaced by any PRNG or hash function without changing the security properties. The "infinite complexity" of fractals is irrelevant — what matters is whether the keystream is cryptographically secure, which requires formal analysis that has not been performed.

---

## Stream Quality

To be fair, the FES keystream does pass basic statistical tests:

| Metric | FES Stream | AES-CTR Stream | Ideal |
|--------|-----------|----------------|-------|
| Unique byte values (of 256) | 256 | 256 | 256 |
| Chi-squared (df=255) | 232.4 | 229.8 | ~255 |
| Bit ratio (ones) | 0.4958 | 0.5009 | 0.5000 |
| Avg byte difference | 84.6 | 83.9 | ~85.3 |

The keystream appears statistically random. However, statistical randomness is a *necessary* but not *sufficient* condition for cryptographic security. The fatal flaws are in the cipher construction (no nonce, no authentication), not in the PRNG quality.

---

## The Patent (EP4388438A1)

The European patent provides slightly more detail than the website but is still deliberately vague:

- **No pseudocode or code listings** are provided
- The Mandelbrot iteration count is not specified — "could be a set value, could be defined based on the spatial region"
- The formula for extracting angle/distance translation values references "modulo addition with defined prime numbers" without naming them
- Only one of the 65,536 mapping regions is identified (Region 57193 at coordinates 0.505, -0.565) — we could not reproduce this with any scan configuration
- The scaling factor `0.0000000000000000001387778781` is given, which equals `0.01 / 2^56`
- The patent describes addition (`(data + key) mod 256`) but the live server uses XOR — an inconsistency

The patent is deliberately broad and underspecified, making independent implementation impossible. This is a valid patent strategy for IP protection, but it is incompatible with being a "standard" that others can implement.

## Can the Server's Output Be Independently Reproduced?

**No.** Despite having the spec, the patent, 12 technical papers, the client-side source code, and extensive black-box testing, we cannot generate the same keystream as the server. The barriers are:

1. **Unpublished mapping table** — 65,536 region coordinates that cannot be regenerated
2. **Unknown key expansion method** — the marketing material says "iterations of SHA512 hashes" but the exact method is unspecified; it could be simple chaining, HMAC-SHA512 with unknown string constants, counter-mode hashing, or something else. The patent doesn't mention SHA-512 at all.
3. **String-dependent computation** — stream bytes depend on how floats are formatted as strings, which varies across languages and runtimes
4. **Key-dependent phase transitions** — the stream changes at message-length boundaries (e.g., multiples of 28 for dim=8) that are both key-dependent and undocumented
5. **Unspecified navigation parameters** — the dynamic prime array, hypotenuse modulus, scaling factors, and angle formulas
6. **Unknown fixed-point format** — the HFN Theory paper says "decimal arithmetic" but doesn't specify the precision or representation
7. **Unknown stream extraction mixing function** — "12 significant bytes per dimension via memory transfer" involves an unspecified mixing/permutation step

**However**, the keystream CAN be extracted from the server via known-plaintext probing. For any given (key, dimensions, message_length), sending a known plaintext reveals the exact keystream, which can then decrypt any other message with the same parameters. This was demonstrated successfully against the live server.

**What we HAVE fully reverse-engineered from the live server:**
- The exact encryption formula: `cipher[i] = plaintext[i] XOR stream[N-1-i]`
- The ADD formula: `cipher[i] = (plaintext[i] + stream[N-1-i]) mod 256`
- The SPLIT formula: `cipher[i] = rotate_left(plaintext[i], stream[N+1-i] mod 7)`
- The operator application order: XOR → ADD → SPLIT
- Multi-pass behavior: all passes use identical stream, even passes cancel with XOR
- FOTP behavior: acts as boolean (on/off), not a true nonce
- Cross-dimension stream sharing: dim≥10 share a common stream tail; dim=8 is independent
- Phase transition patterns: 28-byte interval for dim=8, key-dependent boundary selection

The inability to independently implement FES from its specification is itself a disqualifying flaw for any "standard." AES, by comparison, has published test vectors and can be implemented identically in any language from FIPS 197 alone.

---

## Comparison Summary

| Feature | FES | AES-256-GCM |
|---------|-----|-------------|
| Throughput | ~1 MB/s | ~1 GB/s |
| Nonce/IV | None | Yes (required) |
| Authentication | None | Yes (AEAD) |
| Known-plaintext resistance | None | Complete |
| Ciphertext forgery resistance | None | Complete |
| Peer review | None | 25+ years of global analysis |
| Hardware acceleration | None | AES-NI on all modern CPUs |
| Standardization | Self-published | NIST standard (FIPS 197) |
| Quantum resistance | Unknown (no analysis) | 128-bit security (sufficient) |
| Floating-point dependency | Yes (portability risk) | No (integer only) |
| Spec quality | ChatGPT-assisted, typos | Formal, peer-reviewed |

---

## Conclusion

FES is not a credible encryption standard. It is a homebrew stream cipher that lacks the basic security properties expected of any modern cryptographic construction. Its marketing materials contain numerous false and misleading claims about both its own capabilities and the vulnerabilities of established standards.

The claim that AES is "quantum vulnerable" is false. The claim that FES is "impenetrable" is false — we demonstrated practical attacks against the live server. The claim of "industrial strength performance" is false — FES is hundreds to thousands of times slower than AES.

Organizations seeking quantum-resistant encryption should use **AES-256-GCM** (already quantum-resistant) for symmetric encryption, and NIST's post-quantum standards (ML-KEM, ML-DSA) for asymmetric operations. There is no need for FES or any similar unvetted alternative.

---

## SHA-512 → Keystream Relationship Analysis

To understand how FES derives keystreams from keys, we collected 592 experimental data points from the live server (stored in `data/stream_data.json`). Each entry records the key, its SHA-512 hash, expanded key bytes, mapping index (first 16 bits), and the extracted 20-byte keystream for a fixed payload.

### Methodology

Three categories of keys were tested:
- **500 random keys** (`probe_0000` through `probe_0499`) for broad coverage across mapping indices
- **~40 shared-index keys** — groups of 3-5 keys that happen to share the same 16-bit mapping index (first 2 bytes of expanded key), isolating the effect of the remaining offset bits
- **60 sequential keys** (`SecretKey0`-`19`, `TestKey0`-`19`, `Key0`-`19`) to study the effect of small key changes

All encryptions used the same 20-byte payload ("A"×20), dim=8, no scramble — safely within the first phase boundary (size < 44).

**Caveat on key expansion**: Our analysis assumes key expansion is simple iterated SHA-512 (`SHA512(key) || SHA512(SHA512(key)) || ...`). However, the marketing material only says "iterations of SHA512 hashes" and the patent doesn't mention SHA-512 at all. The actual expansion could use HMAC-SHA512 with unknown string constants (e.g., `HMAC-SHA512(key, "part 0")`), counter-mode hashing, or something else entirely. If so, our computed "mapping indices" and "offset bytes" do not correspond to what the server uses, and the "shared mapping index" groups below may not actually share a mapping index on the server. The stream-level findings (chaotic sensitivity, no correlation) remain valid regardless, since they describe what we observe from the server's output.

### Finding 1: Mapping Index Alone Does NOT Determine the Stream

We found 13 mapping indices shared by 2+ keys. In **every case**, the streams were completely different:

```
Mapping index 16853 (4 keys):
  idx_01053  stream[0:8] = [178, 239, 134, 104, 180, 194, 182, 43]
  idx_05592  stream[0:8] = [22, 136, 85, 155, 159, 253, 131, 210]
  idx_08621  stream[0:8] = [166, 32, 233, 225, 103, 104, 231, 160]
  idx_09739  stream[0:8] = [235, 225, 192, 204, 39, 21, 78, 25]
  → 0/20 bytes match at ANY position
  → Unique values per position: [4, 4, 4, 4, 4, 4, 4, 4, ...] (all different)
```

All 13 groups show the same pattern: **zero common prefix**, all 20 positions have unique values per key. The mapping index (which selects the Mandelbrot boundary region) is only the starting point — the offset bits within that region completely change the stream.

### Finding 2: Chaotic Sensitivity to Offset Bits

Keys sharing the same mapping index differ only in the remaining 96 bits (x,y offsets scaled to ~[0, 0.01]). Despite these offsets selecting points separated by tiny fractions of the 0.01×0.01 region, the resulting streams show:

- **0/20 bytes matching** between any pair
- **Hamming distance ~80/160 bits** (near the ~80 expected from random pairs)

This confirms the Mandelbrot boundary exhibits **chaotic sensitivity to initial conditions** — a hallmark of fractal mathematics. Even infinitesimal differences in starting position produce completely uncorrelated iteration sequences.

### Finding 3: No Exploitable Correlation Between Key Bytes and Stream Bytes

For each of the first 5 stream positions, we checked which of the first 20 expanded key byte positions best predicts the stream value. The best correlation found was **2.4 unique stream values per expanded key byte value** — essentially random (ideal random would be ~2.3 for 592 entries across 256 possible values).

No single byte (or small set of bytes) in the expanded key reveals any information about any stream byte. The mapping from key to stream is effectively a one-way function.

### Finding 4: Sequential Keys Are Completely Uncorrelated

Changing a single character in the key (e.g., SecretKey0 → SecretKey1) produces:
- A completely different SHA-512 hash (avalanche effect)
- A different mapping index (different Mandelbrot region)
- A completely different stream (0/10 bytes match between consecutive keys)

This is expected because SHA-512's avalanche property propagates any input change to all output bits.

### Finding 5: Original Key Bytes vs Expanded Key

One pair of keys sharing mapping index 28144 had different original key lengths (10 vs 9 characters) but different expanded key offsets. Their streams were completely different, consistent with the chaotic sensitivity finding. We could not isolate the "key byte navigation" step's contribution because the SHA-512 expansion already makes everything different.

### Implications

1. **The stream is a strong one-way function of the full expanded key.** No shortcut from partial key knowledge to stream prediction exists.
2. **The fractal's chaotic sensitivity provides good diffusion** — small key changes produce completely unrelated streams.
3. **However, none of this helps with the fundamental flaws.** The stream is still deterministic per key, there's still no nonce or authentication, and the known-plaintext attack bypasses all of this complexity by simply recovering the stream from observed plaintext/ciphertext pairs.
4. **The security of FES depends entirely on the stream being secret** — but any known-plaintext exposure reveals it completely. The elaborate fractal derivation adds computational cost without adding security against practical attacks.

---

## Files in This Repository

| File | Description |
|------|-------------|
| `fes.py` | Python implementation of FES based on the published spec |
| `benchmark.py` | Performance and security comparison: FES vs AES-256 |
| `attack_server.py` | Live known-plaintext attack against portalz.solutions |
| `probe_server.py` | Advanced server probing: phase transitions, operator analysis, FOTP |
| `collect_data.py` | Data collection script — gathers key/stream pairs from server |
| `analyze_data.py` | Offline analysis of SHA-512 → stream relationship |
| `data/stream_data.json` | 592 collected key/stream entries |
| `data/shared_index_groups.json` | Groups of keys sharing mapping indices |
| `docs/` | Source documents (spec PDF, FT-Explained, 12 technical papers) |
| `FINDINGS.md` | This document |
| `ALGORITHM.md` | Detailed algorithm specification as reverse-engineered |
