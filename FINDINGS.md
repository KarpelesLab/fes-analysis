# FES (Fractal Encryption Standard) — Investigation & Findings

## Overview

FES is the "Fractal Encryption Standard" by Portalz PTY LTD (Wolfgang Flatow, Conondale QLD, Australia). It claims to be "a standardised specification of Fractal Transformation engineered to replace quantum vulnerable AES encryption."

This document presents our findings from:
- Reading the published specification (FractalTransformationProcessSpecificationV3.pdf)
- Reading the detailed presentation (docs/FT-Explained.pdf)
- Reading all 12 technical papers published by Portalz (Nov 2025 – Feb 2026)
- Reading the marketing materials at portalz.solutions/fes.html
- Reading the European patent EP4388438A1
- Analyzing the AI "peer reviews" (Grok 4, Claude, ChatGPT 5.2) commissioned by Portalz
- Reverse-engineering the algorithm via the live demo at portalz.solutions/fractalTransform.html
- Extracting and analyzing the client-side JavaScript (fes.js, fractal.js)
- Building a Python implementation based on the spec
- Benchmarking FES against AES-256
- Demonstrating 7 practical attacks against the live server
- Collecting and analyzing 592 experimental data points from the live server
- Reverse-engineering all 3 overwrite operator formulas and their application order

**TL;DR**: FES is a simple XOR stream cipher using Mandelbrot iterations as a PRNG. It is trivially broken by known-plaintext attacks, has no authentication, no nonce, and is hundreds of times slower than AES. Despite a suite of 12 papers claiming "logical impenetrability" and "Shannon's perfect secrecy," we demonstrated keystream recovery, decryption, and forgery against the live production server. Three AI "peer reviews" (Grok, Claude, ChatGPT) were solicited by the author and all failed to identify these trivial vulnerabilities, making them worse than useless as security validation.

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

### Claim 10: "Achieves Shannon's Perfect Secrecy in a Practical Framework"

**VERDICT: FALSE**

The Executive Summary (Nov 2025) claims FES satisfies Shannon's perfect secrecy criterion: P(plaintext | ciphertext) = P(plaintext). This is mathematically impossible for any cipher with key reuse, which FES explicitly supports.

Shannon's perfect secrecy requires that the key be:
1. **At least as long as the message** (FES keys are typically 8-20 characters for arbitrarily long messages)
2. **Used only once** (FES reuses the same keystream for every message under the same key)
3. **Truly random** (FES keys are user-chosen passwords)

FES fails all three requirements. Our known-plaintext attack proves P(plaintext | ciphertext) ≠ P(plaintext): given one known plaintext/ciphertext pair, we can decrypt ALL future messages with certainty. This is the exact opposite of perfect secrecy.

### Claim 11: "Logical Impenetrability — Not Computational Hardness"

**VERDICT: FALSE**

The Impenetrability paper (Feb 2026) asserts: "Irreversibility = Perfect Secrecy = Impenetrability" — claiming FES achieves security by "logical impossibility" rather than computational difficulty.

This is a category error. The paper's central argument is that because the password is "discarded" after portal generation, an attacker cannot reverse the process. But our attacks bypass this entirely:
- We don't need to reverse the portal generation
- We don't need to recover the password
- We simply extract the keystream from any known plaintext/ciphertext pair
- The extracted keystream decrypts all other messages and enables forgery

The "logical impenetrability" thesis assumes the only attack vector is password recovery. Real-world cryptanalysis has many more attack vectors, and FES is vulnerable to the most basic one.

### Claim 12: "Password Discard Ensures Security"

**VERDICT: IRRELEVANT**

All FES papers emphasize that the password is "discarded" after Stage 1 (portal generation) and "never applied to the payload." This is presented as a fundamental security advantage over block ciphers like AES.

This is a distinction without a difference:
- In AES, the key schedule expands the key into round keys that transform the plaintext. The original key is not "applied directly" either — the round keys are.
- In FES, the key generates a portal that produces a keystream. The key is not "applied directly" — the keystream is.
- Both are deterministic functions of the key. Both produce the same output for the same key. The intermediate representation (round keys vs portal coordinates) is irrelevant to security.
- AES's key schedule is also "one-way" in practice — you can't recover the key from observing round key operations. This is not unique to FES.

### Claim 13: "Immune to Harvest Now Decrypt Later (HNDL) Attacks"

**VERDICT: FALSE**

The Executive Summary claims immunity to HNDL attacks. HNDL refers to the threat that an adversary records encrypted traffic today and decrypts it later with a quantum computer. FES's purported immunity relies on the false claim that AES is quantum-vulnerable (see Claim 1).

More critically: our attacks work TODAY, without any quantum computer. An adversary who has ever seen a single known plaintext/ciphertext pair for a given key can decrypt all past and future messages under that key immediately. FES is vulnerable to "Harvest Now, Decrypt Now."

### Claim 14: "Infinite Plausible Deniability"

**VERDICT: MISLEADING**

Multiple papers claim that wrong keys produce "plausible" but incorrect decryptions, providing "infinite plausible deniability." The Grok review even claims to have tested this, finding outputs resembling "Bible excerpts, tax forms, code, JSON."

This is true of ANY stream cipher (or ANY cipher at all) — decrypting with a wrong key produces pseudorandom bytes, which will occasionally contain short sequences that look like text. This is not a meaningful security property. AES-CTR with a wrong key produces the same kind of random-looking output.

True plausible deniability in cryptography (e.g., VeraCrypt hidden volumes) requires carefully engineered dual-use containers where a different key reveals a different but coherent dataset. FES does not provide this — it just produces random noise that, in an infinite keyspace, will statistically contain any finite pattern.

### Claim 15: "Ultra Entropic Chaos — Distinct from Both PRNGs and Physical Entropy"

**VERDICT: MEANINGLESS**

The HFN Theory paper (Dec 2025) introduces "Ultra Entropic Chaos (UEC)" as a new category of randomness, distinct from both PRNGs and true random number generators. This is not a recognized concept in any field of mathematics, physics, or computer science.

The Mandelbrot iteration is a **deterministic computation**. Its output is entirely determined by its input. It is, by definition, a PRNG — a function that produces a sequence of values from a seed (the portal coordinates). Calling it something else does not change its mathematical properties.

The "hyperchaotic" label (multiple positive Lyapunov exponents) describes sensitivity to initial conditions, which is a well-studied property of dynamical systems. It does not imply cryptographic security. Many chaotic systems have been broken as ciphers precisely because chaos theory provides tools for analyzing them that standard cryptanalysis does not need.

### Claim 16: "Multi-Pass Design Provides Additional Security"

**VERDICT: FALSE**

All papers recommend "minimum 3 passes" for security. Stage 3 describes the multi-pass design as providing "amplified" security. However:

Our testing proves that with XOR mode (the default):
- **All passes use the identical keystream**
- **Even-numbered passes cancel out** (P ⊕ K ⊕ K = P)
- **Depth 3 = Depth 1** (two passes cancel, leaving one)
- **Depth 2 = NO ENCRYPTION** (ciphertext is base64 of plaintext!)

The "3 passes" default on the demo server provides exactly the same security as 1 pass — zero additional benefit. A user who selects depth=2 gets null encryption.

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

### 3. Portability and Reproducibility Issues

The algorithm has portability concerns that the documentation attempts to address but does not fully resolve.

The HFN Theory paper (Dec 2025, §7.5) explicitly states FES uses **fixed-point decimal arithmetic** rather than floating-point, which would eliminate platform-dependent rounding. However, an earlier client-side JavaScript implementation (`portalz.solutions/qb/js/fractal.js`) reveals a different approach — string-based extraction:

```javascript
var stripped = v[0].toString().replace('.', '');
var streamByte = stripped % 256;
```

This string-based approach is inherently non-portable. The production server may use fixed-point arithmetic (as the papers claim), but the exact format is unspecified: the number of decimal digits, the representation format, and the precise computation of z²+c in fixed-point are never published.

Either way, the algorithm cannot be independently implemented because:
- The fixed-point format and precision are unspecified
- The stream extraction mixing function is unspecified
- The Silo mapping table is unpublished
- The dynamic prime array is unpublished
- The key expansion method is underspecified

Well-designed ciphers are defined entirely in terms of integer arithmetic with published test vectors. AES can be implemented identically in any language from FIPS 197 alone. FES cannot be implemented at all without access to the proprietary server.

### 4. No Genuine Peer Review

- The specification was "driven by a collaboration between ChatGBT AI and Wolfgang Flatow" (sic — the spec misspells "ChatGPT")
- No independent cryptanalysis has been published in any academic venue
- No academic papers, no conference presentations, no formal security proofs
- The "impenetrability proof" is ChatGPT output, not a mathematical proof

The author commissioned three AI "peer reviews" (Grok 4, Claude, ChatGPT 5.2) in February 2026, all of which concluded FES is "unbroken." These reviews are worse than useless because:

1. **They failed to identify trivial attacks.** All three AI reviews concluded FES is resistant to known-plaintext attacks. We demonstrated this attack works trivially against the live server. The AIs were asked to evaluate the system within the author's own "Peer Review Guide" framework, which constrains the review to questions about "logical irreversibility" and excludes the standard cryptographic attack models that actually break the system.

2. **The review framework is rigged.** The FES Peer Review Guide (Feb 27, 2026) defines "break conditions" that exclude the actual vulnerabilities. It asks reviewers to evaluate "logical/geometric irreversibility" — whether the password can be recovered from the ciphertext. This is the wrong question. The right question is whether the *plaintext* can be recovered, which it trivially can via keystream extraction.

3. **AI reviewers uncritically accepted the framework.** None of the three AIs questioned whether the review framework itself was sound. None asked "but what if an attacker doesn't need to recover the password?" None tested the system with actual known-plaintext probing. They evaluated theoretical properties within the author's chosen frame, rather than performing independent adversarial analysis.

4. **The reviews are presented as independent validation.** Publishing AI-generated reviews with perfect 5/5 scores as "independent peer review" is misleading. Genuine peer review means submission to academic cryptography venues (e.g., IACR ePrint, CRYPTO, Eurocrypt, CCS) where reviewers are adversarial experts, not prompted language models.

### 5. The "Fractal" Aspect Is Cosmetic

The Mandelbrot iteration is just a deterministic function that maps (x,y) coordinates to values. It could be replaced by any PRNG or hash function without changing the security properties. The "infinite complexity" of fractals is irrelevant — what matters is whether the keystream is cryptographically secure, which requires formal analysis that has not been performed.

The term "Ultra Entropic Chaos" introduced in the HFN Theory paper is not a recognized concept in any scientific field. The Mandelbrot iteration is a well-studied deterministic dynamical system that has been characterized since the 1980s. Using novel terminology does not create novel security properties.

### 6. Implementation Inconsistencies Reveal Engineering Issues

Our server probing revealed multiple inconsistencies that indicate the implementation has not been rigorously tested:

- **The `xor` checkbox is ignored** — the server always uses XOR regardless of the form parameter state
- **dim=8 produces an entirely different stream** from dim≥10, which all share a common tail — suggesting a different code path or algorithm for the default dimension count
- **FOTP acts as boolean** — any value ≥2 characters produces the same alternate stream, regardless of the actual value. This defeats its documented purpose as a filename/session-specific nonce.
- **Multi-pass XOR cancellation** — even-depth passes produce null encryption, meaning depth=2 returns the plaintext in base64. This should be caught by any basic testing.
- **The "3 passes" default does nothing** — it's equivalent to 1 pass with XOR mode

These are not subtle edge cases. They are fundamental implementation errors that any testing regime would catch.

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
| Nonce/IV | None (FOTP is boolean, not a nonce) | Yes (required) |
| Authentication | None | Yes (AEAD) |
| Known-plaintext resistance | None (single pair reveals full keystream) | Complete |
| Ciphertext forgery resistance | None (trivial with recovered keystream) | Complete |
| Multi-pass security | None (even passes = null encryption) | N/A (single pass is sufficient) |
| Peer review | AI chatbots (Grok, Claude, ChatGPT) — missed trivial attacks | 25+ years of global expert analysis |
| Hardware acceleration | None | AES-NI on all modern CPUs |
| Standardization | Self-published, spec incomplete | NIST standard (FIPS 197) |
| Independent implementation | Impossible (7+ unpublished components) | Any language, byte-identical results |
| Quantum resistance | Unknown (no analysis performed) | 128-bit security (sufficient) |
| Floating-point dependency | Yes (portability risk) | No (integer only) |
| Spec quality | ChatGPT-assisted, 12 papers, no formal proofs | Formal, peer-reviewed, published test vectors |

---

## Conclusion

FES is not a credible encryption standard. Despite a suite of 12 papers, a European patent, and three AI "peer reviews," FES is a homebrew stream cipher that lacks the basic security properties expected of any modern cryptographic construction.

### What FES Claims vs What We Found

| Claim | Reality |
|-------|---------|
| "Impenetrable" | Keystream recovered from a single known-plaintext pair |
| "Shannon's Perfect Secrecy" | Deterministic stream reused for every message under the same key |
| "Logical irreversibility" | Full decryption and forgery demonstrated against live server |
| "Non-deterministic" | Completely deterministic — same key always produces same stream |
| "Infinite plausible deniability" | Standard property of any cipher; not unique or meaningful |
| "Password is discarded" | Irrelevant — attacks bypass password recovery entirely |
| "Multi-pass amplifies security" | Even passes cancel to identity; 3 passes = 1 pass |
| "FOTP provides nonce functionality" | Acts as boolean toggle, not a true nonce |
| "Ultra Entropic Chaos" | Standard deterministic computation; not a recognized concept |
| "Quantum-proof" | No analysis performed; meanwhile, AES-256 already has 128-bit quantum security |
| "Replaces AES" | ~1000x slower, no authentication, no nonce, trivially broken |
| "Peer reviewed" | AI chatbots prompted within the author's own rigged evaluation framework |

### The Core Failure

FES's entire security thesis rests on the claim that the keystream is unrecoverable because the password is "discarded" after generating the fractal portal. This argument has a fatal gap: **the keystream doesn't need to be reverse-engineered from the password — it can be directly extracted from any known plaintext/ciphertext pair.**

Once extracted, the keystream:
- Decrypts all messages of equal or shorter length encrypted with the same key
- Enables forgery of arbitrary messages the server will accept as valid
- Is reusable forever (no nonce means the stream never changes for that key)

This is not an exotic attack. It is the most basic test any cryptographer applies to a stream cipher, and FES fails it completely. The three AI "peer reviews" failed to identify this because they were constrained by the author's review framework, which asks about password recovery rather than plaintext recovery.

### Recommendation

Organizations seeking quantum-resistant encryption should use **AES-256-GCM** (already quantum-resistant with 128-bit security under Grover's algorithm) for symmetric encryption, and NIST's post-quantum standards (ML-KEM, ML-DSA) for asymmetric operations.

The FES_and_AES.pdf paper suggests using FES on top of AES "for compliance plus impenetrability." This is also inadvisable: layering a broken cipher on top of a sound one adds complexity and attack surface without security benefit. If the inner AES layer is secure (which it is), the outer FES layer adds nothing but latency and a false sense of additional security.

There is no need for FES or any similar unvetted alternative. The established cryptographic community has already solved the post-quantum symmetric encryption problem: AES-256 is sufficient.

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
