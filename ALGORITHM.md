# FES Algorithm — Comprehensive Reverse-Engineered Specification

This documents the FES algorithm as understood from all available sources:
1. The published PDF spec (FractalTransformationProcessSpecificationV3.pdf)
2. Black-box testing of the live server at portalz.solutions
3. Analysis of the JavaScript frontend code (fes.js — UI only)
4. Analysis of the fractal visualization code (qb/js/fractal.js — reveals core computation)
5. The European patent EP4388438A1
6. The detailed presentation (docs/FT-Explained.pdf — contains test vectors and worked examples)
7. The Peer Review Guide (docs/FES_Peer_Review_Guide.pdf — Feb 27, 2026, most detailed spec)
8. The Master Technical Paper (docs/Master-Paper.pdf)
9. FES Stage 1/2/3 papers (docs/FES-Stage-{1,2,3}.pdf)
10. Hyperchaotic Fractal Navigation Theory paper (docs/Hyperchaotic_Fractal_Navigation_Theory.pdf)
11. FES Silos paper (docs/FES-Silos.pdf)
12. FES Impenetrability paper (docs/FES_Impenetrability.pdf)

## Architecture Overview

FES operates in three stages:

```
Stage 1 (Input Layer):    Password → Fractal Portal (N-dimensional coordinate)
Stage 2 (HFN Engine):     Fractal Portal → Fractal Stream (keystream bytes)
Stage 3 (Overwrite Layer): Fractal Stream + Payload → Ciphertext
```

The high-level transform is:
```
C = F(P; Portal, D, T, O)
```
where Portal = fractal coordinates, D = dimensionality, T = passes, O = operator set.

---

## Stage 1: Input Layer (Password → Fractal Portal)

### Parameters

| Parameter | Description | Default (online demo) |
|-----------|-------------|----------------------|
| `dimensions` | Number of dimensions (key space = dimensions × 112 bits) | 8 (896 bits) |
| `depth` | Mandelbrot iteration depth / max iterations | Appears fixed server-side |
| `scramble` | Enables per-pass payload reordering via z-value sorting | Off |
| `xor` | Use XOR combination (vs addition mod 256) | On |
| `whirl` | Unknown additional transformation | Off |
| `asciiRange` | Byte range for stream values | 256 |
| `ms` | Mapping scale / step size | 0.01 |
| `mapping_size` | Number of pre-computed Mandelbrot regions per Silo | 2^16 = 65536 |
| `FOTP` | Filename/Session Portal Migration — maps same password to different portals | Empty |

### 1.1 Silos (The Mapping Table)

A **Silo** is a pre-computed set of 2^16 = 65,536 (x,y) coordinate pairs ("geometric anchors") within the Mandelbrot boundary region. Each Silo is:

- **Globally unique** — no (x,y) pair appears in more than one Silo
- **Internally unique** — no repeats within a Silo
- **Immutable** once constructed
- **GUID-derived** — generated from a GUID-based process ensuring uniqueness
- **Hierarchical** — Master Silo encrypts Organization Silos (decrypted only in memory)

A **default Silo** is built into FES and is used when no custom Silo is configured. The online demo uses this default Silo. Its 65,536 entries are unpublished and cannot be independently derived.

The patent (EP4388438A1) provides one data point: "Fractal Region 57193 top left is x,y: 0.505, -0.565" — but we could not reproduce this with any combination of scan order, iteration depth, or filter criteria.

### 1.2 Password Expansion

The key is expanded in a **context-dependent manner**, binding the password to all FES configuration parameters (dimensions, FOTP, Silo, etc.). This means:
- Identical passwords with different configurations yield **different portals**
- All parameters contribute to entropy, not only the password
- Configuration changes require full re-navigation

The exact expansion method is unknown. The marketing says "iterations of SHA512 hashes" but the patent doesn't mention SHA-512 at all. Possible implementations:

```python
# Option A: Simple chaining
expanded = SHA512(key)
while len(expanded) < required_bytes:
    expanded += SHA512(expanded[-64:])

# Option B: HMAC with counter/label strings (context-bound)
expanded = b""
for i in range(parts_needed):
    expanded += HMAC_SHA512(key, f"dim={dimensions},fotp={fotp},part={i}")

# Option C: Concatenated keyed hashes
expanded = b""
for i in range(parts_needed):
    expanded += SHA512(key + bytes([i]) + config_string)
```

**Important**: If the expansion uses unknown string constants or config-binding, even knowing SHA-512 is involved is insufficient. Key expansion cannot increase entropy beyond the original key.

### 1.3 Portal Assembly (Key → Fractal Portal)

Per the Peer Review Guide §8.2, the expanded key is consumed per dimension pair as follows:

```
For each dimension pair (i = 0, 1, ..., D/2 - 1):
    1. base_vector_index = 4 hex bytes → selects (x_silo, y_silo) from Silo
    2. Δx = 14 hex bytes → x offset (scaled to small range)
    3. Δy = 14 hex bytes → y offset (scaled to small range)
    4. portal_x_i = x_silo + Δx
    5. portal_y_i = y_silo + Δy
```

Total per dimension pair: 4 + 14 + 14 = 32 hex bytes = 16 bytes = 128 bits. But the spec says 112 bits per dimension — the discrepancy suggests "4 hex bytes" may mean 4 bytes (32 bits), and the offsets use the remaining 80 bits split as 40+40.

With D=8 (4 dimension pairs): minimum 4 × 112 = 448 bits = 56 bytes of expanded key.

The earlier FT-Explained.pdf describes an additional **key-byte navigation step** after the initial portal selection:

```
For each byte bkb in the original key:
    cv = mandelbrot_fractal_value(current_x, current_y)
    angle = cv mod dynamic_prime (degrees)
    hypotenuse = fraction derived from cv (~10⁻¹¹)
    current_x += hypotenuse × cos(angle)
    current_y += hypotenuse × sin(angle)
```

This navigates the portal a tiny distance using the raw key bytes, making the final portal depend on both the expanded key (Silo selection + offsets) and the original key bytes.

### 1.4 Test Vector (from FT-Explained.pdf)

**Key:** `Secret99`, **Payload:** `Demo Payload`

**Portal:** x = -2.08907476180957704082504287877, y = -0.08680597208354758390593279988

The fractal value at the portal is approximately **5874.727** for all iterations, suggesting it is derived from |z|² (squared magnitude) after approximately **5 Mandelbrot iterations**. Our high-precision computation gives |z₅|² ≈ 5872.869 — close but not exact (0.03% off), indicating either additional processing, different precision, or a slightly different formula.

---

## Stage 2: Hyperchaotic Fractal Navigation (Portal → Stream)

### 2.1 Multi-Dimensional Mandelbrot Function

From the HFN Theory paper, FES uses an N-dimensional fractal manifold:

```
Z_{k+1} = MB_D(Z_k)
```

In the simplest form (component-wise squaring):
```
z_i^(k+1) = (z_i^k)² + c_i
```

The theory paper suggests optional cross-coordinate coupling:
```
P_c(z) = (z₁² + α₁c₁ + β₁z̄₂, z₂² + α₂c₂ + β₂z̄₃, ..., z_N² + α_Nc_N + β_Nz̄₁)
```

Each dimension pair (x_i, y_i) is treated as a complex number z_i = x_i + iy_i.

### 2.2 Navigation Step

For each iteration, each dimension pair contributes:

1. **Fractal evaluation**: Compute z = z² + c at current position
2. **Angle extraction**: θ_D derived from fractional part of a state coordinate
3. **Hypotenuse extraction**: r_D derived from magnitude of adjacent coordinate
4. **Geometric update**:
   ```
   x'_i = x_i + r_i · cos(θ_i)
   y'_i = y_i + r_i · sin(θ_i)
   ```

### 2.3 Dynamic Prime Modulus System

Per FT-Explained.pdf (slide 21) and the Peer Review Guide: the angle and hypotenuse modulo values are NOT fixed. Instead:
- An array of "randomly selected but fixed" prime numbers is pre-initialized
- The modulus for each iteration's angle and hypotenuse is selected from this array using the previous iteration's value
- This means the modulus changes every iteration

### 2.4 Angle Doubling Pattern

The fractional part of the angle exactly doubles each iteration — a direct consequence of z=z²+c (which doubles the argument in polar coordinates):

```
Angle sequence for "Demo Payload" (Secret99):
  D:  3.727435...  (seed fractional = 0.727435)
  e: 190.454870... (frac = 0.454870 = 2 × 0.727435 mod 1 ✓)
  m:  29.909740... (frac = 0.909740 = 2 × 0.454870 mod 1 ✓)
  o: 164.819481... (frac = 0.819481 = 2 × 0.909740 mod 1 ✓)
  ... pattern continues for all 12 bytes
```

The integer part varies unpredictably due to the dynamic prime modulus.

### 2.5 Stream Extraction ("12 Significant Bytes")

Per the Peer Review Guide §6 and HFN Theory Appendix B:

> "12 significant bytes are extracted per iteration per dimension via a memory transfer."

The extraction process (from HFN Theory Appendix B):
```
For each dimension j:
    1. Interpret ℜ(V_{t,j}) and ℑ(V_{t,j}) as signed fixed-point integers
    2. Concatenate their binary encodings
    3. Apply a mixing function (small cryptographic permutation)
    4. Take the first b bits as output (b = 96 bits = 12 bytes)
```

The global Extract concatenates across dimensions. For D=8 (4 dimension pairs), each iteration produces 4 × 12 = **48 bytes** of stream.

**Critical**: The HFN Theory paper §7.5 explicitly states FES uses **fixed-point (decimal) arithmetic**, not floating-point. This eliminates platform-dependent rounding behavior and ensures deterministic cross-platform reproducibility.

### 2.6 Stream Length and Multi-Pass

Stream length per pass equals the payload length:
```
|K^(t)| = n   (payload length)
Total stream = n × T  (across T passes)
```

Each pass generates fresh fractal stream by continuing navigation from where the previous pass ended.

### 2.7 Length-Dependent Phase Transitions

**Empirical finding**: The keystream has length-dependent phases. At certain payload lengths, the entire stream changes — stream[0] takes a new value and all bytes are recalculated.

**Detailed measurements** (key: SecretKey99, no scramble):

```
dim=8:  transitions at lengths [72, 100, 128, 198, 226]  intervals: [28, 28, 70, 28]
dim=10: transitions at lengths [100, 156]                 intervals: [56]
dim=12: transitions at lengths [100, 156, 184]            intervals: [56, 28]
dim=14: transitions at lengths [100, 156, 184, 212]       intervals: [56, 28, 28]
dim=16: transitions at lengths [100, 184, 212, 240]       intervals: [84, 28, 28]
```

**Phase transitions are key-dependent** — different keys hit transitions at different lengths from a common set of potential boundary points:

```
dim=8 transitions by key:
  SecretKey99:    [72, 100, 128]       intervals: [28, 28]
  TestKeyAlpha:   [72, 100, 128]       intervals: [28, 28]
  abc:            [44, 128]            intervals: [84]
  MyPassword123:  [44, 100, 128]       intervals: [56, 28]
```

The recurring interval of **28 bytes** for dim=8 is striking. All potential transition points appear to fall on multiples of 28 offset from a base value, with the key determining which boundaries are actual transitions.

Within a phase, stream[0] is stable but inner bytes (e.g., stream[2]) can exhibit sub-transitions (e.g., at length 44 for SecretKey99 with dim=8).

At phase boundaries, `stream[-1] == 0` for the length just before the transition.

### 2.8 Cross-Dimension Stream Sharing

**Empirical finding**: Dimensions ≥ 10 share a **common stream tail**. For a fixed key and payload length, all dimensions 10, 12, 14, 16, 18, 20 produce identical bytes from approximately position 14 onward, with only the first ~14 bytes differing per dimension count.

```
key="TestKeyAlpha", length=40:
  dim= 8: [107, 242, 20, 42, 125, 46, 184, 238, ...] (completely independent)
  dim=10: [131, 86, 155, 58, 99, 129, 250, 172, 208, 84, 146, 248, 248, 13, | 14, 165, 42, ...]
  dim=12: [234, 229, 74, 107, 172, 234, 88, 168, 63, 177, 252, 185, 185, 100,| 14, 165, 42, ...]
  dim=16: [108, 208, 221, 223, 229, 124, 27, 79, 84, 212, 167, 194, 194, 226,| 14, 165, 42, ...]
                                                                                ^ identical from here
```

dim=8 is **completely independent** from all higher dimensions. This suggests the server has a fundamentally different code path or stream extraction for dim=8 versus dim≥10.

---

## Stage 3: Overwrite Layer (Stream + Payload → Ciphertext)

### 3.1 Pipeline Per Pass

For each pass:
1. **Generate Fractal Stream** K^(t) of payload length
2. **Optional: fBlit** (bit swap priming)
3. **Optional: Scramble** (entropy-based reordering)
4. **Apply overwrite operators** in fixed order: XOR → ADD → SPLIT
5. Result becomes input for next pass: P^(t+1) = O(P^(t), K^(t))

### 3.2 Online Demo Form Parameters

The HTML form (`fractalTransform.html`) provides these overwrite checkboxes:
- **xor** (checked by default) — XOR combination
- **add** — additive combination
- **split** (labeled "bit split") — bit rotation

Multiple can be selected simultaneously. When none are checked, XOR is used as default.

The form also provides:
- **scramble** (checked by default) — payload byte reordering
- **depth** (default: 3) — number of passes (1-7)
- **dimensions** (default: 8) — key space selector (8/16/32/64/128/256/512)
- **whirl** — hidden field, commented out in UI (was "Key Whirl" checkbox)
- **asciiRange** — hidden field, always "256"

### 3.3 Overwrite Operators

**Application order** (verified empirically): When multiple operators are enabled, they are applied in this fixed sequence: **XOR → ADD → SPLIT**

#### XOR (Default)
```
cipher_byte = payload_byte XOR stream_byte
```
The stream is applied in **reverse order**:
```
ciphertext[i] = plaintext[i] XOR stream[N-1-i]
```

**Verified**: When no overwrite checkboxes are checked, XOR is applied as default.

#### ADD (Additive)
```
Encrypt: ciphertext[i] = (plaintext[i] + stream[N-1-i]) mod 256
Decrypt: plaintext[i] = (ciphertext[i] - stream[N-1-i]) mod 256
```

**Verified**: ADD uses the same stream index as XOR: `stream[N-1-i]`. The stream bytes are identical whether using XOR or ADD mode.

Note: The `xor` parameter on the form is **ignored by the server** — the server always applies XOR when it's supposed to, regardless of the checkbox state. FT-Explained.pdf describes addition as the standard method, but the live server defaults to XOR.

#### SUB (Substitution-Based)
Fractal-driven byte substitution using a permuted S-box:

**Step 1**: B_seed initialization — B = [0,1,...,255], then 2550 deterministic pairwise swaps from a fixed PRNG seed → produces B_seed (constant across all executions).

**Step 2**: Per-pass permutation — Using the same stable-rank mechanism as Scramble, derive π_sub^(t) from a 256-length sort vector S_sub^(t). Apply: B_work^(t)[j] = B_seed[π_sub^(t)(j)].

**Step 3**: Encryption substitution:
```
i = (p(n) + k(n)) mod 256
p'(n) = B_work[i]
```

Decryption uses the inverse permutation.

#### fBlit (Prime Fractal Bit Swaps)
Performs stream-driven swaps of prime-length bit blocks within the payload.

```
L = 8 × n  (payload bit-length)
Exit if L < 64 (payload < 9 bytes)

p_split = floor(L/4) - 1
p_max = floor(L/5)

Select fixed prime p_f < p_split from prime list
Select maximum prime index I_max where P[I_max] < p_max

Static ZAP Phase (2 deterministic swaps):
    SwapBits(P, 0, p_f, p_f)
    SwapBits(P, L - 2*p_f, L - p_f, p_f)

Dragon Phase (N = min(256, floor(L/100)) stream-driven swaps):
    For j = 0..N-1:
        i_p = k_{4j} mod (I_max + 1)  →  p = P[i_p]
        src = floor(k_{4j+1} · (L-p) / 128), clamped to [0, L-p-1]
        d = +1 if src < L/2, else -1
        Δ = floor(k_{4j+3} · p / 128)
        tgt = src + d · (p + Δ), clamped to [0, L-p-1]
        SwapBits(P, src, tgt, p)
```

Decryption replays swaps in reverse order.

#### bit split (Byte-Local Bit Rotation)

**Verified formula** (confirmed against live server with 3 different keys, 8 different input byte values):

```
For payload byte at position i:
    s = stream[N+1-i] mod 7       # NOTE: offset +2 from XOR's stream index!
    cipher[i] = rotate_left(plaintext[i], s)
```

Where `rotate_left(byte, s) = ((byte << s) | (byte >> (8 - s))) & 0xFF`.

Key differences from the Peer Review Guide description:
1. The stream index is `stream[N+1-i]`, NOT `stream[N-1-i]` — a **+2 offset** from XOR/ADD
2. The modulus is **7** (not 8), giving rotation amounts 0-6
3. The operation is a standard circular left rotation of the byte

This means the split operator reads from a different part of the stream than XOR/ADD. The stream used is the same keystream, but accessed at positions offset by +2.

#### bit warp (Prime-Length Bit-Block Rotation)
```
L = 8 × n  (payload bit-length)
Exit if L < 64

For each step:
    Select p_ℓ (prime chunk length, range 19-31) from stream
    Select s_p (split point, range 3-29) from stream

    Process sequential bit blocks of size p_ℓ:
        B = GetBitBlock(P, pos, p_ℓ)
        L_part = floor(B / 2^(p_ℓ - s_p))
        R_part = B mod 2^(p_ℓ - s_p)
        B' = R_part · 2^s_p + L_part
        SetBitBlock(P, pos, p_ℓ, B')
        pos += p_ℓ
```
Decryption inverts split point: s_p ← p_ℓ - s_p.

### 3.3 Scramble Mode

When scramble is enabled, a per-pass reordering is applied:

1. During pass t, raw decimal z values are collected: S^(t) = [s_0, ..., s_{n-1}]
2. Sorting S^(t) produces permutation π^(t) = rank(S^(t)) (ties broken by sequence order)
3. Payload is reordered: P_scr^(t)[j] = P^(t)[π^(t)(j)]

The Sort Array values are also used for substitution (sub) per-pass permutation reordering.

**Empirical finding**: With scramble enabled:
- Keystream values change entirely (not a permutation of the non-scramble stream)
- Stream is still deterministic for a given key
- Stream is still consistent across message lengths within a phase
- Known-plaintext attacks work identically

### 3.5 Multi-Pass (Depth) Behavior

**Verified**: The `depth` parameter controls the number of passes. All passes use the **identical stream** with XOR mode:

```
depth=1 (odd):  encrypted normally
depth=2 (even): XOR cancels → null encryption (ciphertext = base64 of plaintext!)
depth=3 (odd):  same as depth=1
depth=4 (even): null encryption again
...pattern continues
```

This means **multi-pass XOR provides zero additional security** — it's either equivalent to single-pass (odd depths) or completely transparent (even depths). The server's default of depth=3 is identical to depth=1.

### 3.6 FOTP Parameter

**Verified**: The FOTP ("Filename/Session Portal Migration") parameter is active on the live server. Both `fotp` and `FOTP` parameter names work. However:

- FOTP acts as a **boolean**, not a true nonce: any value of sufficient length (≥2 chars) produces the **same alternate stream** regardless of the actual value
- Single-character FOTP values have no effect
- Decryption with wrong FOTP still succeeds (the server ignores FOTP mismatch on decrypt)

```
fotp=''         stream[0:5]=[109, 84, 124, 87, 119]  (default)
fotp='test'     stream[0:5]=[239, 226, 84, 242, 188]  (alternate)
fotp='file.txt' stream[0:5]=[239, 226, 84, 242, 188]  (same alternate!)
fotp='a'        stream[0:5]=[109, 84, 124, 87, 119]  (no effect - too short)
```

### 3.7 Reverse Application

**Critical finding**: The stream is applied in **reverse order**:
```
ciphertext[i] = plaintext[i] XOR stream[N-1-i]
```

Proof (live server, key "SecretKey99", dim=8, no scramble):
```
"AB"   → cipher = [65⊕84, 66⊕109] = [21, 47]           ✓
"ABC"  → cipher = [65⊕124, 66⊕84, 67⊕109] = [61,22,46] ✓
Underlying stream: [109, 84, 124, 87, 119, 51, 133, 129, ...]
```

---

## Encryption / Decryption Summary

### Encryption
```
For T passes:
    K^(t) = generate_stream(portal, pass=t, length=n)
    If scramble: reorder P using sort(z_values)
    If fBlit: apply bit swap priming
    P = apply_operators(P, K^(t))  # xor/add/sub/bit_split/bit_warp
Output: base64(P)
```

### Decryption
```
For T passes (reverse order):
    K^(t) = generate_stream(portal, pass=t, length=n)
    P = reverse_operators(P, K^(t))
    If fBlit: reverse bit swap priming
    If scramble: reverse reorder
Output: P
```

---

## Can the Server's Stream Be Independently Reproduced?

**No.** Multiple compounding unknowns prevent independent implementation:

1. **The key expansion method is unknown and context-bound.** The expansion binds to all config parameters. Without knowing the exact method (simple chaining, HMAC, keyed hash with unknown strings), we cannot compute the expanded key.

2. **The default Silo is unpublished.** 65,536 pre-computed (x,y) coordinates, GUID-derived, with no way to regenerate them.

3. **The fractal value extraction is underspecified.** The spec says "12 significant bytes via memory transfer" from fixed-point mantissa. The exact fixed-point format, precision, and mixing function are not published.

4. **Fixed-point arithmetic details are unknown.** The number of decimal digits, the representation format, and the exact computation of z²+c in fixed-point are not specified.

5. **The dynamic prime array is unpublished.** The "randomly selected but fixed" primes used for angle/hypotenuse modulus.

6. **The B_seed permutation is unknown.** 2550 swap positions from an unspecified "deterministic pseudo-random generator."

7. **Multi-pass behavior and phase transitions are undocumented.** The mechanism governing how many passes and where boundaries fall is not in any published document.

8. **Cross-coordinate coupling parameters (α_i, β_i) are unknown.** If FES uses the coupled N-dimensional Mandelbrot variant.

This means **FES is not a standard in any meaningful sense** — it is a single proprietary implementation that cannot be independently replicated. By contrast, AES can be implemented from FIPS 197 by anyone, in any language, and produce byte-identical results verified against published test vectors.

---

## Security-Relevant Observations

1. **No nonce/IV**: The keystream is entirely determined by the key and config. Same key + config = same stream, always.
2. **No authentication**: Pure encryption, no MAC or tag. Bit-flipping attacks are trivial.
3. **Deterministic stream**: For key K, the stream is deterministic per (key, dimensions, FOTP, Silo, message_length).
4. **Known-plaintext attack is devastating**: Given any plaintext/ciphertext pair, the entire keystream is recovered, enabling decryption and forgery of all messages of equal or shorter length.
5. **Reverse application is irrelevant**: Applying the stream forward or backward doesn't change any security property — it's still `plaintext ⊕ keystream`.
6. **Not independently implementable**: See above — at least 8 missing components prevent interoperable implementation.

## Document Suite

The full FES document suite comprises:
- Master Technical Paper (overview)
- FES Stage 1: Input Layer (Silos, password expansion, portal assembly)
- FES Stage 2: HFN (hyperchaotic navigation, stream generation)
- FES Stage 3: Overwrite Layer (operators, multi-pass)
- FES Silos (compartmentalization concept)
- FES Impenetrability (security claims)
- Hyperchaotic Fractal Navigation Theory (mathematical framework, pseudocode)
- FES Peer Review Guide (most detailed technical specification)
- FT-Explained (worked examples with test vectors)
- Executive Summary, FES and AES comparison
- AI "peer reviews" (Grok, Claude, ChatGPT — all uncritical)
