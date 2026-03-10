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

The exact expansion method is unknown. The HFN Theory paper §4.1 explicitly states: **"The design of Φ is left open in FES"** — it's not specified, only constrained to satisfy key sensitivity, distribution, and intractability. The marketing says "iterations of SHA512 hashes" but the patent doesn't mention SHA-512 at all. Possible implementations:

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

**Hash function identification (exhaustive negative result)**: 13 standard hash function variants were tested by finding 2-byte prefix collision pairs and checking if colliding keys share any stream properties:

```
Tested: SHA-512, SHA-256, SHA-384, SHA-1, MD5,
        SHA-512², SHA-256², HMAC-SHA512(key,"FES"),
        HMAC-SHA512("FES",key), SHA-512(key+"8"),
        SHA-512("8"+key), SHA-512(key+\x00),
        SHA-512(rev(key))

Result: 0/13 collision pairs share K value or any stream bytes.
        All produce 0/42 stream byte matches between colliding keys.
```

This means the server's key derivation either:
1. Uses a hash function or constant not among those tested
2. Uses more than 2 bytes of the hash for Silo indexing (making 2-byte collisions insufficient)
3. Involves domain-separated hashing with unknown constant strings
4. Uses a completely custom hash or key schedule

**The exact key derivation method cannot be determined from black-box testing.**

### 1.2.1 Key Derivation Behavioral Analysis (from server probing)

Extensive black-box testing of the server reveals these key derivation properties:

**Key handling:**
- **Null-terminated C-string**: `"test\x00"` produces the SAME stream as `"test"` — the server truncates at null bytes. This suggests C/C++ or PHP backend.
- **No key truncation**: Keys of length 1 through 500+ all produce different streams. Every byte matters.
- **Key order matters**: "AB" ≠ "BA", "abc" ≠ "cba" — not commutative, consistent with hash-based processing.
- **Case-sensitive**: "test" ≠ "Test" ≠ "TEST"
- **Whitespace-sensitive**: trailing spaces, tabs, newlines all change the stream
- **Empty/null keys rejected**: empty string and "\x00" return no stream

**Hash function identification (NEGATIVE results):**
- K value (block[0] XOR block[13]) has ZERO correlation with SHA-512 of the key — tested: SHA[0] through SHA[7], SHA[0] XOR SHA[1], SHA[0:2] mod 256, sum(SHA) mod 256, SHA XOR fold, SHA512(SHA512(key))[0]. All 0/95 matches.
- b[0] values for single-char keys show 0 matches with SHA-256[0] and SHA-384[0]
- Keys with the same SHA-512[0:2] prefix produce ZERO stream correlation (test_shared_index.py)
- b[0] values show no simple arithmetic relationship to character codes (80 unique XOR values, 78 unique ADD values out of 95 chars)
- NOT raw SHA-512, SHA-256, SHA-384, or MD5 (at the byte level)

**Timing:**
- Constant ~250ms (±40ms network jitter) regardless of key length (1 to 512 chars)
- Suggests a single, fixed-cost hash operation — NOT iterative PBKDF2 which would scale
- Cannot distinguish between: SHA-512 with constant iterations, single SHA-256, or any other constant-time hash

**Prefix-sharing analysis:**
- Keys "Se", "Sec", "Secr", "Secre", "Secret" have 0% stream correlation pairwise
- Proves the ENTIRE key is hashed at once (not processed byte-by-byte with running state)
- The per-byte navigation described in FT-Explained occurs AFTER hash-based portal selection

**K value systematics:**
- K=0 for ALL 95 printable ASCII single-char keys
- K≠0 for almost all multi-char keys (76 unique K values out of 90 two-digit numeric keys)
- K for 'A'×N (N=1..32) shows no detectable pattern — values appear pseudo-random
- K(A+digit) XOR K(B+digit) is NOT constant — first byte doesn't additively combine
- K cannot be computed from the other 12 bytes of a block (varies across blocks)

**FOTP (Filename/Session Portal Migration):**
- **Boolean mechanism**: len(FOTP) >= 2 → active; len(FOTP) < 2 → transparent (no effect)
- **Value irrelevant**: ALL FOTP values (len>=2) produce IDENTICAL stream: "xx" = "test" = "longFOTP123"
- **Forces K=0**: At ALL dimensions, FOTP-active streams have K=0
- **Transparent for K=0 keys**: Single-char keys produce the same stream with or without FOTP
- **NOT concatenation**: FOTP='test' + key='A' ≠ key='Atest' and ≠ key='testA'
- **Key-dependent**: Different keys with same FOTP produce different (uncorrelated) streams
- **Adds at most 1 bit**: on/off binary decision, no nonce properties
- **Implementation inference**: `if len(fotp) >= 2: use_k0_portal_mode()`

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

### 1.5 Navigation Analysis Findings (from FT-Explained precise data)

**Hypotenuse values** from the FT-Explained table are extremely small (25 decimal places):
```
Step D→e:   hyp ≈ 5.77e-12
Step e→m:   hyp ≈ 6.19e-12
Step m→o:   hyp ≈ 2.45e-12
Step o→ :   hyp ≈ 4.55e-12
Step  →P:   hyp ≈ 1.05e-11
```

**V3 spec formula discrepancy**: The V3 spec claims `cv = int(FV)`, `tv = cv mod 256`. But at the Secret99 portal, int(FV) = 5874, and 5874 mod 256 = 242, which does NOT match the actual stream byte 215. The correct stream byte (215) corresponds to the first 3 fractional digits: 727 mod 256 = 215. This confirms the V3 spec's `int(FV)` formula is incorrect for the actual implementation — the fractional digits are used.

**Angle vs navigation direction discrepancy**: FT-Explained lists angle at byte 'D' = 3.727°, but the actual step direction from D→e (computed from portal coordinate deltas) is 190.455° — they don't match. The relationship between the tabulated "angle" and the actual geometric step direction involves the dynamic prime modulus and byte-dependent hypotenuse in ways not yet fully understood.

**Roundtrip navigation test limitation**: Reverse-navigating from the Fractal Portal and then forward-navigating back is self-consistent for ANY formula choice — this only measures convergence quality, not formula correctness. Any (iter, mod, hyp) combination gives near-zero roundtrip error.

**Secret98 portal**: Located at (-0.874066561899989..., -0.671977900889159...), an entirely different Mandelbrot region from Secret99 (-2.089..., -0.087...). This confirms hash-based full key expansion determines the portal region, not just an offset from a fixed point.

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

### 2.5 The HFN Iteration Loop (from HFN Theory Algorithm 1)

The complete stream generation loop, as given in HFN Theory paper (page 10):

```
Z_0 ← Φ(key)                              // Portal mapping
state ← Z_0
S ← ε                                     // empty bitstring
while |S| < L do                           // L = target stream length
    V ← F(state)                           // fractal evaluation (z = z² + c)
    θ ← Γ(V)                              // geometric extraction (angles, radii)
    state ← N(state; θ)                    // navigate using extracted parameters
    b ← Extract(V)                         // bit extraction from V (NOT navigated state!)
    S ← S || b                             // append to stream
end while
return first L bits of S
```

**Critical**: Extract operates on V (the fractal evaluation), not on the navigated state. The same V drives both navigation AND bit extraction.

State evolution formula: `Z_{t+1} = N(Z_t; Γ(F(Z_t)))` — where Γ maps the fractal evaluation F(Z_t) to geometric parameters θ_t.

### 2.5.1 Stream Extraction ("12 Significant Bytes")

Per the Peer Review Guide §6 and HFN Theory Appendix B:

> "12 significant bytes are extracted per iteration per dimension via a memory transfer."

HFN Theory §7.5 states each dimension contributes **112 bits** (14 bytes) to the key space. But the Peer Review Guide says **12 bytes** per iteration per dimension — the discrepancy suggests 112 bits is the coordinate precision per dimension pair, while 12 bytes (96 bits) is what's extracted per iteration.

The extraction process (from HFN Theory Appendix B, the most concrete description):

```
For each dimension j:
    1. Interpret Re(V_{t,j}) and Im(V_{t,j}) as signed fixed-point integers
    2. Concatenate their binary encodings
    3. Apply a MIXING FUNCTION ("a small cryptographic permutation")
    4. Take the first b bits as output for that dimension
Global Extract: concatenate across dimensions
```

This breaks down into three stages (from FES-Stage-2 §5.1-5.2):

**Stage A — Raw-State Byte Extraction** (Stage-2 §5.1):
```
For each dimension j:
    1. Interpret ℜ(V_{t,j}) and ℑ(V_{t,j}) as signed fixed-point integers
    2. Concatenate their binary encodings
    3. Extract bytes "directly from internal fractal state values"
       - Preserves "all significant bits of the underlying state"
       - Does NOT rely on rounding, formatting, whitening, or compression
       - "The full internal precision of the state contributes to the output"
```

**Stage B — Nonlinear Rolling Transformation** (Stage-2 §5.2):
> "Extracted bytes are passed through a nonlinear rolling transformation that introduces inter-byte and inter-iteration dependencies."

The HFN Theory paper describes this as **"a small cryptographic permutation"**. This mixing step prevents attackers from isolating or modelling independent output streams. The exact transformation is proprietary.

**Stage C — Optional Ordering Metrics** (Stage-2 §5.3):
Per-byte weighting information derived from fractal state interactions enables deterministic but nonlinear ordering of the final output stream.

The global Extract concatenates across dimensions. For D=8 (4 dimension pairs), each iteration produces 4 × 12 = **48 bytes** of stream.

**Critical**: The HFN Theory paper §7.5 explicitly states FES uses **fixed-point (decimal) arithmetic**, not floating-point. This eliminates platform-dependent rounding behavior and ensures deterministic cross-platform reproducibility. Each dimension pair contributes 224 bits of coordinate precision (14 hex bytes × 2 for x and y).

### 2.5.1 What Byte Extraction is NOT

Exhaustive testing against the 12 known portal positions from FT-Explained (Secret99, "Demo Payload") confirmed:

- `int(FV) mod 256` does NOT produce correct stream bytes (V3 spec formula is wrong)
- No single `(iteration, component, digit_count)` formula matches all 12 stream bytes
- Binary fixed-point extraction (from zx, zy, |z|, |z|², or their XOR/sum) at any bit offset produced zero matches across all 12 positions
- Decimal digit groups (2, 3, or 4 digits) of any component mod 256 do not consistently match
- The "nonlinear rolling transformation" is the key missing piece — without it, raw extraction values cannot be mapped to stream bytes

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

### 2.8 Cross-Dimension Stream Structure

**Odd dimension rounding**: The server rounds odd dimensions up to the next even number. dim=3 produces the same stream as dim=4, dim=5=dim=6, dim=7=dim=8, dim=9=dim=10. This confirms the dimension-pair model (D/2 pairs).

**Dimension pair contributions**: Each additional dimension pair modifies the stream. The modification pattern suggests **XOR combination** of per-pair contributions:

```
key="Secret99", length=24:
  dim=2:  [0, 236, 132, 69, 152, 194, 255, 39, 26, 246, 205, 118, ...]
  dim=4:  [121, 41, 184, 220, 184, 4, 115, 180, 101, 240, 246, 190, ...]
  dim=6:  [121, 41, 179, 181, 201, 105, 47, 22, 199, 82, 84, 28, ...]
  dim=8:  [215, 27, 210, 179, 226, 199, 7, 46, 14, 223, 201, 97, ...]

  d(4→6) XOR: [0, 0, 11, 105, 113, 109, 92, 162, 162, 162, 162, 162, 162, 0, 0, ...]
                                 pair 3 contributes at positions 2-12 only ↑
```

Key observations:
- Each pair contributes ~12 bytes (consistent with "12 bytes per iteration per dimension")
- The contribution offset varies per pair (pair 3 contributes at positions 2-12, not 0-11)
- The overlap pattern is **key-dependent** (different keys show different sharing boundaries)
- dim=2 stream[0] = 0 for Secret99 (possibly pair 1 has no contribution at position 0)

**dim=8 vs dim≥10 independence**: Dimensions ≤8 and ≥10 use fundamentally different code paths. The streams are completely unrelated:

```
key="Secret99", length=24:
  dim= 8: [215, 27, 210, 179, 226, 199, 7, 46, ...]  (family A)
  dim=10: [69, 64, 238, 13, 65, 208, 83, 154, ...]    (family B - completely different)
```

Within family B (dim≥10), pairs share a common tail (identical from ~position 14 onward), with only the first ~14 bytes differing per dimension count.

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

**Empirical findings about the Sort Array** (from scramble permutation recovery):

The scramble permutation was recovered via KPA (2 queries: uniform bytes for stream, unique bytes for permutation). Key findings:

1. **The XOR stream is identical** with and without scramble (verified for Secret99 at lengths 12, 24, 32)
2. **Sort Array z values do NOT correspond to any FT-Explained column**: The Sort Array ordering doesn't match FV, angle, hypotenuse, or stream byte ordering. The Sort Array uses z values from the FULL multi-dimensional computation (all dimension pairs), not just the first pair's |z_6|.
3. **The permutation changes with dimension count**: dim=2, 4, 6, 8 all produce different permutations, confirming the Sort Array depends on the specific dimension pairs involved.
4. **The permutation grows coherently with payload length**: existing orderings are preserved as new positions are inserted.

```
Recovered permutations for key="Secret99", dim=8:
  len= 8: π=[6, 7, 1, 5, 3, 4, 2, 0]
  len=12: π=[8, 6, 7, 10, 1, 5, 11, 3, 4, 2, 0, 9]
  len=16: π=[12, 13, 8, 6, 7, 10, 1, 15, 5, 14, 11, 3, 4, 2, 0, 9]
  len=24: π=[12, 13, 8, 22, 6, 7, 10, 1, 15, 17, 5, 14, 11, 3, 4, 23, 21, 19, 20, 16, 2, 18, 0, 9]
```

The Peer Review Guide §7.4.1 shows Sort Array values ranging from 37.4 to 15369 across 32 byte positions — vastly different from FV ≈ 5874.727 at all positions. This confirms the Sort Array captures z values from multiple dimension pairs at multiple iterations.

**Empirical finding**: With scramble enabled:
- Stream is IDENTICAL to non-scramble stream (empirically confirmed)
- Stream is deterministic for a given key
- Stream is consistent across message lengths within a phase
- Known-plaintext attacks work identically (recover both stream and permutation with 2 queries)

### 3.5 Multi-Pass (Depth) Behavior

**Verified**: The `depth` parameter controls the number of passes (1-7 in the UI).

**Without scramble**: All passes use the **identical stream**:

```
depth=1 (odd):  encrypted normally
depth=2 (even): XOR cancels → null encryption (ciphertext = base64 of plaintext!)
depth=3 (odd):  same as depth=1
depth=4 (even): null encryption again
```

**With scramble (the server default)**: Each pass produces a **different effective stream** because the scramble permutation reorders bytes between passes, preventing simple XOR cancellation:

```
depth=1: ct=[68, 215, 199, 193, 118, ...]
depth=2: ct=[51, 183, 191, 68, 69, ...]   (different, real encryption)
depth=3: ct=[183, 229, 227, 193, 118, ...] (different from both depth=1 and depth=2)
```

However, the combined (stream + scramble permutation) operation is still deterministic per (key, depth, length). A known-plaintext attack recovers both the effective XOR stream and the scramble permutation with 2 chosen-plaintext queries, enabling decryption of all messages at that depth.

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

## Visualization Code Analysis (qb/js/fractal.js)

The online demo's JavaScript visualization reveals simplified versions of the core algorithms:

### Stream Byte Extraction (Simplified)
```javascript
var v = pixelValue(cx, cy);  // returns [|z|², iterations_hex, 250_hex]
var stripped = v[0].toString().replace('.', '');
var streamByte = stripped % 256;
```
This is **decimal string manipulation**: remove the decimal point from |z|², interpret as integer, mod 256.

### Navigation Step (Simplified)
```javascript
const fv = pixelValue(cx, cy)[0];  // fv = |z|²
const angle = (fv * 360) % 360;    // angleMultiplier = 360
const hypotenuse = ((fv * 1_000_000 % 20000) * 0.000015) * 0.2;
nextX = current.x + cos(angle) * hypotenuse;
nextY = current.y + sin(angle) * hypotenuse;
```

### Critical Differences from Server Implementation
1. **maxDepth**: Visualization uses 200; server likely uses different value
2. **Fixed-point**: Server uses decimal fixed-point (not float64)
3. **Dynamic prime**: Server uses dynamic prime modulus array (not fixed angleMultiplier=360)
4. **Key byte influence**: V3 spec states "Key and/or SHA byte values can influence av and hv"
5. **Nonlinear mixing**: Server applies inter-byte rolling transformation after raw extraction

### Verification Against Known Data
- At Secret99 portal, standard Mandelbrot gives |z₅|² = 5872.87, but FT-Explained shows FV = 5874.73 — a ~0.03% discrepancy confirming the server uses different precision/method
- The frac[:3] mod 256 formula produces 215 (matching stream byte 0 for Secret99), but ALL 12 FV values give 215 because FV ≈ 5874.727 for all positions — the per-byte diversity comes from the mixing function

### V3 Spec Portal Coordinate Discrepancy
V3 spec diagrams show completely different portal coordinates from FT-Explained:
```
V3 spec:       Secret99 Portal: x ≈ -1.907, y ≈ +0.793
FT-Explained:  Secret99 Portal: x ≈ -2.089, y ≈ -0.087
```
Different Mandelbrot regions entirely — indicates the Silo table or software version changed between documents.

---

## Stream Structure Analysis

### Boundary Artifact: stream[11] == stream[12] (Universal)

**Verified across ALL keys and ALL dimensions tested** (78/78 tests, 12 keys × 6 dimensions + more): the 11th and 12th bytes of the stream are always identical.

```
Position frequency across 48-byte streams (8 keys):
    stream[11]==stream[12]: 8/8 (100%) *** ALWAYS ***
    stream[25]==stream[26]: 7/8 (88%)   ← also very common
    stream[39]==stream[40]: 4/8 (50%)
    stream[53]==stream[54]: 3/8 (38%)
```

The interval between boundaries is **14 positions** (not 12!): 11→25→39→53→...
This suggests the stream extraction produces 14-byte blocks, where the last byte of block N equals the first byte of block N+1.

Key properties:
- The repeated value varies by key (not a fixed constant) — it depends on the portal
- The boundary does NOT shift with dimensions — always at position 11-12 first
- Values are diverse: 22 unique values across 25 keys at position 11
- The "12 significant bytes per dimension" from the spec may actually be 14 raw bytes with a 2-byte overlap at block boundaries

This is a structural artifact of the extraction/mixing pipeline — the mixing function's state creates a 1-byte carry-over at each 14-byte block boundary.

### XOR Invariant: block[0] XOR block[13] = CONSTANT (100% Reliable)

**Verified across ALL keys (15+), ALL dimensions (2, 4, 6, 8, 10, 12), 100% consistency.**

When the stream is split into 14-byte blocks, the XOR of the first and last byte of every block is identical — a key-dependent constant that never varies within a stream:

```
block[n][0] XOR block[n][13] = K    for all n (where K depends on key + dim)

Examples (dim=8):
    Secret99:    K = 81    (0x51)
    hello:       K = 153   (0x99)
    password123: K = 184   (0xb8)
    alpha:       K = 23    (0x17)
    gamma:       K = 79    (0x4f)
```

Cross-dimension behavior for "Secret99":
```
    dim=2:  K = 162  (0xa2)
    dim=4:  K = 81   (0x51)    ← same as dim=8!
    dim=6:  K = 81   (0x51)
    dim=8:  K = 81   (0x51)
    dim=10: K = 145  (0x91)
    dim=12: K = 145  (0x91)
```

This is the ONLY position pair (out of 91 possible pairs within a 14-byte block) that has a constant XOR across all blocks. No other pair (i,j) satisfies this.

**Root Cause — 14-byte block = 7 bytes Re(z) + 7 bytes Im(z):**

Confirmed at dim=2 (single pair): each 14-byte block is the concatenation of Re(z) and Im(z) extracted as 7-byte (56-bit) fixed-point values:
```
block = [Re[0], Re[1], ..., Re[6], Im[0], Im[1], ..., Im[6]]
         ^^^^                               ^^^^
         MSB of Re(z)                       LSB of Im(z)
```

Therefore: **block[0] XOR block[13] = Re(z)[MSB] XOR Im(z)[LSB] = K** for all z in the Mandelbrot orbit. This is a property of the fractal iteration itself, not the mixing function.

For single-char keys, K=0 means Re(z)[MSB] == Im(z)[LSB] for every z in the orbit — a symmetry property of those specific portals.

**K = XOR of per-dimension-pair constants (100% confirmed across 15 keys):**
```
K(dim=2)  = K_pair0
K(dim=4)  = K_pair0 XOR K_pair1
K(dim=6)  = K_pair0 XOR K_pair1 XOR K_pair2
K(dim=8)  = K_pair0 XOR K_pair1 XOR K_pair2 XOR K_pair3

Per-pair constants (Secret99):
    K_pair0 = 162,  K_pair1 = 243,  K_pair2 = 0,  K_pair3 = 0
```

This proves dimension pairs' contributions are **combined via XOR** in the stream.

**Implications:**
- **Distinguisher from random data**: For any ciphertext, extract the stream (via KPA), split into 14-byte blocks, check if `block[0] XOR block[13]` is constant. Random data would have ~1/256 chance per block.
- **Extraction format confirmed**: 14 bytes = 7 bytes Re + 7 bytes Im = 56 bits each = 112 bits total per pair per iteration
- **Cross-dimension XOR combination**: Multiple dimension pairs are combined by XOR, not concatenation or addition
- **Stream convergence**: dim=4 and dim=8 produce IDENTICAL streams from block 1 onward (only block 0 differs). Additional dimension pairs only affect the first extraction block.

### Stream Convergence Across Dimensions

Empirical testing reveals that streams at different dimensions converge after the first block:

```
Convergence from block 1 onward:
    dim=6 vs dim=8:  ALWAYS converge (all keys tested)
    dim=4 vs dim=8:  ~60% of keys converge (when K_pair2 = K_pair3 = 0)
    dim=2 vs dim=4:  Partial convergence for some keys (K_pair1 = 0)
    dim=2 vs dim=8:  Rarely converge (dim=2 uses different orbit)
```

When K_pair_N = 0, the added pair only affects block 0. When K_pair_N ≠ 0, the pair's contribution persists across all blocks. Pairs with K_pair=0 have portals that escape the Mandelbrot set after the first iteration — they contribute their portal value to block 0 but produce no further output.

**Critical finding — Most dimension pairs' portals ESCAPE the Mandelbrot set:**

```
Secret99 per-pair K values (dim=2 through dim=50):
    K_pair0 = 162  (bounded orbit — contributes to all blocks)
    K_pair1 = 243  (bounded orbit — contributes to all blocks)
    K_pair2 = 0    (escaping orbit — block 0 only)
    K_pair3 = 0    (escaping orbit — block 0 only)
    K_pair4 = 192  (bounded orbit — dim≥10 code path)
    K_pair5 through K_pair499 = ALL ZERO  (all escaping!)

K stabilizes at 145 from dim=10 through dim=1000+
```

This pattern holds for all keys tested:
- Secret99: stabilizes at dim=10 (K=145)
- hello: stabilizes at dim=16 (K=197)
- AB: stabilizes at dim=16 (K=151)

**Devastating implication for FES security claims:**
- The spec claims "112N bits of key space" for N dimensions
- In practice, only ~3-5 dimension pairs have bounded orbits
- Adding dimensions beyond the stability point adds ZERO cryptographic strength
- dim=1000 produces the SAME stream (blocks 1+) as dim=16/32/64
- The effective key space is ~3-5 × 112 = 336-560 bits, NOT 112N bits

**Block 0 difference between dimensions**: the XOR of block 0 at dim=4 vs dim=8 shows the contribution of pairs 2+3. Escaped pairs contribute K_pair=0 meaning block[0]==block[13] for their contribution.

### Mixing Function Analysis

The "nonlinear rolling transformation" (Stage-2 §5.2) has these confirmed properties:

1. **Preserves the XOR invariant**: output[0] XOR output[13] = K for all inputs
2. **block[11] XOR block[12] ∈ {0, 128}**: positions 11 and 12 differ only in MSB (bit 7)
3. **NOT raw Mandelbrot z values**: Mandelbrot recurrence z_{n+1} = z_n² + c does NOT hold between consecutive blocks (tested all standard binary fixed-point formats)
4. **Blocks represent navigated fractal evaluations**, not consecutive z² iterations: per HFN Algorithm 1, each block comes from V = F(state) where state is updated via geometric navigation
5. **XOR invariant is key-derived, not mixing-derived**: K=0 for all single-character keys regardless of dimension, suggesting the invariant comes from the extraction/portal properties

**Byte-level statistical analysis** (40+ keys, 200+ blocks at dim=2):

6. **All 14 byte positions have near-uniform entropy** (~6.9-7.0 bits out of 8 max). No position is obviously "raw MSB" or "raw LSB" — the mixing function spreads entropy uniformly across all positions.
7. **byte[0] spans the full 0-255 range** uniformly. Since Mandelbrot z values are bounded in [-2, 2], the MSB of a raw 56-bit fixed-point number would cluster near specific values. The uniform distribution proves the mixing function significantly transforms the raw extraction output — blocks are NOT simply [Re₇ || Im₇].
8. **block-to-block deltas at position 0 EQUAL deltas at position 13** — verified 100% across all keys. This means Δ(block[n][0]) = Δ(block[n][13]) for consecutive blocks, a very strong structural constraint unique to the (0,13) pair.
9. **No other position pairs share identical block-to-block deltas** — only (0,13).
10. **positions (7,8) have moderately reduced XOR entropy** (6.4 bits vs ~7.0 for other pairs), suggesting a weak correlation between Im[0] and Im[1] but not a constant relationship.
11. **No repeated blocks** in 40-block streams (any key) — the inter-iteration dependency ensures unique blocks even for periodic Mandelbrot orbits.
12. **Nibble entropy is uniform** across all positions (~3.9-4.0 bits out of 4 max). No nibble-level structure is visible.
13. **K cannot be computed from the other 12 bytes** — tested XOR of various byte subsets, individual bytes; all vary across blocks while K remains constant. K is truly a key+dim constant determined by the initial state.

**"12 significant bytes" interpretation**: The 14-byte block contains exactly **2 derived bytes**:
- byte[13] = byte[0] XOR K (the XOR invariant — K is constant per key+dim)
- byte[12] ≈ byte[11] (differ only in bit 7, with bit-7 flip determined by block index)

This leaves **12 independent bytes** per block (positions 0-11), matching the spec's "12 significant bytes per dimension per iteration." The website's claim of **"104 bits per dimension"** = 13 bytes likely counts positions 0-12 as significant (byte[12] has 7 independent bits relative to byte[11], so 12×8 + 7 = 103 ≈ 104 bits).

**Period-3 pattern in the bit-7 flip** (byte[11] vs byte[12], dim=2 only):

At dim=2, the XOR between byte[11] and byte[12] follows a period-3 pattern by block index:
```
Blocks at index 0 mod 3: ALWAYS XOR=0   (100%, 500/500 across 50 keys)
Blocks at index 1 mod 3: ~39% XOR=128   (key-dependent)
Blocks at index 2 mod 3: ~63% XOR=128   (key-dependent)
```

This period-3 pattern is SPECIFIC to dim=2 (single pair). At dim≥4, the pattern breaks due to XOR combination of multiple pairs, though block 0 universally has XOR=0 across all dims and all keys.

The period-3 structure implies the mixing function or extraction process has a 3-step cycle when operating on a single dimension pair. This could relate to:
- A 3-iteration pipeline in the fixed-point arithmetic
- A 3-element state machine in the mixing function
- Three-fold symmetry in the Mandelbrot evaluation

**No bit-level Re/Im cross-correlations**: Systematic testing of all 7×7×8×8 = 3136 bit-position combinations between Re and Im bytes found ZERO correlations above 80% or below 20%. The mixing function effectively decorrelates Re and Im at the bit level (except for the MSB/LSB XOR invariant).

### Ignored Parameters (Server-Side)

The following parameters are completely IGNORED by the server (stream unchanged):
- `asciiRange`: values 128, 256, 512 all produce identical streams
- `ms` (mapping scale): values 0.001, 0.01, 0.1, 1.0 all identical
- `whirl`: empty, "on", "1", "test" all identical

This contradicts the spec's claim of context-bound key expansion incorporating "configuration state."

### Key Byte Influence on Stream (V3 Spec Confirmation)

V3 spec §Navigation: "Key and/or SHA byte values can influence av and hv. This further reduces fractal stream determinism."

This means the stream generation depends on BOTH:
1. The portal coordinates (from Silo + key expansion)
2. The raw key bytes or SHA-512(key) bytes, mixed into each navigation step

Empirical confirmation: SHA-512 of the key has ZERO direct byte-level correlation with the stream (0/12 matches for all keys tested). The key bytes influence navigation indirectly through the angle/hypotenuse computation, not as a simple XOR/ADD with the extracted values.

### Stream Stability

The stream is completely stable across payload lengths within a phase:
- Secret99 dim=2: first 8 bytes identical for lengths 12 through 48
- Secret99 dim=8: first 8 bytes identical for lengths 12 through 48

### Sort Array Ordering (Scramble Permutation Recovery)

The scramble permutation is derived from a **Sort Array** — the sorted order of |z|² values at each navigated Mandelbrot position. Recovery via 2 queries (uniform bytes for stream, unique bytes for permutation) reveals:

1. **Position 12 consistently has the smallest |z|² value** across multiple keys at dim=8. This is the byte position that appears first in the sort order (rank 0), meaning the Mandelbrot evaluation at the 12th extraction step consistently yields the smallest magnitude.

2. **Permutations are deterministic** — recovering the same key twice produces identical Sort Array orderings.

3. **Near-random pairwise distances** — Kendall tau distances between different keys are ~40-60% of maximum, consistent with independent random permutations. No two keys share similar orderings.

4. **Keys with shared prefix have uncorrelated orderings** — "A0" through "A9" show no more similarity to each other or to "A" than random key pairs. This confirms the entire key determines the portal (and thus the Sort Array), not individual characters.

5. **Sort Array ordering is key-dependent but structurally consistent** — the structural property that position 12 tends to have the smallest value suggests a systematic feature of the Mandelbrot region selected by the Silo, not a key-specific property.

---

## Can the Server's Stream Be Independently Reproduced?

**No.** Multiple compounding unknowns prevent independent implementation:

1. **The key expansion method is unknown.** 13 standard hash function variants (SHA-512, SHA-256, SHA-384, SHA-1, MD5, double hashes, HMAC variants, salted versions) all failed collision testing — none produced keys with shared stream properties. Server uses null-terminated C-strings, hashes the entire key at once (not byte-by-byte), with constant ~250ms timing regardless of key length. The spec claims context-binding to config params, but asciiRange/ms/whirl are demonstrably ignored.

2. **The default Silo is unpublished.** 65,536 pre-computed (x,y) coordinates, GUID-derived, with no way to regenerate them. No client-side code performs Silo lookup — all processing is server-side.

3. **The extraction produces 14-byte blocks (not 12)** organized as [Re₇ || Im₇], with per-pair outputs combined via XOR (contradicting the HFN paper's claim of concatenation). The "12 significant bytes" from the spec is actually 14 raw bytes with 2 bytes of overlap at block boundaries.

4. **Fixed-point arithmetic uses "decimal (or integer)" precision** (HFN Theory §7.5) — not standard IEEE floating-point. The exact format (number of decimal digits, representation) is unpublished. Sort Array values have exactly 16 fractional decimal digits (~53 bits).

5. **The dynamic prime array is unpublished.** The "randomly selected but fixed" primes used for angle/hypotenuse modulus.

6. **The nonlinear rolling transformation is proprietary.** This mixing function has "inter-byte and inter-iteration dependencies" (Stage-2 §5.2). It preserves the XOR invariant (block[0] XOR block[13] = K), preserves the Im[4]≈Im[5] property (XOR ∈ {0, 128}), but prevents Mandelbrot recurrence from being detected between blocks.

7. **Key byte mixing in navigation is unspecified.** V3 spec confirms key/SHA bytes influence angle and hypotenuse, but the exact mechanism is unknown.

8. **The B_seed permutation is unknown.** 2550 swap positions from an unspecified "deterministic pseudo-random generator."

9. **Multi-pass behavior and phase transitions are undocumented.** The mechanism governing how many passes and where boundaries fall is not in any published document.

10. **Per-pair portal independence**: Each dimension pair gets its own portal, independent of the total dimension count. Per-pair portals are derived from partitioned key material (presumably 16 bytes per pair from the expanded key).

10. **Cross-coordinate coupling parameters (α_i, β_i) are unknown.** If FES uses the coupled N-dimensional Mandelbrot variant.

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
