# FES Algorithm — Detailed Reverse-Engineered Specification

This documents the FES algorithm as understood from:
1. The published PDF spec (FractalTransformationProcessSpecificationV3.pdf)
2. Black-box testing of the live server at portalz.solutions
3. Analysis of the JavaScript frontend code (fes.js — UI only)
4. Analysis of the fractal visualization code (qb/js/fractal.js — reveals core computation)
5. The European patent EP4388438A1
6. The detailed presentation (docs/FT-Explained.pdf — contains test vectors and worked examples)

## Parameters

| Parameter | Description | Default (online demo) |
|-----------|-------------|----------------------|
| `dimensions` | Number of fractal dimensions (key space = dimensions × 112 bits) | 8 (896 bits) |
| `depth` | Mandelbrot iteration depth / max iterations | Appears fixed server-side |
| `scramble` | Modifies stream generation (not just byte reordering) | Off |
| `xor` | Use XOR combination (vs addition mod 256) | On |
| `whirl` | Unknown additional transformation | Off |
| `asciiRange` | Byte range for stream values | 256 |
| `ms` | Mapping scale / step size | 0.01 |
| `mapping_size` | Number of pre-computed Mandelbrot regions | 2^16 = 65536 |

## Phase 1: Initialization (One-Time)

Build a mapping table of "suitable" Mandelbrot boundary regions:

```
mapping = []
for each point (x, y) scanning outward from (0, 0) with step 0.01:
    iterations = mandelbrot_escape_iterations(x, y, max_iter)
    if iterations == max_iter:   skip  (inside set, infinite)
    if iterations > mac:         skip  (too complex)
    if iterations < 2:           skip  (too simple, far outside set)
    mapping.append((x, y))
    if len(mapping) == 65536:    stop
```

This table is constant and can be precomputed and stored.

## Phase 2: Key Expansion

The user's key is expanded to fill `dimensions × 112` bits. The marketing material states this uses "iterations of SHA512 hashes" but does not specify the exact method.

**Possible implementations** (we cannot determine which is used):

```python
# Option A: Simple chaining (our initial assumption)
expanded = SHA512(key)
while len(expanded) < required_bytes:
    expanded += SHA512(expanded[-64:])
expanded = expanded[:required_bytes]

# Option B: HMAC with counter/label strings
expanded = b""
for i in range(parts_needed):
    expanded += HMAC_SHA512(key, f"part {i}")
expanded = expanded[:required_bytes]

# Option C: Concatenated keyed hashes
expanded = b""
for i in range(parts_needed):
    expanded += SHA512(key + bytes([i]))
expanded = expanded[:required_bytes]
```

The patent (EP4388438A1) does **not mention SHA-512 at all** — it describes a purely fractal-based key derivation. The client-side JavaScript (fes.js) performs no hashing; all cryptographic operations happen server-side. Without access to the server implementation, the exact key expansion method is unknown.

**Important implication**: If the expansion uses HMAC or keyed hashing with unknown string constants, even knowing that SHA-512 is involved is insufficient to compute the expanded key. This is yet another barrier to independent implementation.

Note: Regardless of method, key expansion cannot increase entropy beyond the original key's entropy.

## Phase 3: Key Mapping (Key → Fractal Portal)

The expanded key hash is used to navigate to a unique point in the Mandelbrot set:

```
1. n = first 16 bits of expanded_hash  (selects mapping region index)
2. remaining bits split into xm, ym    (offset within the region)
3. Scale xm, ym to [0, 0.01]
4. FMP = mapping[n] + (scaled_xm, scaled_ym)

5. For each byte bkb in the original key:
     cv = mandelbrot_complex_value(current_x, current_y)
     cv_int = integer_from_fractional_digits(cv)
     angle = cv_int mod 360   (degrees)
     hypotenuse = 0.01 / bkb
     current_x += hypotenuse × cos(angle)
     current_y += hypotenuse × sin(angle)

6. Fractal Portal = (current_x, current_y)
```

The `mandelbrot_complex_value` function (from the spec):
```
Iterate z = z² + c at point (cx, cy)
"calculate complex value cv using the Mandelbrot algorithm at current x,y,
 making cv an integer by removing the decimal point and keeping the
 fractional digits"
```

### Detailed Test Vector Data (from FT-Explained.pdf)

The document `docs/FT-Explained.pdf` provides a complete worked example:

**Key:** `Secret99`, **Payload:** `Demo Payload`
**Portal:** x = -2.08907476180957704082504287877, y = -0.08680597208354758390593279988

The fractal value for all iterations is approximately **5874.727**, suggesting it is derived from |z|² (squared magnitude) after approximately **5 Mandelbrot iterations** at the portal point. Our high-precision computation gives |z₅|² ≈ 5872.869 — close but not exact (0.03% off), indicating either additional processing, different precision, or a slightly different formula than standard z=z²+c.

From the fractal value, three quantities are derived per iteration:
1. **Byte transform value** = fractal_value mod 256 (combined with payload byte)
2. **Angle** = fractal_value mod dynamic_prime (degrees, for navigation)
3. **Hypotenuse** = fraction derived from fractal_value (~10⁻¹¹, extremely small navigation steps)

**Critical finding: the angle's fractional part exactly doubles each iteration.** This is a direct consequence of the Mandelbrot squaring operation (z=z²+c doubles the argument of z in polar coordinates):

```
Angle sequence for "Demo Payload":
  D:  3.727435...  (seed fractional = 0.727435)
  e: 190.454870... (frac = 0.454870 = 2 × 0.727435 mod 1 ✓)
  m:  29.909740... (frac = 0.909740 = 2 × 0.454870 mod 1 ✓)
  o: 164.819481... (frac = 0.819481 = 2 × 0.909740 mod 1 ✓)
  ... pattern continues perfectly for all 12 bytes
```

The integer part of the angle varies unpredictably, governed by the **dynamic prime modulus system** (see below). The hypotenuse values are ~10⁻¹¹, keeping all navigation within a ~0.000000000012 square region.

### Dynamic Prime Modulus System

Per FT-Explained.pdf (slide 21): the angle and hypotenuse modulo values are NOT fixed. Instead:
- An array of "randomly selected but fixed" prime numbers is pre-initialized
- The modulus for each iteration's angle and hypotenuse is selected from this array using the previous iteration's value
- This means the modulus changes every iteration, adding another unknown

### Combination Method

FT-Explained.pdf explicitly describes **addition mod 256** (not XOR):
> "The fractal values are added to the payload values. When the sum exceeds 256 then 256 is subtracted."
> "When extracting the payload from the cipher the values are subtracted. When the result is less than zero then 256 is added."

The online server's `xor=on` parameter selects XOR instead, which is mathematically equivalent in terms of security properties but produces different ciphertext bytes. The patent also describes addition. XOR appears to be an alternative mode.

### Previous Analysis

The spec is deliberately vague about which value is used (magnitude, squared magnitude, real part, etc.) and how "removing the decimal point" works. The patent (EP4388438A1) only adds that it is a "30 digit fractal number" that is "truncated."

A client-side demo (`qb/js/fractal.js`, self-described as "a simplified educational abstraction") shows one approach: `zx*zx + zy*zy` (squared magnitude) converted via `str(fv).replace('.','') % 256`. While this is explicitly not the production code, it demonstrates a pattern where the stream byte depends on the **string representation of a floating-point number** — an operation that varies across programming languages and runtimes, making cross-platform reproducibility impossible.

The patent (EP4388438A1) provides one verifiable data point — "Fractal Region 57193 top left is x,y: 0.505, -0.565" — but we were unable to reproduce this with any combination of scan order, iteration depth, or filter criteria, confirming that the mapping table cannot be independently generated from the published information.

## Phase 4: Fractal Stream Generation

Generate a keystream of length N (= payload size) starting from the portal:

```
stream = array of N bytes
(x, y) = fractal_portal

for i in 0 to N-1:
    cv = mandelbrot_complex_value(x, y)
    stream[i] = cv mod 256
    angle = cv mod 360
    hyp = (cv mod hvm) / hvm × 0.01
    x += hyp × cos(angle_in_radians)
    y += hyp × sin(angle_in_radians)
```

Where `hvm` is a modulus constant (not fully specified; likely ~1000).

## Phase 5: Encryption

**Critical finding**: The stream is applied in **reverse order**.

```
For i in 0 to N-1:
    ciphertext[i] = plaintext[i] XOR stream[N - 1 - i]
```

This was confirmed by encrypting multiple messages of different lengths with the same key and observing that shorter messages' ciphertexts correspond to the tail of longer messages' keystream application.

### Proof of Reverse Application

Using key "SecretKey99", dimensions=8, no scramble, against the live server:

```
"AB"          → XOR stream positions used: [stream[1], stream[0]]
"ABC"         → XOR stream positions used: [stream[2], stream[1], stream[0]]
"ABCDE"       → XOR stream positions used: [stream[4], stream[3], stream[2], stream[1], stream[0]]
"hello world" → XOR stream positions used: [stream[10], ..., stream[1], stream[0]]

Underlying stream: [109, 84, 124, 87, 119, 51, 133, 129, 157, 12, 20, ...]

Verification (all match server output):
  AB:    cipher = [65⊕84, 66⊕109] = [21, 47]           ✓
  ABC:   cipher = [65⊕124, 66⊕84, 67⊕109] = [61,22,46] ✓
  ABCDE: cipher = [65⊕119, 66⊕87, 67⊕124, 68⊕84, 69⊕109] ✓
```

## Phase 6: Decryption

Identical to encryption (XOR is self-inverse):

```
For i in 0 to N-1:
    plaintext[i] = ciphertext[i] XOR stream[N - 1 - i]
```

## Phase 7: Base64 Encoding

The ciphertext bytes are base64-encoded (without padding) for the text representation shown in the demo.

## Scramble Mode

When scramble is enabled:
- The keystream values change entirely (not a permutation of the non-scramble stream)
- The stream is still deterministic for a given key
- The stream is still consistent across message lengths
- Known-plaintext attacks work identically

Scramble likely modifies the navigation function during stream generation (e.g., reordering how angle/hypotenuse are computed, or mixing in additional key-derived values).

## Multiple Passes / Length-Dependent Stream Phases

Per the spec: "Multiple passes simply continue with current x,y." The patent adds: "The encryption process can be repeated n times by transferring the buffer to the payload at the end of each pass while maintaining the last x,y key location between passes."

**Empirical finding**: The keystream is NOT a simple infinite sequence — it has **length-dependent phases**. The stream generated for a 32-byte message differs from the stream generated for a 64-byte message, even at the same positions:

```
Key: SecretKey99, dimensions=8, no scramble

stream[0..7] for sizes  4-43: [109, 84, 124, 87, 119, 51, 133, 129]
stream[0..7] for sizes 44-71: [109, 84, 115, 173, 236, 119, 170, 83]
stream[0..7] for sizes 72-99: [201, 231, 30, 87, ...]  (completely different)
```

Phase transition points for dim=8: sizes **[4, 44, 72, 100]** (intervals: 40, 28, 28)
Phase transition points for dim=12: sizes **[4, 72]** (interval: 68)
Phase transition points for dim=16: sizes **[4, 72]** (interval: 68)

Key observations:
- Transitions are **key-independent** — same boundaries for all keys at same dimensions
- Note that for dim=8: 40 + 28 = 68, matching the single interval for dim=12 and 16
- Within each phase, the stream is perfectly consistent across all message lengths
- The known-plaintext attack works within each phase

This suggests the server applies multiple passes based on message length, with phase boundaries determined by the dimension count. The exact mechanism is not specified in any published document.

## Can the Server's Stream Be Independently Reproduced?

**No.** We attempted to reproduce the server's exact keystream and failed due to multiple compounding unknowns:

1. **The key expansion method is unknown.** The marketing material says "iterations of SHA512 hashes" but the patent doesn't mention SHA-512 at all. The actual method could be simple chaining (`SHA512(key) || SHA512(SHA512(key))`), HMAC-SHA512 with unknown string constants (`HMAC-SHA512(key, "part 0") || ...`), counter-mode hashing, or something else entirely. Without knowing the exact method, we cannot compute the expanded key from a user's key string.

2. **The mapping table is unpublished.** 65,536 pre-computed (x,y) coordinates with no way to regenerate them. The patent provides one example — Region 57193 at (0.505, -0.565) — which we could not reproduce with any combination of scan order, iteration depth, or filter criteria.

3. **The "fractal value" extraction is underspecified.** The spec says to compute "the complex value" and "remove the decimal point and keep the fractional digits" but does not define which value (magnitude, squared magnitude, real/imaginary part) or how the decimal-to-integer conversion works across implementations.

4. **String representation of floats varies across languages.** If the implementation uses a `toString().replace('.','')` pattern (as seen in the demo code), the result depends on how many decimal digits the runtime produces — which differs between JavaScript, Python, Java, C++, and even between versions of the same language.

5. **Navigation parameters are unspecified.** The hypotenuse modulus (hvm), scaling factor, and exact angle computation are not given in the spec or patent.

6. **Multi-pass behavior is undocumented.** The phase transition mechanism (above) is not described in any published material.

This means **FES is not a standard** in any meaningful sense — it is a single proprietary implementation that cannot be independently replicated. By contrast, AES can be implemented from the FIPS 197 spec by anyone, in any language, and produce byte-identical results verified against published test vectors.

## Security-Relevant Observations

1. **No nonce/IV**: The keystream is entirely determined by the key. Same key = same stream, always.
2. **No authentication**: Pure encryption, no MAC or tag. Bit-flipping attacks are trivial.
3. **Deterministic stream**: The stream for key K is deterministic per (key, dimensions, message_length).
4. **Reverse application is irrelevant**: Applying the stream forward or backward doesn't change any security property — it's still `plaintext XOR keystream`.
5. **Floating-point and string-representation dependency**: Cross-platform reproducibility is fundamentally impossible.
6. **Not independently implementable**: Missing mapping table, unspecified parameters, and undocumented multi-pass behavior make it impossible to create an interoperable implementation.
