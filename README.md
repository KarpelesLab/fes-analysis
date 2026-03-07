# FES (Fractal Encryption Standard) Analysis

Independent security analysis of the "Fractal Encryption Standard" (FES) by Portalz PTY LTD, which claims to "replace quantum vulnerable AES encryption."

## Summary

FES is a stream cipher that uses Mandelbrot set iterations as a PRNG to generate a keystream, which is XORed with the plaintext. Despite elaborate "fractal" terminology, it reduces to:

```
ciphertext[i] = plaintext[i] XOR keystream[N-1-i]
```

We found that:
- **AES is NOT quantum vulnerable** — AES-256 retains 128-bit security under Grover's algorithm (NIST recommendation)
- **FES is trivially broken** by known-plaintext attacks (demonstrated against the live server)
- **FES has no nonce/IV** — same key always produces the same keystream
- **FES has no authentication** — ciphertext forgery is trivial
- **FES is ~1000x slower** than AES-256-CTR
- **FES cannot be independently implemented** — the spec is incomplete and relies on unpublished parameters

## Key Findings

| Feature | FES | AES-256-GCM |
|---------|-----|-------------|
| Throughput | ~1 MB/s | ~1 GB/s |
| Nonce/IV | None | Yes |
| Authentication | None | Yes (AEAD) |
| Known-plaintext resistance | None | Complete |
| Ciphertext forgery resistance | None | Complete |
| Peer review | None | 25+ years |
| Hardware acceleration | None | AES-NI |
| Quantum resistance | Unknown | 128-bit security |

## Attacks Demonstrated

All attacks were performed against the production server at `portalz.solutions/fes.dna`:

1. **Keystream recovery** — extract the full keystream from any known plaintext/ciphertext pair
2. **Decryption** — decrypt unknown messages using the recovered keystream
3. **Forgery** — craft ciphertexts that the server decrypts to arbitrary chosen messages
4. **Scramble mode bypass** — all attacks work identically with scramble enabled

## Repository Contents

| File | Description |
|------|-------------|
| [`FINDINGS.md`](FINDINGS.md) | Complete investigation report with claim-by-claim analysis |
| [`ALGORITHM.md`](ALGORITHM.md) | Detailed reverse-engineered algorithm specification |
| [`fes.py`](fes.py) | Python implementation of FES based on the published spec |
| [`benchmark.py`](benchmark.py) | Performance and security comparison: FES vs AES-256 |
| [`attack_server.py`](attack_server.py) | Known-plaintext attack against the live server |
| [`collect_data.py`](collect_data.py) | Data collection from the server for offline analysis |
| [`analyze_data.py`](analyze_data.py) | Offline analysis of SHA-512 to keystream relationship |
| [`data/`](data/) | Collected experimental data (592 key/stream entries) |
| [`docs/`](docs/) | Source documents (spec PDF, FT-Explained presentation) |

## How to Run

```bash
# Attack demonstration (requires network access to portalz.solutions)
python3 attack_server.py

# Benchmark FES vs AES (requires pycryptodome)
pip install pycryptodome
python3 benchmark.py

# Offline analysis of collected data
python3 analyze_data.py
```

## Technical Details

See [`ALGORITHM.md`](ALGORITHM.md) for the full reverse-engineered specification, including:
- Key expansion (iterated SHA-512, exact method unknown)
- Key-to-portal mapping via Mandelbrot boundary regions
- Fractal stream generation with dynamic prime modulus navigation
- Length-dependent phase transitions
- The angle doubling pattern (consequence of z=z²+c)

See [`FINDINGS.md`](FINDINGS.md) for the complete security analysis, including:
- Claim-by-claim evaluation of all marketing statements
- Attack demonstrations with full output
- Performance benchmarks
- Stream quality analysis
- SHA-512 to keystream relationship analysis (592 data points)

## Conclusion

FES is not a credible encryption standard. Organizations seeking quantum-resistant encryption should use **AES-256-GCM** (already quantum-resistant) for symmetric encryption, and NIST's post-quantum standards (ML-KEM, ML-DSA) for asymmetric operations.
