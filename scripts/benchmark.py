"""
FES vs AES Performance and Security Comparison

This benchmark compares:
- FES (Fractal Encryption Standard) - our implementation from the spec
- AES-256-CTR (industry standard stream cipher mode for fair comparison)
- AES-256-GCM (authenticated encryption, the recommended mode)

We measure:
1. Encryption throughput (bytes/second)
2. Decryption throughput (bytes/second)
3. Key setup time
4. Stream generation quality (statistical randomness)
"""

import hashlib
import math
import os
import time
import statistics
from collections import Counter

from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

from fes import FES


def benchmark_fes(fes_instance, data_sizes, key="BenchmarkKey123", rounds=3):
    """Benchmark FES encryption/decryption."""
    results = {}
    for size in data_sizes:
        plaintext = os.urandom(size)
        enc_times = []
        dec_times = []

        for _ in range(rounds):
            t0 = time.perf_counter()
            ciphertext = fes_instance.encrypt(key, plaintext)
            enc_times.append(time.perf_counter() - t0)

            t0 = time.perf_counter()
            recovered = fes_instance.decrypt(key, ciphertext)
            dec_times.append(time.perf_counter() - t0)

            assert recovered == plaintext, "FES round-trip failed!"

        results[size] = {
            'enc_time': statistics.median(enc_times),
            'dec_time': statistics.median(dec_times),
            'enc_throughput': size / statistics.median(enc_times),
            'dec_throughput': size / statistics.median(dec_times),
        }
    return results


def benchmark_aes_ctr(data_sizes, rounds=3):
    """Benchmark AES-256-CTR encryption/decryption."""
    key = get_random_bytes(32)  # AES-256
    results = {}

    for size in data_sizes:
        plaintext = os.urandom(size)
        enc_times = []
        dec_times = []

        for _ in range(rounds):
            nonce = get_random_bytes(8)
            cipher = AES.new(key, AES.MODE_CTR, nonce=nonce)
            t0 = time.perf_counter()
            ciphertext = cipher.encrypt(plaintext)
            enc_times.append(time.perf_counter() - t0)

            cipher = AES.new(key, AES.MODE_CTR, nonce=nonce)
            t0 = time.perf_counter()
            recovered = cipher.decrypt(ciphertext)
            dec_times.append(time.perf_counter() - t0)

            assert recovered == plaintext

        results[size] = {
            'enc_time': statistics.median(enc_times),
            'dec_time': statistics.median(dec_times),
            'enc_throughput': size / statistics.median(enc_times),
            'dec_throughput': size / statistics.median(dec_times),
        }
    return results


def benchmark_aes_gcm(data_sizes, rounds=3):
    """Benchmark AES-256-GCM (authenticated encryption)."""
    key = get_random_bytes(32)
    results = {}

    for size in data_sizes:
        plaintext = os.urandom(size)
        enc_times = []
        dec_times = []

        for _ in range(rounds):
            cipher = AES.new(key, AES.MODE_GCM)
            nonce = cipher.nonce
            t0 = time.perf_counter()
            ciphertext, tag = cipher.encrypt_and_digest(plaintext)
            enc_times.append(time.perf_counter() - t0)

            cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
            t0 = time.perf_counter()
            recovered = cipher.decrypt_and_verify(ciphertext, tag)
            dec_times.append(time.perf_counter() - t0)

            assert recovered == plaintext

        results[size] = {
            'enc_time': statistics.median(enc_times),
            'dec_time': statistics.median(dec_times),
            'enc_throughput': size / statistics.median(enc_times),
            'dec_throughput': size / statistics.median(dec_times),
        }
    return results


def analyze_stream_randomness(stream_bytes):
    """Basic statistical tests on the keystream."""
    n = len(stream_bytes)
    if n == 0:
        return {}

    # Byte frequency distribution
    freq = Counter(stream_bytes)
    expected = n / 256
    chi_squared = sum((count - expected) ** 2 / expected for count in freq.values())
    # Add zero counts for missing bytes
    missing = 256 - len(freq)
    chi_squared += missing * expected  # (0 - expected)^2 / expected = expected

    # Bit balance (should be ~50% ones)
    total_bits = n * 8
    ones = sum(bin(b).count('1') for b in stream_bytes)
    bit_ratio = ones / total_bits

    # Sequential correlation (adjacent byte difference)
    if n > 1:
        diffs = [abs(stream_bytes[i] - stream_bytes[i-1]) for i in range(1, n)]
        avg_diff = statistics.mean(diffs)
    else:
        avg_diff = 0

    # Runs test (count consecutive same bits)
    bits = ''.join(format(b, '08b') for b in stream_bytes)
    runs = 1
    for i in range(1, len(bits)):
        if bits[i] != bits[i-1]:
            runs += 1
    expected_runs = (2 * ones * (total_bits - ones)) / total_bits + 1

    return {
        'byte_count': n,
        'unique_bytes': len(freq),
        'chi_squared': chi_squared,
        'chi_squared_dof': 255,
        'bit_ratio': bit_ratio,
        'avg_byte_diff': avg_diff,
        'runs': runs,
        'expected_runs': expected_runs,
    }


def test_key_sensitivity(fes_instance):
    """Test avalanche effect: small key changes should produce very different output."""
    plaintext = b"The quick brown fox jumps over the lazy dog"
    keys = ["SecretKey99", "SecretKey98", "SecretKey89", "secretKey99", "SecretKey9a"]

    print("\n  Key Sensitivity (avalanche effect):")
    ciphertexts = {}
    for key in keys:
        ct = fes_instance.encrypt(key, plaintext)
        ciphertexts[key] = ct

    base_ct = ciphertexts[keys[0]]
    for key in keys[1:]:
        ct = ciphertexts[key]
        # Count differing bits
        diff_bits = sum(bin(a ^ b).count('1') for a, b in zip(base_ct, ct))
        total_bits = len(base_ct) * 8
        print(f"    '{keys[0]}' vs '{key}': {diff_bits}/{total_bits} bits differ "
              f"({100*diff_bits/total_bits:.1f}%)")


def test_known_plaintext_vulnerability(fes_instance):
    """Demonstrate the known-plaintext stream recovery vulnerability."""
    key = "TestKey123"

    # Attacker knows plaintext1 and its ciphertext
    plaintext1 = b"Known plaintext msg!12345678901"  # 32 bytes
    ciphertext1 = fes_instance.encrypt(key, plaintext1)

    # Recover the stream from known plaintext/ciphertext
    N = len(plaintext1)
    recovered_stream_reversed = bytearray(N)
    for i in range(N):
        recovered_stream_reversed[i] = plaintext1[i] ^ ciphertext1[i]
    # This gives us stream[N-1-i] at position i, so reverse it
    recovered_stream = bytes(reversed(recovered_stream_reversed))

    # Now encrypt a DIFFERENT plaintext of same length with same key
    plaintext2 = b"Another secret msg 12345678901!"  # 32 bytes
    assert len(plaintext2) == N
    ciphertext2 = fes_instance.encrypt(key, plaintext2)

    # Attacker can decrypt plaintext2 using recovered stream
    attacked_plaintext = bytearray(N)
    for i in range(N):
        attacked_plaintext[i] = ciphertext2[i] ^ recovered_stream_reversed[i]

    return plaintext2, bytes(attacked_plaintext)


def format_throughput(bps):
    """Format bytes/second as human-readable string."""
    if bps >= 1_000_000_000:
        return f"{bps/1_000_000_000:.2f} GB/s"
    elif bps >= 1_000_000:
        return f"{bps/1_000_000:.2f} MB/s"
    elif bps >= 1_000:
        return f"{bps/1_000:.2f} KB/s"
    return f"{bps:.2f} B/s"


def main():
    print("=" * 70)
    print("FES vs AES: Performance & Security Comparison")
    print("=" * 70)

    # Initialize FES (smaller mapping for reasonable benchmark time)
    print("\n[1] Initializing FES...")
    t0 = time.perf_counter()
    fes = FES(max_iter=128, mapping_size=4096, dimensions=8)
    count = fes.build_mapping()
    fes_init_time = time.perf_counter() - t0
    print(f"    Mapping table: {count} regions in {fes_init_time:.2f}s")

    # Benchmark sizes
    # FES is too slow for large sizes, so we use small ones
    fes_sizes = [16, 64, 256, 1024]
    aes_sizes = [16, 64, 256, 1024, 4096, 65536, 1048576]

    # Run benchmarks
    print("\n[2] Benchmarking FES...")
    fes_results = benchmark_fes(fes, fes_sizes)

    print("[3] Benchmarking AES-256-CTR...")
    aes_ctr_results = benchmark_aes_ctr(aes_sizes)

    print("[4] Benchmarking AES-256-GCM...")
    aes_gcm_results = benchmark_aes_gcm(aes_sizes)

    # Results table
    print("\n" + "=" * 70)
    print("PERFORMANCE RESULTS")
    print("=" * 70)
    print(f"\n{'Size':>10} | {'FES Encrypt':>14} | {'AES-CTR Enc':>14} | {'AES-GCM Enc':>14} | {'FES/AES Ratio':>14}")
    print("-" * 75)

    for size in fes_sizes:
        fes_tp = fes_results[size]['enc_throughput']
        aes_tp = aes_ctr_results[size]['enc_throughput']
        gcm_tp = aes_gcm_results[size]['enc_throughput']
        ratio = aes_tp / fes_tp if fes_tp > 0 else float('inf')
        print(f"{size:>10} | {format_throughput(fes_tp):>14} | {format_throughput(aes_tp):>14} | {format_throughput(gcm_tp):>14} | {ratio:>12.0f}x")

    print(f"\n{'Size':>10} | {'AES-CTR Enc':>14} | {'AES-GCM Enc':>14}")
    print("-" * 45)
    for size in aes_sizes:
        if size not in fes_results:
            aes_tp = aes_ctr_results[size]['enc_throughput']
            gcm_tp = aes_gcm_results[size]['enc_throughput']
            print(f"{size:>10} | {format_throughput(aes_tp):>14} | {format_throughput(gcm_tp):>14}")

    # FES claim check: "0.05 seconds per megabyte"
    # Extrapolate from our benchmark
    if 1024 in fes_results:
        fes_1mb_est = fes_results[1024]['enc_time'] * 1024  # 1MB = 1024 * 1KB
        print(f"\n  FES estimated time for 1 MB: {fes_1mb_est:.2f}s")
        print(f"  FES claimed time for 1 MB:   0.05s")
        print(f"  Claim vs reality ratio:      {fes_1mb_est/0.05:.0f}x slower than claimed")

    # Stream quality analysis
    print("\n" + "=" * 70)
    print("STREAM QUALITY ANALYSIS")
    print("=" * 70)

    key = "TestStreamKey"
    fes_stream_data = fes.encrypt(key, bytes(4096))  # Encrypt zeros to get raw stream
    aes_key = hashlib.sha256(key.encode()).digest()
    aes_cipher = AES.new(aes_key, AES.MODE_CTR, nonce=b'\x00' * 8)
    aes_stream_data = aes_cipher.encrypt(bytes(4096))

    fes_stats = analyze_stream_randomness(fes_stream_data)
    aes_stats = analyze_stream_randomness(aes_stream_data)

    print(f"\n{'Metric':>25} | {'FES Stream':>15} | {'AES-CTR Stream':>15} | {'Ideal':>10}")
    print("-" * 72)
    print(f"{'Unique byte values':>25} | {fes_stats['unique_bytes']:>15} | {aes_stats['unique_bytes']:>15} | {'256':>10}")
    print(f"{'Chi-squared (df=255)':>25} | {fes_stats['chi_squared']:>15.1f} | {aes_stats['chi_squared']:>15.1f} | {'~255':>10}")
    print(f"{'Bit ratio (ones)':>25} | {fes_stats['bit_ratio']:>15.4f} | {aes_stats['bit_ratio']:>15.4f} | {'0.5000':>10}")
    print(f"{'Avg byte difference':>25} | {fes_stats['avg_byte_diff']:>15.1f} | {aes_stats['avg_byte_diff']:>15.1f} | {'~85.3':>10}")
    expected_runs_str = f"~{fes_stats['expected_runs']:.0f}"
    print(f"{'Runs count':>25} | {fes_stats['runs']:>15} | {aes_stats['runs']:>15} | {expected_runs_str:>10}")

    # Key sensitivity
    print("\n" + "=" * 70)
    print("KEY SENSITIVITY (AVALANCHE EFFECT)")
    print("=" * 70)
    test_key_sensitivity(fes)

    # Known-plaintext attack
    print("\n" + "=" * 70)
    print("KNOWN-PLAINTEXT ATTACK DEMONSTRATION")
    print("=" * 70)

    original, attacked = test_known_plaintext_vulnerability(fes)
    match = original == attacked
    print(f"\n  Original plaintext:  {original}")
    print(f"  Attacked recovery:   {attacked}")
    print(f"  Attack successful:   {match}")
    if match:
        print("  >>> FES is VULNERABLE to known-plaintext attacks! <<<")
        print("  If an attacker knows ANY plaintext and its ciphertext,")
        print("  they can decrypt ALL messages of the same length with the same key.")

    # Security analysis summary
    print("\n" + "=" * 70)
    print("SECURITY ANALYSIS SUMMARY")
    print("=" * 70)
    print("""
  CLAIM 1: "FES replaces quantum-vulnerable AES encryption"
  VERDICT: FALSE
    - AES is NOT quantum-vulnerable. Grover's algorithm reduces AES-256
      security from 256 bits to 128 bits, which is still completely secure.
    - NIST explicitly states AES-256 is quantum-resistant.
    - No quantum computer can break AES-256 in any foreseeable future.

  CLAIM 2: "Infinite key-space starting at 832 bits"
  VERDICT: MISLEADING
    - Key space size alone does not determine security. AES-256's 256-bit
      key space (2^256 possibilities) already exceeds the number of atoms
      in the observable universe (~2^266).
    - FES expands keys via SHA-512 hashing, which cannot add entropy beyond
      what the original key contains. A 10-character password hashed to
      832 bits still has ~10 characters of entropy.

  CLAIM 3: "Impenetrable - a world-first in cryptography"
  VERDICT: FALSE
    - FES is a simple stream cipher: keystream XOR plaintext.
    - It is trivially vulnerable to known-plaintext attacks (demonstrated
      above): if you know one plaintext/ciphertext pair, you recover the
      keystream and can decrypt any same-length message with the same key.
    - It has NO authentication (no MAC/tag), making it vulnerable to
      ciphertext manipulation (bit-flipping attacks).
    - The spec states "addition is a one-way function" which is incorrect.

  CLAIM 4: "The payload no longer exists in the ciphertext in any form"
  VERDICT: FALSE
    - The payload is simply XORed with a keystream. The relationship is
      direct: ciphertext = plaintext XOR keystream. Given the keystream
      (recoverable from any known plaintext), the payload is trivially
      extracted.

  CLAIM 5: "Defeats the parallelism of GPU and Quantum Computers"
  VERDICT: MISLEADING
    - Sequential stream generation is not a security advantage. It's a
      PERFORMANCE disadvantage. AES in CTR mode is parallelizable, which
      is a feature, not a vulnerability.
    - The sequential nature of FES stream generation makes it inherently
      slow and unsuitable for high-throughput applications.

  CLAIM 6: "Industrial strength performance - 0.05s per megabyte"
  VERDICT: DUBIOUS
    - Our Python implementation (following the spec) is orders of magnitude
      slower than AES. Even an optimized C implementation would be far
      slower due to the per-byte Mandelbrot iterations.
    - AES benefits from hardware acceleration (AES-NI) on modern CPUs.

  FUNDAMENTAL ISSUES:
    1. No peer review or published cryptanalysis
    2. Spec was "driven by collaboration between ChatGBT AI and Wolfgang Flatow"
    3. Relies on floating-point determinism (portability nightmare)
    4. No authentication mechanism (vulnerable to tampering)
    5. Stream cipher with no nonce/IV (same key+message = same ciphertext)
    6. The "fractal" aspect is just a PRNG - any CSPRNG would be equivalent
    7. The reverse-order stream application is security-irrelevant
""")


if __name__ == "__main__":
    main()
