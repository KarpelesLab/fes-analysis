"""
FES (Fractal Encryption Standard) - Python Implementation
Based on the Fractal Transformation Process Specification V3 by Wolfgang Flatow / Portalz.

This is a faithful implementation based on:
- The PDF spec (FractalTransformationProcessSpecificationV3.pdf)
- Black-box testing of the online demo at portalz.solutions
- Reverse engineering of the stream application order

Key findings from reverse engineering:
- The keystream is applied in REVERSE order: cipher[i] = plaintext[i] XOR stream[N-1-i]
- The "scramble" option modifies the stream generation, not just byte ordering
- The "depth" form parameter appears to have no effect on the online demo
- The algorithm is fundamentally a Mandelbrot-iteration-based stream cipher
"""

import hashlib
import math
import struct
import time


class FES:
    """
    Fractal Encryption Standard implementation.

    The algorithm:
    1. Build a mapping table of 2^16 "suitable" Mandelbrot boundary regions
    2. Hash the key, use hash bits to select a region and offset into it
    3. Navigate through Mandelbrot space using key bytes to reach a "fractal portal"
    4. Generate a keystream by iterating Mandelbrot at sequential positions
    5. Encrypt: ciphertext[i] = plaintext[i] XOR stream[N-1-i]  (reverse application)
    6. Decrypt: plaintext[i] = ciphertext[i] XOR stream[N-1-i]  (same operation)
    """

    def __init__(self, max_iter=256, mapping_size=65536, ms=0.01, mac=None, dimensions=8):
        self.max_iter = max_iter
        self.mapping_size = mapping_size
        self.ms = ms
        self.mac = mac if mac is not None else max_iter
        self.dimensions = dimensions
        self.mapping = None

    def _mandelbrot_iteration(self, cx, cy, max_iter=None):
        """Compute Mandelbrot iteration at point (cx, cy).
        Returns (iteration_count, final_zx, final_zy)."""
        if max_iter is None:
            max_iter = self.max_iter
        zx, zy = 0.0, 0.0
        for i in range(max_iter):
            zx2 = zx * zx
            zy2 = zy * zy
            if zx2 + zy2 > 4.0:
                return (i, zx, zy)
            zy = 2.0 * zx * zy + cy
            zx = zx2 - zy2 + cx
        return (max_iter, zx, zy)

    def _mandelbrot_cv(self, cx, cy):
        """Compute the Mandelbrot 'complex value' integer at a point.
        Per spec: iterate, get final z, extract integer from fractional digits."""
        _, zx, zy = self._mandelbrot_iteration(cx, cy)
        magnitude = math.sqrt(zx * zx + zy * zy)
        frac = abs(magnitude) - int(abs(magnitude))
        # Convert fractional digits to large integer (~15 significant digits)
        cv = int(frac * 1_000_000_000_000_000)
        if cv == 0:
            cv = 1
        return cv

    def build_mapping(self):
        """Build mapping table by scanning Mandelbrot boundary regions.
        Per spec: scan from (0,0) outward with step 0.01."""
        mapping = []
        step = self.ms
        max_range = int(2.5 / step)

        # Generate candidates sorted by distance from origin
        candidates = []
        for ix in range(-max_range, max_range + 1):
            for iy in range(-max_range, max_range + 1):
                x = ix * step
                y = iy * step
                candidates.append((x * x + y * y, x, y))
        candidates.sort()

        for _, x, y in candidates:
            if len(mapping) >= self.mapping_size:
                break
            icount, _, _ = self._mandelbrot_iteration(x, y)
            if icount >= self.max_iter:  # Inside set (infinite)
                continue
            if icount > self.mac:  # Too complex
                continue
            if icount < 2:  # Too simple (outside set)
                continue
            mapping.append((x, y))

        self.mapping = mapping
        return len(mapping)

    def _expand_key(self, key_bytes):
        """Expand key using iterated SHA-512 to fill required key space.
        Per spec: 'expanded with iterations of SHA512 hashes until required key space is achieved.'"""
        bits_needed = self.dimensions * 112  # 112 bits per dimension
        bytes_needed = (bits_needed + 7) // 8
        expanded = hashlib.sha512(key_bytes).digest()
        while len(expanded) < bytes_needed:
            expanded += hashlib.sha512(expanded).digest()
        return expanded[:bytes_needed]

    def _key_to_portal(self, key):
        """Map key to fractal portal coordinates."""
        if isinstance(key, str):
            key_bytes = key.encode('utf-8')
        else:
            key_bytes = key

        expanded = self._expand_key(key_bytes)

        # Per spec: split hash into n (16 bits for mapping index), xm, ym
        # For multi-dimensional: use 112 bits per dimension (16 + 48 + 48)
        n = struct.unpack('>H', expanded[0:2])[0] % len(self.mapping)

        remaining = expanded[2:]
        half = len(remaining) // 2
        xm_bytes = remaining[:half]
        ym_bytes = remaining[half:]

        xm_val = int.from_bytes(xm_bytes, 'big')
        ym_val = int.from_bytes(ym_bytes, 'big')
        max_val = (1 << (half * 8)) - 1 if half > 0 else 1
        xm_scaled = (xm_val / max_val) * self.ms if max_val > 0 else 0
        ym_scaled = (ym_val / max_val) * self.ms if max_val > 0 else 0

        dmr_x, dmr_y = self.mapping[n]
        fpx = dmr_x + xm_scaled
        fpy = dmr_y + ym_scaled

        # Navigate using original key bytes
        for bkb in key_bytes:
            if bkb == 0:
                bkb = 1
            cv = self._mandelbrot_cv(fpx, fpy)
            angle_rad = math.radians(cv % 360)
            hyp = self.ms / bkb
            fpx += hyp * math.cos(angle_rad)
            fpy += hyp * math.sin(angle_rad)

        return fpx, fpy

    def _generate_stream(self, fpx, fpy, length, hvm=1000):
        """Generate fractal keystream of given length starting from portal."""
        stream = bytearray(length)
        x, y = fpx, fpy

        for i in range(length):
            cv = self._mandelbrot_cv(x, y)
            stream[i] = cv % 256
            av = cv % 360
            hv = cv % hvm
            if hv == 0:
                hv = 1

            angle_rad = math.radians(av)
            hyp = (hv / hvm) * self.ms
            x += hyp * math.cos(angle_rad)
            y += hyp * math.sin(angle_rad)

        return bytes(stream)

    def encrypt(self, key, plaintext):
        """Encrypt: cipher[i] = plaintext[i] XOR stream[N-1-i]"""
        if self.mapping is None:
            self.build_mapping()
        if isinstance(plaintext, str):
            plaintext = plaintext.encode('utf-8')

        N = len(plaintext)
        fpx, fpy = self._key_to_portal(key)
        stream = self._generate_stream(fpx, fpy, N)

        ciphertext = bytearray(N)
        for i in range(N):
            ciphertext[i] = plaintext[i] ^ stream[N - 1 - i]

        return bytes(ciphertext)

    def decrypt(self, key, ciphertext):
        """Decrypt: plaintext[i] = ciphertext[i] XOR stream[N-1-i] (same as encrypt)"""
        if self.mapping is None:
            self.build_mapping()
        if isinstance(ciphertext, str):
            ciphertext = ciphertext.encode('utf-8')

        N = len(ciphertext)
        fpx, fpy = self._key_to_portal(key)
        stream = self._generate_stream(fpx, fpy, N)

        plaintext = bytearray(N)
        for i in range(N):
            plaintext[i] = ciphertext[i] ^ stream[N - 1 - i]

        return bytes(plaintext)


def test_roundtrip():
    """Verify encrypt/decrypt round-trip works."""
    print("FES Round-Trip Test")
    print("=" * 60)

    fes = FES(max_iter=128, mapping_size=4096, dimensions=8)
    print("Building Mandelbrot mapping table...")
    t0 = time.time()
    count = fes.build_mapping()
    t_map = time.time() - t0
    print(f"  Found {count} suitable regions in {t_map:.2f}s")

    key = "SecretKey99"
    plaintext = "hello world"
    print(f"\nKey:       {key}")
    print(f"Plaintext: {plaintext}")

    t0 = time.time()
    ciphertext = fes.encrypt(key, plaintext)
    t_enc = time.time() - t0
    print(f"Ciphertext (hex): {ciphertext.hex()}")
    print(f"Encrypt time: {t_enc*1000:.1f}ms")

    t0 = time.time()
    recovered = fes.decrypt(key, ciphertext)
    t_dec = time.time() - t0
    print(f"Recovered: {recovered.decode('utf-8', errors='replace')}")
    print(f"Decrypt time: {t_dec*1000:.1f}ms")

    assert recovered == plaintext.encode('utf-8'), "Round-trip FAILED!"
    print("\nRound-trip PASSED!")

    # Note: our output won't match the server's output because:
    # 1. Different mapping table (server has pre-computed fixed table)
    # 2. Possibly different floating-point behavior
    # 3. Unknown exact hvm and other constants
    # But the ALGORITHM is faithful to the spec and round-trips correctly.
    return fes


if __name__ == "__main__":
    test_roundtrip()
