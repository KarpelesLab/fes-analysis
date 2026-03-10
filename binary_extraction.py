"""
Test binary extraction of stream bytes from Mandelbrot z values.

HFN Theory Appendix B says:
1. Interpret Re(V) and Im(V) as signed fixed-point integers
2. Concatenate their binary encodings
3. Apply mixing function (small cryptographic permutation)
4. Take first b bits as output

We test without the mixing function first, then try common permutations.
"""

from decimal import Decimal, getcontext

getcontext().prec = 80

PORTALS = [
    ("D",  "-2.08907476180957701022001083650", "-0.08680597208354758191207770730"),
    ("e",  "-2.08907476181522003792380968740", "-0.08680597208458885481071240080"),
    ("m",  "-2.08907476180923032802915825710", "-0.08680597208334813676592169720"),
    ("o",  "-2.08907476181107661452222121900", "-0.08680597208314070620383176580"),
    (" ",  "-2.08907476181442825818550023280", "-0.08680597208023072934617983240"),
    ("P",  "-2.08907476180436862921232677160", "-0.08680597208306643814826154770"),
    ("a",  "-2.08907476181307931138051932930", "-0.08680597208096131920214754340"),
    ("y",  "-2.08907476181089027613870934230", "-0.08680597208523521959207236210"),
    ("l",  "-2.08907476180897180563306393630", "-0.08680597208472406243986805040"),
    ("o2", "-2.08907476181171974211069395000", "-0.08680597208084869794064169780"),
    ("a2", "-2.08907476181481324569076360310", "-0.08680597208289478361839539360"),
    ("d",  "-2.08907476180781278213431070650", "-0.08680597208488735293400753930"),
]

STREAM = [215, 27, 210, 179, 226, 199, 7, 46, 14, 223, 201, 97]


def mandelbrot_z(cx, cy, n_iters):
    zx, zy = Decimal(0), Decimal(0)
    for _ in range(n_iters):
        zx, zy = zx * zx - zy * zy + cx, 2 * zx * zy + cy
    return zx, zy


def decimal_to_fixed_bits(val, int_bits=16, frac_bits=256):
    """Convert Decimal to fixed-point binary string (sign + int + frac)."""
    sign = 1 if val < 0 else 0
    v = abs(val)
    int_part = int(v)
    frac_part = v - int_part

    # Integer bits
    int_bin = format(int_part, f'0{int_bits}b')

    # Fractional bits
    frac_bin = []
    for _ in range(frac_bits):
        frac_part *= 2
        bit = int(frac_part)
        frac_bin.append(str(bit))
        frac_part -= bit

    return str(sign) + int_bin + ''.join(frac_bin)


def bits_to_bytes(bits_str, start=0, count=12):
    """Extract bytes from a bit string starting at position start."""
    result = []
    for i in range(count):
        byte_start = start + i * 8
        if byte_start + 8 > len(bits_str):
            break
        byte_val = int(bits_str[byte_start:byte_start + 8], 2)
        result.append(byte_val)
    return result


def main():
    # Compute z values at all portal positions
    for n_iter in [5, 6, 7, 8]:
        print(f"\n{'='*80}")
        print(f"ITERATION COUNT = {n_iter}")
        print(f"{'='*80}")

        all_zx_bits = []
        all_zy_bits = []

        for pidx, (ch, fx, fy) in enumerate(PORTALS):
            cx, cy = Decimal(fx), Decimal(fy)
            zx, zy = mandelbrot_z(cx, cy, n_iter)
            zx_bits = decimal_to_fixed_bits(zx, int_bits=16, frac_bits=256)
            zy_bits = decimal_to_fixed_bits(zy, int_bits=16, frac_bits=256)
            all_zx_bits.append(zx_bits)
            all_zy_bits.append(zy_bits)

        # Test 1: Extract byte from fixed-point representation of zx
        print(f"\n  TEST 1: Byte from zx fixed-point binary")
        for byte_offset in range(32):  # Try different starting positions
            matches = 0
            match_positions = []
            for pidx in range(12):
                extracted = bits_to_bytes(all_zx_bits[pidx], start=byte_offset * 8, count=1)
                if extracted and extracted[0] == STREAM[pidx]:
                    matches += 1
                    match_positions.append(pidx)
            if matches >= 3:
                print(f"    offset={byte_offset:2d}: {matches}/12 matches at {match_positions}")

        # Test 2: Extract byte from zy
        print(f"\n  TEST 2: Byte from zy fixed-point binary")
        for byte_offset in range(32):
            matches = 0
            match_positions = []
            for pidx in range(12):
                extracted = bits_to_bytes(all_zy_bits[pidx], start=byte_offset * 8, count=1)
                if extracted and extracted[0] == STREAM[pidx]:
                    matches += 1
                    match_positions.append(pidx)
            if matches >= 3:
                print(f"    offset={byte_offset:2d}: {matches}/12 matches at {match_positions}")

        # Test 3: XOR of zx_byte and zy_byte at same offset
        print(f"\n  TEST 3: zx_byte XOR zy_byte")
        for byte_offset in range(32):
            matches = 0
            match_positions = []
            for pidx in range(12):
                bx = bits_to_bytes(all_zx_bits[pidx], start=byte_offset * 8, count=1)
                by = bits_to_bytes(all_zy_bits[pidx], start=byte_offset * 8, count=1)
                if bx and by:
                    combined = bx[0] ^ by[0]
                    if combined == STREAM[pidx]:
                        matches += 1
                        match_positions.append(pidx)
            if matches >= 3:
                print(f"    offset={byte_offset:2d}: {matches}/12 matches at {match_positions}")

        # Test 4: zx_byte + zy_byte mod 256
        print(f"\n  TEST 4: (zx_byte + zy_byte) mod 256")
        for byte_offset in range(32):
            matches = 0
            match_positions = []
            for pidx in range(12):
                bx = bits_to_bytes(all_zx_bits[pidx], start=byte_offset * 8, count=1)
                by = bits_to_bytes(all_zy_bits[pidx], start=byte_offset * 8, count=1)
                if bx and by:
                    combined = (bx[0] + by[0]) % 256
                    if combined == STREAM[pidx]:
                        matches += 1
                        match_positions.append(pidx)
            if matches >= 3:
                print(f"    offset={byte_offset:2d}: {matches}/12 matches at {match_positions}")

        # Test 5: Concatenated bits (zx || zy), extract from different positions
        print(f"\n  TEST 5: Bytes from concatenated zx||zy")
        for byte_offset in range(60):
            matches = 0
            match_positions = []
            for pidx in range(12):
                concat = all_zx_bits[pidx] + all_zy_bits[pidx]
                extracted = bits_to_bytes(concat, start=byte_offset * 8, count=1)
                if extracted and extracted[0] == STREAM[pidx]:
                    matches += 1
                    match_positions.append(pidx)
            if matches >= 3:
                print(f"    offset={byte_offset:2d}: {matches}/12 matches at {match_positions}")

        # Test 6: Concatenated (zy || zx)
        print(f"\n  TEST 6: Bytes from concatenated zy||zx")
        for byte_offset in range(60):
            matches = 0
            match_positions = []
            for pidx in range(12):
                concat = all_zy_bits[pidx] + all_zx_bits[pidx]
                extracted = bits_to_bytes(concat, start=byte_offset * 8, count=1)
                if extracted and extracted[0] == STREAM[pidx]:
                    matches += 1
                    match_positions.append(pidx)
            if matches >= 3:
                print(f"    offset={byte_offset:2d}: {matches}/12 matches at {match_positions}")

        # Test 7: Try |z|² and |z| in binary
        print(f"\n  TEST 7: Bytes from |z| and |z|² fixed-point binary")
        for pidx_test in range(1):  # Just show first portal for now
            cx, cy = Decimal(PORTALS[pidx_test][1]), Decimal(PORTALS[pidx_test][2])
            zx, zy = mandelbrot_z(cx, cy, n_iter)
            mag_sq = zx * zx + zy * zy
            mag = mag_sq.sqrt()
            mag_bits = decimal_to_fixed_bits(mag, int_bits=16, frac_bits=256)
            mag_sq_bits = decimal_to_fixed_bits(mag_sq, int_bits=32, frac_bits=256)
            first_bytes_mag = bits_to_bytes(mag_bits, start=0, count=8)
            first_bytes_magsq = bits_to_bytes(mag_sq_bits, start=0, count=8)
            print(f"    |z| first 8 bytes: {first_bytes_mag}")
            print(f"    |z|² first 8 bytes: {first_bytes_magsq}")
            print(f"    stream[0] = {STREAM[0]}")

        # Test 8: Different bit-width interpretations
        # What if the fixed-point uses a different number of integer bits?
        print(f"\n  TEST 8: Varying integer bit width for zx")
        for int_bits in [2, 4, 8, 12, 16, 20, 24, 32]:
            for pidx in range(12):
                cx, cy = Decimal(PORTALS[pidx][1]), Decimal(PORTALS[pidx][2])
                zx, zy = mandelbrot_z(cx, cy, n_iter)
                zx_bits = decimal_to_fixed_bits(zx, int_bits=int_bits, frac_bits=256)
                # Try extracting first byte of the fractional part
                frac_start = 1 + int_bits  # skip sign + int bits
                extracted = bits_to_bytes(zx_bits, start=frac_start, count=1)
                if extracted and extracted[0] == STREAM[pidx]:
                    print(f"    int_bits={int_bits:2d}, portal {pidx}: "
                          f"frac byte 0 = {extracted[0]} = stream[{pidx}] ✓")

    # Test 9: DECIMAL DIGIT extraction with different bases
    # What if cv = int(FV_decimal_string_without_dot) for first N chars?
    print(f"\n{'='*80}")
    print("TEST 9: Decimal string manipulation")
    print(f"{'='*80}")

    for n_iter in [5, 6, 7, 8]:
        print(f"\n  iter={n_iter}:")
        for pidx in range(12):
            cx, cy = Decimal(PORTALS[pidx][1]), Decimal(PORTALS[pidx][2])
            zx, zy = mandelbrot_z(cx, cy, n_iter)
            mag_sq = zx * zx + zy * zy
            mag = mag_sq.sqrt()

            # Full decimal string of |z|
            mag_str = str(mag)
            # Remove the "." and leading digits to get pure digit sequence
            if '.' in mag_str:
                int_part, frac_part = mag_str.split('.')
            else:
                int_part, frac_part = mag_str, ''

            # Try: all digits concatenated (no dot)
            all_digits = int_part + frac_part
            for start in range(min(20, len(all_digits))):
                for length in range(1, min(10, len(all_digits) - start + 1)):
                    cv = int(all_digits[start:start + length])
                    if cv % 256 == STREAM[pidx]:
                        if pidx == 0 or length <= 3:  # Only show short matches
                            print(f"    [{pidx:2d}] |z|={mag_str[:15]}... "
                                  f"digits[{start}:{start+length}]={all_digits[start:start+length]}"
                                  f" → {cv}%256={cv%256}")
                            break
                else:
                    continue
                break

    # Test 10: What if the extraction uses the MANTISSA bytes directly?
    # In decimal fixed-point with 80-digit precision:
    # FV = 5874.72743512971...
    # Mantissa (without integer part) = 72743512971...
    # Byte 0 = digits 0..2 = 727, 727 mod 256 = 215 ✓
    # What about a different digit grouping?
    print(f"\n{'='*80}")
    print("TEST 10: Mantissa digit grouping (3 digits → 1 byte)")
    print(f"{'='*80}")

    for n_iter in [5, 6, 7, 8]:
        print(f"\n  iter={n_iter}:")
        for pidx in range(12):
            cx, cy = Decimal(PORTALS[pidx][1]), Decimal(PORTALS[pidx][2])
            zx, zy = mandelbrot_z(cx, cy, n_iter)
            mag = (zx * zx + zy * zy).sqrt()
            mag_str = str(mag)
            if '.' in mag_str:
                frac = mag_str.split('.')[1]
            else:
                frac = ''

            # Try groups of 3 digits from the fractional part
            bytes_from_groups = []
            for g in range(0, min(36, len(frac)), 3):
                group = frac[g:g + 3]
                if len(group) == 3:
                    bytes_from_groups.append(int(group) % 256)

            if pidx < 6 and bytes_from_groups:
                match_idx = -1
                for i, b in enumerate(bytes_from_groups):
                    if b == STREAM[pidx]:
                        match_idx = i
                        break
                if match_idx >= 0:
                    print(f"    [{pidx:2d}] frac={frac[:24]}... "
                          f"group[{match_idx}]={frac[match_idx*3:match_idx*3+3]} "
                          f"→ {int(frac[match_idx*3:match_idx*3+3])%256} ✓")
                else:
                    print(f"    [{pidx:2d}] frac={frac[:24]}... "
                          f"groups[:4]={bytes_from_groups[:4]} NO MATCH for {STREAM[pidx]}")

    # Test 11: What if the extraction is from |z|^2 (squared magnitude)?
    print(f"\n{'='*80}")
    print("TEST 11: |z|² mantissa digit grouping (3 digits → 1 byte)")
    print(f"{'='*80}")

    for n_iter in [5, 6, 7, 8]:
        print(f"\n  iter={n_iter}:")
        for pidx in range(12):
            cx, cy = Decimal(PORTALS[pidx][1]), Decimal(PORTALS[pidx][2])
            zx, zy = mandelbrot_z(cx, cy, n_iter)
            mag_sq = zx * zx + zy * zy
            mag_sq_str = str(mag_sq)
            if '.' in mag_sq_str:
                frac = mag_sq_str.split('.')[1]
            else:
                frac = ''

            bytes_from_groups = []
            for g in range(0, min(36, len(frac)), 3):
                group = frac[g:g + 3]
                if len(group) == 3:
                    bytes_from_groups.append(int(group) % 256)

            if pidx < 6 and bytes_from_groups:
                match_idx = -1
                for i, b in enumerate(bytes_from_groups):
                    if b == STREAM[pidx]:
                        match_idx = i
                        break
                if match_idx >= 0:
                    print(f"    [{pidx:2d}] frac={frac[:24]}... "
                          f"group[{match_idx}]={frac[match_idx*3:match_idx*3+3]} "
                          f"→ {int(frac[match_idx*3:match_idx*3+3])%256} ✓")
                else:
                    print(f"    [{pidx:2d}] frac={frac[:24]}... "
                          f"groups[:4]={bytes_from_groups[:4]} NO MATCH for {STREAM[pidx]}")

    # Test 12: Extraction from zx and zy separately (3-digit groups)
    print(f"\n{'='*80}")
    print("TEST 12: zx/zy fractional digit grouping")
    print(f"{'='*80}")

    for n_iter in [5, 6, 7, 8]:
        print(f"\n  iter={n_iter}:")
        for pidx in range(min(6, 12)):
            cx, cy = Decimal(PORTALS[pidx][1]), Decimal(PORTALS[pidx][2])
            zx, zy = mandelbrot_z(cx, cy, n_iter)

            for comp_name, comp_val in [("zx", zx), ("zy", zy)]:
                val_str = str(abs(comp_val))
                if '.' in val_str:
                    frac = val_str.split('.')[1]
                else:
                    frac = ''

                for group_size in [2, 3, 4]:
                    bytes_from_groups = []
                    for g in range(0, min(30, len(frac)), group_size):
                        group = frac[g:g + group_size]
                        if len(group) == group_size:
                            bytes_from_groups.append(int(group) % 256)

                    for i, b in enumerate(bytes_from_groups[:8]):
                        if b == STREAM[pidx]:
                            print(f"    [{pidx:2d}] {comp_name} frac groups({group_size})"
                                  f"[{i}]={frac[i*group_size:i*group_size+group_size]}"
                                  f" → {b} ✓")
                            break


if __name__ == "__main__":
    main()
