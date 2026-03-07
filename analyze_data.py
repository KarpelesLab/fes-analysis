"""
Analyze collected FES stream data to understand the SHA-512 → stream relationship.

Questions to answer:
1. Do keys with the same mapping index (first 16 bits) produce related streams?
2. How do the offset bits (remaining 96 bits) affect the stream?
3. Is there a detectable relationship between expanded key bytes and stream bytes?
4. Can we determine the mapping table from the data?
"""

import json
import hashlib
from collections import defaultdict


def load_data():
    with open("data/stream_data.json") as f:
        return json.load(f)


def analyze_shared_indices(data):
    """Compare streams from keys with the same mapping index."""
    print("=" * 70)
    print("ANALYSIS 1: Keys sharing the same mapping index")
    print("=" * 70)

    # Group entries by mapping index
    by_index = defaultdict(list)
    for entry in data["keys"]:
        by_index[entry["mapping_index"]].append(entry)

    # Find groups with multiple keys
    shared = {idx: entries for idx, entries in by_index.items() if len(entries) >= 2}
    print(f"Found {len(shared)} mapping indices with 2+ keys")

    for idx, entries in sorted(shared.items(), key=lambda x: -len(x[1]))[:8]:
        print(f"\n  Mapping index {idx} ({len(entries)} keys):")
        for e in entries[:5]:
            s = e["stream"][:10]
            exp = e["expanded_key"][:6]
            print(f"    key='{e['key']:20s}' stream[0:10]={s}  exp[0:6]={exp}")

        # Check if streams are identical or related
        streams = [tuple(e["stream"]) for e in entries]
        if len(set(streams)) == 1:
            print(f"    >>> ALL STREAMS IDENTICAL")
        else:
            # Check common prefix length
            min_prefix = 20
            for i in range(1, len(streams)):
                common = 0
                for j in range(min(len(streams[0]), len(streams[i]))):
                    if streams[0][j] == streams[i][j]:
                        common += 1
                    else:
                        break
                min_prefix = min(min_prefix, common)
            print(f"    >>> Streams differ. Common prefix length: {min_prefix}")

            # Check byte-by-byte similarity
            diffs = []
            for pos in range(20):
                vals = set(e["stream"][pos] for e in entries)
                diffs.append(len(vals))
            print(f"    >>> Unique values per position: {diffs}")


def analyze_expanded_key_correlation(data):
    """Look for correlations between expanded key bytes and stream bytes."""
    print("\n" + "=" * 70)
    print("ANALYSIS 2: Expanded key bytes vs stream bytes correlation")
    print("=" * 70)

    entries = data["keys"]

    # Check if specific expanded key bytes predict specific stream bytes
    # The expanded key is 112 bytes for dim=8
    # First 2 bytes = mapping index, rest = offsets

    # For each stream position, find which expanded key bytes correlate most
    for stream_pos in range(5):
        print(f"\n  Stream position {stream_pos}:")
        best_corr = 0
        best_exp_pos = -1

        for exp_pos in range(min(20, len(entries[0]["expanded_key"]))):
            # Simple: check if same expanded key byte → same stream byte
            groups = defaultdict(set)
            for e in entries:
                exp_val = e["expanded_key"][exp_pos]
                stream_val = e["stream"][stream_pos]
                groups[exp_val].add(stream_val)

            # If perfect correlation, each exp_val maps to exactly 1 stream_val
            avg_unique = sum(len(v) for v in groups.values()) / len(groups)
            if avg_unique < best_corr or best_corr == 0:
                best_corr = avg_unique
                best_exp_pos = exp_pos

        print(f"    Best correlating exp_key position: {best_exp_pos} "
              f"(avg {best_corr:.1f} unique stream values per exp_key value)")


def analyze_mapping_index_effect(data):
    """Check if the mapping index (first 16 bits) determines stream[0]."""
    print("\n" + "=" * 70)
    print("ANALYSIS 3: Does mapping index determine stream values?")
    print("=" * 70)

    entries = data["keys"]

    # Group by mapping index, check if stream[0] is determined
    by_index = defaultdict(list)
    for e in entries:
        by_index[e["mapping_index"]].append(e["stream"][0])

    consistent = 0
    inconsistent = 0
    for idx, stream0_vals in by_index.items():
        if len(stream0_vals) > 1:
            if len(set(stream0_vals)) == 1:
                consistent += 1
            else:
                inconsistent += 1

    print(f"  Indices with 2+ keys where stream[0] is same: {consistent}")
    print(f"  Indices with 2+ keys where stream[0] differs: {inconsistent}")

    if inconsistent > 0 and consistent == 0:
        print("  >>> Mapping index alone does NOT determine stream[0]")
        print("  >>> The offset bits also affect stream generation")
    elif consistent > 0 and inconsistent == 0:
        print("  >>> Mapping index FULLY determines stream[0]")
        print("  >>> Offset bits only affect later stream positions")
    else:
        print(f"  >>> Mixed: {consistent} consistent, {inconsistent} inconsistent")


def analyze_stream_by_index_value(data):
    """Build a map: mapping_index → stream[0] to understand the mapping table."""
    print("\n" + "=" * 70)
    print("ANALYSIS 4: Mapping index → stream[0] relationship")
    print("=" * 70)

    entries = data["keys"]

    # Map: mapping_index → set of stream[0] values
    idx_to_s0 = defaultdict(set)
    for e in entries:
        idx_to_s0[e["mapping_index"]].add(e["stream"][0])

    # How many unique stream[0] values per index?
    single = sum(1 for v in idx_to_s0.values() if len(v) == 1)
    multi = sum(1 for v in idx_to_s0.values() if len(v) > 1)
    print(f"  Indices with single stream[0]: {single} (only 1 key)")
    print(f"  Indices with multiple stream[0]: {multi}")

    # Distribution of stream[0] values
    all_s0 = [e["stream"][0] for e in entries]
    from collections import Counter
    s0_counts = Counter(all_s0)
    print(f"  Unique stream[0] values seen: {len(s0_counts)}")
    print(f"  Most common stream[0]: {s0_counts.most_common(5)}")


def analyze_key_byte_navigation(data):
    """Check if the original key bytes affect the stream (KTM function)."""
    print("\n" + "=" * 70)
    print("ANALYSIS 5: Do original key bytes affect the stream?")
    print("=" * 70)

    entries = data["keys"]

    # Find pairs of keys with same expanded key prefix but different raw key bytes
    # Actually simpler: keys with same SHA-512 would give same everything
    # But keys with same mapping index + offsets but different raw key lengths might differ
    # due to the "navigate using key bytes" step

    # Compare keys of different lengths that happen to share a mapping index
    by_index = defaultdict(list)
    for e in entries:
        by_index[e["mapping_index"]].append(e)

    for idx, group in sorted(by_index.items(), key=lambda x: -len(x[1])):
        if len(group) < 2:
            continue
        # Check if keys of different lengths produce different streams
        lengths = set(len(e["key"]) for e in group)
        if len(lengths) > 1:
            print(f"\n  Index {idx}: keys of different lengths")
            for e in group:
                print(f"    key='{e['key']}' (len={len(e['key'])}) "
                      f"stream[0:5]={e['stream'][:5]} "
                      f"exp[2:6]={e['expanded_key'][2:6]}")
            break


def analyze_offset_sensitivity(data):
    """For keys with same mapping index, how much do streams differ?"""
    print("\n" + "=" * 70)
    print("ANALYSIS 6: Stream sensitivity to offset bits (same mapping index)")
    print("=" * 70)

    entries = data["keys"]
    by_index = defaultdict(list)
    for e in entries:
        by_index[e["mapping_index"]].append(e)

    for idx, group in sorted(by_index.items(), key=lambda x: -len(x[1]))[:5]:
        if len(group) < 3:
            continue
        print(f"\n  Mapping index {idx} ({len(group)} keys):")
        for e in group:
            exp = e["expanded_key"]
            offset_x = exp[2:8]  # bytes 2-7 (48 bits for x offset)
            offset_y = exp[8:14]  # bytes 8-13 (48 bits for y offset)
            print(f"    key='{e['key']:20s}' offset_x={offset_x} offset_y={offset_y} "
                  f"stream[0:8]={e['stream'][:8]}")

        # Count matching stream bytes between all pairs
        for i in range(len(group)):
            for j in range(i + 1, len(group)):
                s1 = group[i]["stream"]
                s2 = group[j]["stream"]
                matching = sum(1 for a, b in zip(s1, s2) if a == b)
                hamming = sum(bin(a ^ b).count('1') for a, b in zip(s1, s2))
                print(f"    '{group[i]['key']}' vs '{group[j]['key']}': "
                      f"{matching}/20 bytes match, hamming={hamming}/160")


def analyze_sequential_keys(data):
    """Look at how small key changes affect the stream."""
    print("\n" + "=" * 70)
    print("ANALYSIS 7: Sequential key changes (SecretKey0..19)")
    print("=" * 70)

    entries = {e["key"]: e for e in data["keys"]}

    for base in ["SecretKey", "TestKey", "Key"]:
        print(f"\n  Base: '{base}'")
        prev_stream = None
        for i in range(20):
            key = f"{base}{i}"
            if key not in entries:
                continue
            e = entries[key]
            s = e["stream"][:10]
            idx = e["mapping_index"]
            diff = ""
            if prev_stream is not None:
                matching = sum(1 for a, b in zip(s, prev_stream) if a == b)
                diff = f" ({matching}/10 match prev)"
            print(f"    {key:20s} idx={idx:>5d} stream[0:10]={s}{diff}")
            prev_stream = s


def main():
    data = load_data()
    print(f"Loaded {len(data['keys'])} entries\n")

    analyze_shared_indices(data)
    analyze_mapping_index_effect(data)
    analyze_stream_by_index_value(data)
    analyze_expanded_key_correlation(data)
    analyze_key_byte_navigation(data)
    analyze_offset_sensitivity(data)
    analyze_sequential_keys(data)


if __name__ == "__main__":
    main()
