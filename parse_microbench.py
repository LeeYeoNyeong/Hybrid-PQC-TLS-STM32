#!/usr/bin/env python3
"""Parse DWT microbenchmark UART output and print summary table."""
import re
import sys

def parse(path):
    results = {}
    with open(path) as f:
        for line in f:
            m = re.match(
                r'\[MICRO\]\s+([\w]+)\s+n=(\d+)\s+mean=\s*([\d.]+) us\s+stddev=\s*([\d.]+) us'
                r'\s+min=\s*([\d.]+)\s+max=\s*([\d.]+)',
                line.strip())
            if m:
                results[m.group(1)] = {
                    'n':      int(m.group(2)),
                    'mean':   float(m.group(3)),
                    'stddev': float(m.group(4)),
                    'min':    float(m.group(5)),
                    'max':    float(m.group(6)),
                }
    return results

def main():
    if len(sys.argv) < 2:
        print(f'Usage: {sys.argv[0]} <uart_log>')
        sys.exit(1)
    results = parse(sys.argv[1])
    if not results:
        print('No [MICRO] lines found.')
        sys.exit(1)

    hdr = f"{'Operation':<22} {'n':>5} {'mean(µs)':>10} {'stddev':>8} {'min':>8} {'max':>8}"
    print(hdr)
    print('-' * len(hdr))
    for name, r in results.items():
        print(f"{name:<22} {r['n']:>5} {r['mean']:>10.1f} {r['stddev']:>8.1f} "
              f"{r['min']:>8.1f} {r['max']:>8.1f}")

    # Ratio summary — ECC
    if 'P256_KEYGEN' in results and 'X25519_KEYGEN' in results:
        ratio_kg = results['X25519_KEYGEN']['mean'] / results['P256_KEYGEN']['mean']
        print(f"\nX25519/P256 keygen ratio: {ratio_kg:.1f}×")
    if 'P256_ECDH' in results and 'X25519_ECDH' in results:
        ratio_dh = results['X25519_ECDH']['mean'] / results['P256_ECDH']['mean']
        print(f"X25519/P256 ECDH ratio:   {ratio_dh:.1f}×")

    # ML-KEM scaling across levels
    for op in ('KEYGEN', 'ENCAP', 'DECAP'):
        k512, k768, k1024 = f'MLKEM512_{op}', f'MLKEM768_{op}', f'MLKEM1024_{op}'
        if k512 in results and k768 in results and k1024 in results:
            m512 = results[k512]['mean']
            print(f"\nML-KEM {op} (µs):  512={m512:.0f}  "
                  f"768={results[k768]['mean']:.0f} ({results[k768]['mean']/m512:.1f}×)  "
                  f"1024={results[k1024]['mean']:.0f} ({results[k1024]['mean']/m512:.1f}×)")

if __name__ == '__main__':
    main()
