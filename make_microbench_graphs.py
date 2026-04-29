#!/usr/bin/env python3
"""Generate DWT microbench bar charts from parse_microbench results."""
import sys
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
import matplotlib.ticker as mticker
import numpy as np
from parse_microbench import parse

def plot_mlkem(results, out='microbench_phase_f2_mlkem.png'):
    ops   = ['KEYGEN', 'ENCAP', 'DECAP']
    levels = ['512', '768', '1024']
    colors = ['#4C72B0', '#DD8452', '#55A868']

    # Collect data: means and stddevs in ms
    means = {}
    stds  = {}
    for op in ops:
        for lvl in levels:
            key = f'MLKEM{lvl}_{op}'
            means[(op, lvl)] = results[key]['mean']  / 1000.0
            stds[(op, lvl)]  = results[key]['stddev'] / 1000.0

    x      = np.arange(len(ops))
    width  = 0.22
    offsets = [-width, 0, width]

    fig, ax = plt.subplots(figsize=(9, 5))
    for i, (lvl, off, col) in enumerate(zip(levels, offsets, colors)):
        vals = [means[(op, lvl)] for op in ops]
        errs = [stds[(op, lvl)]  for op in ops]
        bars = ax.bar(x + off, vals, width, label=f'ML-KEM-{lvl}',
                      color=col, yerr=errs, capsize=4, error_kw={'linewidth': 1.2})
        for bar, v in zip(bars, vals):
            ax.text(bar.get_x() + bar.get_width() / 2, bar.get_height() + 0.3,
                    f'{v:.1f}', ha='center', va='bottom', fontsize=7.5)

    ax.set_xticks(x)
    ax.set_xticklabels(ops, fontsize=11)
    ax.set_ylabel('Time (ms)', fontsize=11)
    ax.set_title('ML-KEM Standalone DWT Microbench — STM32F439ZI @ 168 MHz (-O0 Debug)', fontsize=11)
    ax.legend(fontsize=10)
    ax.yaxis.set_minor_locator(mticker.AutoMinorLocator())
    ax.grid(axis='y', which='both', linestyle='--', alpha=0.4)
    ax.set_ylim(0, max(means[('DECAP', '1024')] * 1.18, 60))
    fig.tight_layout()
    fig.savefig(out, dpi=150)
    print(f'Saved {out}')


def plot_ecc_vs_mlkem(results, out='microbench_phase_f2_ecc_mlkem.png'):
    labels = ['P256\nKeygen', 'P256\nECDH', 'X25519\nKeygen', 'X25519\nECDH',
              'MLKEM512\nKeygen', 'MLKEM768\nKeygen', 'MLKEM1024\nKeygen',
              'MLKEM512\nEncap', 'MLKEM512\nDecap']
    keys   = ['P256_KEYGEN', 'P256_ECDH', 'X25519_KEYGEN', 'X25519_ECDH',
              'MLKEM512_KEYGEN', 'MLKEM768_KEYGEN', 'MLKEM1024_KEYGEN',
              'MLKEM512_ENCAP', 'MLKEM512_DECAP']
    colors_ecc  = ['#4C72B0'] * 4
    colors_mlkem = ['#DD8452'] * 5
    colors = colors_ecc + colors_mlkem

    vals = [results[k]['mean'] / 1000.0 for k in keys if k in results]
    errs = [results[k]['stddev'] / 1000.0 for k in keys if k in results]
    labels_present = [l for l, k in zip(labels, keys) if k in results]
    colors_present = [c for c, k in zip(colors, keys) if k in results]

    fig, ax = plt.subplots(figsize=(12, 5))
    bars = ax.bar(range(len(vals)), vals, color=colors_present,
                  yerr=errs, capsize=3, error_kw={'linewidth': 1.0})
    for bar, v in zip(bars, vals):
        ax.text(bar.get_x() + bar.get_width() / 2, bar.get_height() + 0.5,
                f'{v:.1f}', ha='center', va='bottom', fontsize=8)

    ax.set_xticks(range(len(vals)))
    ax.set_xticklabels(labels_present, fontsize=8.5)
    ax.set_ylabel('Time (ms)', fontsize=11)
    ax.set_title('ECC vs ML-KEM DWT Microbench — STM32F439ZI @ 168 MHz (-O0 Debug)', fontsize=11)
    from matplotlib.patches import Patch
    ax.legend(handles=[Patch(color='#4C72B0', label='ECC (P256 / X25519)'),
                       Patch(color='#DD8452', label='ML-KEM')], fontsize=10)
    ax.yaxis.set_minor_locator(mticker.AutoMinorLocator())
    ax.grid(axis='y', which='both', linestyle='--', alpha=0.4)
    fig.tight_layout()
    fig.savefig(out, dpi=150)
    print(f'Saved {out}')


def main():
    path = sys.argv[1] if len(sys.argv) > 1 else 'results/benchmark_microbench_mlkem_20260430.txt'
    results = parse(path)
    if not results:
        print('No results found'); sys.exit(1)
    plot_mlkem(results)
    plot_ecc_vs_mlkem(results)

if __name__ == '__main__':
    main()
