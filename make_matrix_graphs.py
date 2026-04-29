#!/usr/bin/env python3
"""Generate cert×KEM matrix benchmark graphs — Phase D + retest combined (2026-04-29)."""
import re
import os
import numpy as np
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
import matplotlib.colors as mcolors
from matplotlib.patches import Patch

OUT_DIR  = 'benchmark_graphs_20260429'
T_FILE   = 'benchmark_matrix_timing_96_20260428.txt'
PH_FILE  = 'benchmark_matrix_phases_x25519mlkem_20260428.txt'
RETEST_T_FILE  = 'benchmark_retest_x25519mlkem_20260429.txt'
RETEST_PH_FILE = 'benchmark_retest_phases_20260429.txt'

os.makedirs(OUT_DIR, exist_ok=True)

# ── cert types (display order, label) ──────────────────────────────────────
CERT_ORDER = ['ECDSA', 'MLDSA', 'RELATED', 'CATALYST', 'CHAMELEON',
              'DUAL', 'COMPOSITE', 'FALCON', 'SPHINCS_FAST', 'SPHINCS_SMALL']
CERT_LABEL = {
    'ECDSA': 'ECDSA', 'MLDSA': 'ML-DSA', 'RELATED': 'Related',
    'CATALYST': 'Catalyst', 'CHAMELEON': 'Chameleon', 'DUAL': 'Dual',
    'COMPOSITE': 'Composite', 'FALCON': 'Falcon',
    'SPHINCS_FAST': 'SPHINCS+\n(fast)', 'SPHINCS_SMALL': 'SPHINCS+\n(small)',
}

# 11 matrix columns: (level, kem_suffix, column_label)
COLS = [
    ('L1', 'P256',           'L1\nP-256'),
    ('L1', 'X25519',         'L1\nX25519*'),
    ('L1', 'X25519MLKEM512', 'L1\nX25519\nMLKEM512'),
    ('L1', 'MLKEM512',       'L1\nMLKEM512'),
    ('L3', 'P256',           'L3\nP-256'),
    ('L3', 'HYB768',         'L3\nHYB768'),
    ('L3', 'X25519MLKEM768', 'L3\nX25519\nMLKEM768'),
    ('L3', 'MLKEM768',       'L3\nMLKEM768'),
    ('L5', 'P384',           'L5\nP-384'),
    ('L5', 'HYB1024',        'L5\nHYB1024'),
    ('L5', 'MLKEM1024',      'L5\nMLKEM1024'),
]


# ── loaders ────────────────────────────────────────────────────────────────

def load_timing(path, min_n=100):
    """Return {scenario: mean_ms} for n>=min_n rows (timing section only)."""
    data = {}
    with open(path) as f:
        for line in f:
            # combined file has phases/sizes/heap sections after timing — stop at first non-timing header
            if any(kw in line for kw in ('SrvHello', 'Cert_B', 'min_free_B')):
                break
            m = re.match(r'([A-Z][A-Z0-9_]+)\s+(\d+)\s+\d+\s+([\d.]+)', line)
            if m and int(m.group(2)) >= min_n:
                data[m.group(1)] = float(m.group(3))
    return data


def load_phases(path):
    """Return {scenario: (sh, cert, cv, pqcv, fin)}."""
    data = {}
    with open(path) as f:
        for line in f:
            m = re.match(
                r'([A-Z][A-Z0-9_]+)\s+([\d.]+)\s+([\d.]+)\s+([\d.]+)\s+([\d.]+)\s+([\d.]+)',
                line)
            if m:
                data[m.group(1)] = tuple(float(m.group(i)) for i in range(2, 7))
    return data


def load_sizes(path):
    """Return ({scenario: cert_b}, {scenario: peak_used_cum_b}) from -s output file."""
    cert_bytes = {}
    heap_bytes = {}
    mode = None
    with open(path) as f:
        for line in f:
            line = line.rstrip()
            if 'Cert_B' in line:
                mode = 'sizes'
            elif 'min_free_B' in line:
                mode = 'heap'
            elif mode == 'sizes':
                m = re.match(r'([A-Z][A-Z0-9_]+)\s+(\d+)\s+(\d+)\s+(\d+)', line)
                if m:
                    cert_bytes[m.group(1)] = int(m.group(2))
            elif mode == 'heap':
                m = re.match(r'([A-Z][A-Z0-9_]+)\s+(\d+)\s+(\d+)', line)
                if m:
                    heap_bytes[m.group(1)] = int(m.group(3))
    return cert_bytes, heap_bytes


def key(cert, level, kem):
    return f'{cert}_{level}_{kem}'


# Load Phase D data (96 scenarios, 6 X25519MLKEM had server errors → no data)
timing = load_timing(T_FILE)
phases = load_phases(PH_FILE)

# Overlay retest data (6 corrected X25519MLKEM scenarios, n>=95)
timing.update(load_timing(RETEST_T_FILE, min_n=95))
phases.update(load_phases(RETEST_PH_FILE))


# ── 1. Cert × KEM Heatmap ──────────────────────────────────────────────────

def plot_heatmap():
    n_rows, n_cols = len(CERT_ORDER), len(COLS)
    grid   = np.full((n_rows, n_cols), np.nan)
    labels = [[''] * n_cols for _ in range(n_rows)]

    for r, cert in enumerate(CERT_ORDER):
        for c, (lv, kem, _) in enumerate(COLS):
            sc = key(cert, lv, kem)
            if sc in timing:
                grid[r, c] = timing[sc]
                labels[r][c] = f'{timing[sc]:.0f}'

    # Custom colormap: white→yellow→red, gray for NaN
    cmap = plt.cm.YlOrRd.copy()
    cmap.set_bad(color='#CCCCCC')

    fig, ax = plt.subplots(figsize=(14, 7))
    vmin = np.nanmin(grid[grid < 2000])   # cap colorbar at 2s for readability
    vmax = 2000
    im = ax.imshow(grid, cmap=cmap, aspect='auto',
                   norm=mcolors.PowerNorm(gamma=0.5, vmin=vmin, vmax=vmax))

    # annotate cells
    for r in range(n_rows):
        for c in range(n_cols):
            if np.isnan(grid[r, c]):
                ax.text(c, r, 'OOM', ha='center', va='center', fontsize=7,
                        color='#555', fontstyle='italic')
            else:
                ms = grid[r, c]
                color = 'white' if ms > 1200 else 'black'
                txt = f'{ms/1000:.1f}s' if ms >= 1000 else f'{ms:.0f}ms'
                ax.text(c, r, txt, ha='center', va='center', fontsize=6.5,
                        color=color, fontweight='bold')

    ax.set_xticks(range(n_cols))
    ax.set_xticklabels([c[2] for c in COLS], fontsize=8)
    ax.set_yticks(range(n_rows))
    ax.set_yticklabels([CERT_LABEL[c] for c in CERT_ORDER], fontsize=9)
    ax.set_title('TLS 1.3 Handshake Latency — Cert × KEM Matrix\n'
                 'STM32F439ZI @ 168 MHz, n=100, OOM=hardware limit, *=non-SP X25519',
                 fontsize=11)
    cbar = fig.colorbar(im, ax=ax, shrink=0.8)
    cbar.set_label('Latency (ms, PowerNorm γ=0.5, cap 2s)', fontsize=8)
    # add vertical separators between level groups
    for x in [2.5, 5.5]:
        ax.axvline(x, color='white', linewidth=2)
    ax.text(1,   -0.7, 'Level 1', ha='center', fontsize=8, style='italic', transform=ax.transData)
    ax.text(4,   -0.7, 'Level 3', ha='center', fontsize=8, style='italic', transform=ax.transData)
    ax.text(7,   -0.7, 'Level 5', ha='center', fontsize=8, style='italic', transform=ax.transData)
    plt.tight_layout()
    out = f'{OUT_DIR}/cert_kem_heatmap.png'
    plt.savefig(out, dpi=150, bbox_inches='tight')
    plt.close()
    print(f'[saved] {out}')


# ── 2. Stacked Stage Breakdown (P-256/P-384 KEM fixed per level) ───────────

def plot_stacked_breakdown():
    PHASE_COLORS = ['#4A90D9', '#F5A623', '#E74C3C', '#9B59B6', '#2ECC71']
    PHASE_NAMES  = ['SrvHello (KEM)', 'Cert (chain)', 'CertVfy (sig)', 'PQCertVfy (hybrid)', 'Finished']

    # select classical KEM per level
    kem_per_level = {'L1': 'P256', 'L3': 'P256', 'L5': 'P384'}
    rows, row_labels = [], []
    for cert in CERT_ORDER:
        for lv, kem in [('L1', 'P256'), ('L3', 'P256'), ('L5', 'P384')]:
            sc = key(cert, lv, kem)
            if sc in phases and sum(phases[sc]) > 0:
                rows.append(phases[sc])
                rows[-1] = rows[-1][:5]  # (sh, cert, cv, pqcv, fin)
                lv_short = {'L1': '1', 'L3': '3', 'L5': '5'}[lv]
                row_labels.append(f'{CERT_LABEL[cert]}\nL{lv_short}')

    arr = np.array(rows)
    x = np.arange(len(rows))
    fig, ax = plt.subplots(figsize=(18, 6))
    bottom = np.zeros(len(rows))
    for i, (name, color) in enumerate(zip(PHASE_NAMES, PHASE_COLORS)):
        vals = arr[:, i]
        ax.bar(x, vals, bottom=bottom, label=name, color=color, width=0.7)
        bottom += vals

    ax.set_xticks(x)
    ax.set_xticklabels(row_labels, fontsize=6.5, rotation=0)
    ax.set_ylabel('Latency (ms)')
    ax.set_title('Stage Breakdown per Cert × Level (P-256/P-384 KEM, n=100)\n'
                 'Note: Sum < total handshake — unaccounted = TCP/TLS overhead', fontsize=10)
    ax.legend(loc='upper left', fontsize=8)
    # draw vertical separators between cert types
    cert_group_size = 3
    for i in range(1, len(CERT_ORDER)):
        ax.axvline(i * cert_group_size - 0.5, color='gray', linewidth=0.8, linestyle='--')
    plt.tight_layout()
    out = f'{OUT_DIR}/stacked_stage_breakdown.png'
    plt.savefig(out, dpi=150, bbox_inches='tight')
    plt.close()
    print(f'[saved] {out}')


# ── 3. Cert Type Comparison (P-256/P-384 KEM fixed) ───────────────────────

def plot_cert_comparison():
    LEVEL_COLORS = {'L1': '#4A90D9', 'L3': '#F5A623', 'L5': '#E74C3C'}
    LEVELS = [('L1', 'P256'), ('L3', 'P256'), ('L5', 'P384')]

    fig, ax = plt.subplots(figsize=(14, 6))
    n_cert = len(CERT_ORDER)
    n_lv   = len(LEVELS)
    width  = 0.25
    x = np.arange(n_cert)

    for i, (lv, kem) in enumerate(LEVELS):
        vals, errs = [], []
        for cert in CERT_ORDER:
            sc = key(cert, lv, kem)
            vals.append(timing.get(sc, 0))
        offset = (i - 1) * width
        bars = ax.bar(x + offset, vals, width=width, label=f'L{lv[1]} ({kem})',
                      color=LEVEL_COLORS[lv], alpha=0.85)
        for bar, val in zip(bars, vals):
            if val > 0:
                ax.text(bar.get_x() + bar.get_width()/2, bar.get_height() + 15,
                        f'{val:.0f}', ha='center', va='bottom', fontsize=5.5, rotation=90)

    ax.set_xticks(x)
    ax.set_xticklabels([CERT_LABEL[c] for c in CERT_ORDER], fontsize=9)
    ax.set_ylabel('Mean Latency (ms)')
    ax.set_title('Cert Type Comparison — Classical KEM (P-256/P-384), n=100\n'
                 'STM32F439ZI @ 168 MHz', fontsize=11)
    ax.legend()
    ax.set_ylim(0, ax.get_ylim()[1] * 1.15)
    plt.tight_layout()
    out = f'{OUT_DIR}/cert_comparison_classical_kem.png'
    plt.savefig(out, dpi=150, bbox_inches='tight')
    plt.close()
    print(f'[saved] {out}')


# ── 4. KEM Comparison (L1 only, all cert types) ────────────────────────────

def plot_kem_comparison():
    L1_KEMS = [
        ('P256',           'P-256 (classical)',        '#4A90D9'),
        ('X25519',         'X25519* (non-SP)',          '#F5A623'),
        ('X25519MLKEM512', 'X25519+ML-KEM-512 (hybrid)','#9B59B6'),
        ('MLKEM512',       'ML-KEM-512 (PQC)',          '#2ECC71'),
    ]
    fig, ax = plt.subplots(figsize=(16, 6))
    n_cert = len(CERT_ORDER)
    width  = 0.22
    x = np.arange(n_cert)

    for i, (kem, label, color) in enumerate(L1_KEMS):
        vals = [timing.get(key(c, 'L1', kem), 0) for c in CERT_ORDER]
        offset = (i - 1.5) * width
        bars = ax.bar(x + offset, vals, width=width, label=label, color=color, alpha=0.85)
        for bar, val in zip(bars, vals):
            if val > 0:
                ax.text(bar.get_x() + bar.get_width()/2, bar.get_height() + 15,
                        f'{val:.0f}', ha='center', va='bottom', fontsize=5.5, rotation=90)

    ax.set_xticks(x)
    ax.set_xticklabels([CERT_LABEL[c] for c in CERT_ORDER], fontsize=9)
    ax.set_ylabel('Mean Latency (ms)')
    ax.set_title('KEM Group Comparison at Level 1 (all cert types), n=100\n'
                 '*X25519: non-SP Cortex-M implementation (~9× slower than P-256)', fontsize=10)
    ax.legend()
    ax.set_ylim(0, ax.get_ylim()[1] * 1.15)
    plt.tight_layout()
    out = f'{OUT_DIR}/kem_comparison_l1.png'
    plt.savefig(out, dpi=150, bbox_inches='tight')
    plt.close()
    print(f'[saved] {out}')


# ── 5. PQC Cost Decomposition ──────────────────────────────────────────────

def plot_pqc_decomposition():
    """Show classical vs PQ verification cost for cert types with PQCertVfy > 0."""
    HYBRID_CERTS = ['RELATED', 'CATALYST', 'CHAMELEON', 'DUAL']
    LEVELS = [('L1', 'P256'), ('L3', 'P256'), ('L5', 'P384')]

    rows, labels, classical, pq_cost = [], [], [], []
    for cert in HYBRID_CERTS:
        for lv, kem in LEVELS:
            sc = key(cert, lv, kem)
            if sc in phases:
                sh, cert_t, cv, pqcv, fin = phases[sc]
                total_ph = sh + cert_t + cv + pqcv + fin
                if total_ph > 0 and pqcv > 0:
                    rows.append(sc)
                    labels.append(f'{CERT_LABEL[cert]}\nL{lv[1]}')
                    classical.append(sh + cert_t + cv + fin)
                    pq_cost.append(pqcv)

    x = np.arange(len(rows))
    fig, ax = plt.subplots(figsize=(12, 5))
    bar_cl = ax.bar(x, classical, label='Classical (SrvHello+Cert+CertVfy)', color='#4A90D9', alpha=0.85)
    bar_pq = ax.bar(x, pq_cost, bottom=classical, label='PQCertVfy (hybrid PQ sig)', color='#E74C3C', alpha=0.85)

    # annotate PQ fraction
    for xi, (cl, pq) in enumerate(zip(classical, pq_cost)):
        total = cl + pq
        frac  = pq / total * 100
        ax.text(xi, total + 2, f'{frac:.0f}%', ha='center', va='bottom', fontsize=7, color='#E74C3C')

    ax.set_xticks(x)
    ax.set_xticklabels(labels, fontsize=8)
    ax.set_ylabel('Phase Sum (ms)\n(measured wolfSSL callbacks only)')
    ax.set_title('PQC Cost Decomposition — Hybrid Cert Types\n'
                 'Red % = PQCertVfy fraction of measured phase sum', fontsize=10)
    ax.legend(fontsize=8)
    # vertical separators per cert type
    for i in range(1, len(HYBRID_CERTS)):
        ax.axvline(i * 3 - 0.5, color='gray', linewidth=0.8, linestyle='--')
    plt.tight_layout()
    out = f'{OUT_DIR}/pqc_cost_decomposition.png'
    plt.savefig(out, dpi=150, bbox_inches='tight')
    plt.close()
    print(f'[saved] {out}')


SZ_FILE = 'benchmark_matrix_sizes_x25519mlkem_20260428.txt'

LEVEL_COLORS = {'L1': '#2ECC71', 'L3': '#F39C12', 'L5': '#E74C3C'}


def plot_cert_chain_sizes(sz_file=SZ_FILE):
    """Bar chart: cert chain DER total bytes per cert type × security level (P256 baseline KEM)."""
    if not os.path.exists(sz_file):
        print(f'[skip] {sz_file} not found — run capture first')
        return
    cert_bytes, _ = load_sizes(sz_file)

    # collect P256/P384 baseline KEM per level for each cert type
    records = {}  # cert -> {level: bytes}
    baseline_kem = {'L1': 'P256', 'L3': 'P256', 'L5': 'P384'}
    for cert in CERT_ORDER:
        records[cert] = {}
        for lv, bk in baseline_kem.items():
            sc = key(cert, lv, bk)
            if sc in cert_bytes and cert_bytes[sc] > 0:
                records[cert][lv] = cert_bytes[sc]

    labels = [CERT_LABEL[c].replace('\n', '\n') for c in CERT_ORDER]
    x = np.arange(len(CERT_ORDER))
    w = 0.25
    fig, ax = plt.subplots(figsize=(13, 5))
    for i, lv in enumerate(['L1', 'L3', 'L5']):
        vals = [records[c].get(lv, 0) for c in CERT_ORDER]
        bars = ax.bar(x + (i - 1) * w, vals, w, label=lv, color=LEVEL_COLORS[lv])
        for b, v in zip(bars, vals):
            if v > 0:
                ax.text(b.get_x() + b.get_width() / 2, b.get_height() + 20,
                        f'{v}', ha='center', va='bottom', fontsize=6, rotation=90)

    ax.set_xticks(x)
    ax.set_xticklabels(labels, fontsize=8)
    ax.set_ylabel('Cert Chain DER Total (bytes)')
    ax.set_title('Peer Certificate Chain DER Size by Cert Type & Security Level\n'
                 '(Baseline KEM: L1/L3=P-256, L5=P-384; sum of all DER certs in SESSION_CERTS chain)',
                 fontsize=10)
    ax.legend(title='Level')
    plt.tight_layout()
    out = f'{OUT_DIR}/handshake_size_per_alg.png'
    plt.savefig(out, dpi=150, bbox_inches='tight')
    plt.close()
    print(f'[saved] {out}')


def plot_heap_watermark(sz_file=SZ_FILE):
    """Horizontal bar chart: cumulative heap peak_used per cert type (worst KEM per level)."""
    if not os.path.exists(sz_file):
        print(f'[skip] {sz_file} not found — run capture first')
        return
    _, heap_bytes = load_sizes(sz_file)
    if not heap_bytes:
        print('[skip] no heap data in sizes file')
        return

    # highest peak_used per cert type across all KEM/level combos
    worst = {}
    for sc, pu in heap_bytes.items():
        parts = sc.split('_')
        cert = '_'.join(parts[:-2]) if len(parts) > 3 else parts[0]
        # try to match known cert types
        for c in CERT_ORDER:
            if sc.startswith(c + '_'):
                worst[c] = max(worst.get(c, 0), pu)
                break

    labels = [CERT_LABEL[c].replace('\n', ' ') for c in CERT_ORDER if c in worst]
    vals   = [worst[c] / 1024 for c in CERT_ORDER if c in worst]
    total_kb = 194.0  # CCM 56KB + SRAM 138KB

    fig, ax = plt.subplots(figsize=(9, 5))
    colors = plt.cm.RdYlGn_r(np.linspace(0.2, 0.8, len(vals)))
    bars = ax.barh(labels, vals, color=colors)
    ax.axvline(total_kb, color='red', linestyle='--', linewidth=1.2, label=f'Total heap {total_kb:.0f} KB')
    for b, v in zip(bars, vals):
        ax.text(v + 1, b.get_y() + b.get_height() / 2,
                f'{v:.1f} KB', va='center', fontsize=8)
    ax.set_xlabel('Cumulative Peak Used Heap (KB, since boot)')
    ax.set_title('Heap Peak Usage by Cert Type\n'
                 '(worst scenario per type; cumulative since boot — monotonically non-decreasing)',
                 fontsize=10)
    ax.legend()
    plt.tight_layout()
    out = f'{OUT_DIR}/heap_peak_per_scenario.png'
    plt.savefig(out, dpi=150, bbox_inches='tight')
    plt.close()
    print(f'[saved] {out}')


if __name__ == '__main__':
    import sys
    sz_file = sys.argv[1] if len(sys.argv) > 1 else SZ_FILE
    plot_heatmap()
    plot_stacked_breakdown()
    plot_cert_comparison()
    plot_kem_comparison()
    plot_pqc_decomposition()
    plot_cert_chain_sizes(sz_file)
    plot_heap_watermark(sz_file)
    print(f'\nAll graphs saved to {OUT_DIR}/')
    print(f'   Files: {sorted(os.listdir(OUT_DIR))}')
