#!/usr/bin/env python3
"""Parse garbled UART matrix benchmark log and compute per-scenario statistics."""
import re
import math
import argparse
from collections import defaultdict

def mean(xs):
    return sum(xs) / len(xs)

def stddev(xs):
    if len(xs) < 2:
        return 0.0
    m = mean(xs)
    return math.sqrt(sum((x - m) ** 2 for x in xs) / len(xs))

def ci95(xs):
    m = mean(xs); s = stddev(xs); n = len(xs)
    e = 1.96 * s / math.sqrt(n)
    return m - e, m + e


def parse(log_path):
    scenario_timings  = defaultdict(list)
    scenario_errors   = defaultdict(int)
    scenario_phases   = {}   # name -> (sh, cert, cv, pqcv, fin)
    scenario_sizes    = {}   # name -> (cert_b, certvy_b, pqcertvy_b)
    scenario_heap     = {}   # name -> (min_free_b, peak_used_b)
    scenario_order    = []
    current           = None
    expecting_phases  = False  # True only directly after a Results: line

    header_re  = re.compile(r'===\s+([A-Z0-9_]+)\s+===')
    ok_re      = re.compile(
        r'\b((?:ECDSA|MLDSA|CATALYST|CHAMELEON|RELATED|DUAL|COMPOSITE'
        r'|FALCON|SPHINCS_FAST|SPHINCS_SMALL)'
        r'_L[135]_(?:P256|P384|X25519|HYB768|HYB1024|MLKEM512|MLKEM768|MLKEM1024))\b'
        r'.*?OK \((\d+) ms\)')
    results_re = re.compile(r'Results:\s+([A-Z][A-Z0-9_]+)')
    # Tightened: require d+.d+ and trailing ms to avoid garbled float strings
    phases_re  = re.compile(
        r'phases\s+'
        r'SrvHello=(\d+\.\d+)\s+'
        r'Cert=(\d+\.\d+)\s+'
        r'CertVfy=(\d+\.\d+)\s+'
        r'PQCertVfy=(\d+\.\d+)\s+'
        r'Finished=(\d+\.\d+)\s*ms')
    sizes_re   = re.compile(
        r'sizes\s+Cert=(\d+)B\s+CertVfy=(\d+)B\s+PQCertVfy=(\d+)B')
    heap_re    = re.compile(
        r'heap\s+min_free=(\d+)B\s+peak_used=(\d+)B')
    n_re       = re.compile(r'n=(\d+)')
    nerr_re    = re.compile(r'errors=(\d+)')

    with open(log_path, 'rb') as f:
        raw = f.read()

    for raw_line in re.split(b'[\r\n]+', raw):
        try:
            line = raw_line.decode('ascii', errors='replace')
        except Exception:
            continue

        m = header_re.search(line)
        if m:
            current = m.group(1)
            expecting_phases = False
            if current not in scenario_order:
                scenario_order.append(current)
            continue

        m = results_re.search(line)
        if m:
            current = m.group(1)
            expecting_phases = True
            if current not in scenario_order:
                scenario_order.append(current)
            nm = n_re.search(line); em = nerr_re.search(line)
            if nm and em:
                scenario_errors[current] = int(em.group(1))
            continue

        # Only accept phases line immediately after a Results: line for the same scenario
        if expecting_phases:
            m = phases_re.search(line)
            if m and current:
                try:
                    vals = tuple(float(m.group(i)) for i in range(1, 6))
                    scenario_phases[current] = vals
                except ValueError:
                    pass
                expecting_phases = False
                continue

        # sizes/heap lines — match anywhere, attach to current scenario
        m = sizes_re.search(line)
        if m and current:
            scenario_sizes[current] = (int(m.group(1)), int(m.group(2)), int(m.group(3)))
            continue

        m = heap_re.search(line)
        if m and current:
            scenario_heap[current] = (int(m.group(1)), int(m.group(2)))
            continue

        m = ok_re.search(line)
        if m:
            scen = m.group(1); ms = int(m.group(2))
            if scen not in scenario_order:
                scenario_order.append(scen)
            scenario_timings[scen].append(ms)
            current = scen
            expecting_phases = False

    return scenario_order, scenario_timings, scenario_errors, scenario_phases, scenario_sizes, scenario_heap


def report(scenario_order, timings, errors, phases, sizes=None, heap=None,
           phases_file=None, sizes_file=None):
    hdr = (f"{'Scenario':<35} {'n':>5} {'err':>4} {'mean':>8} "
           f"{'stddev':>7} {'min':>6} {'max':>6} {'95CI_lo':>8} {'95CI_hi':>8}")
    print(hdr)
    print("-" * len(hdr))
    for sc in scenario_order:
        t = timings.get(sc, [])
        e = errors.get(sc, 0)
        if not t:
            print(f"{sc:<35} {'?':>5} {e:>4}  (no data)")
            continue
        n = len(t); m = mean(t); s = stddev(t)
        lo, hi = ci95(t) if n > 1 else (m, m)
        print(f"{sc:<35} {n:>5} {e:>4} {m:>8.1f} {s:>7.1f} "
              f"{min(t):>6} {max(t):>6} {lo:>8.1f} {hi:>8.1f}")

    complete = [s for s in scenario_order if len(timings.get(s, [])) >= 100]
    print(f"\nComplete (≥100): {len(complete)}/78 scenarios"
          f"  (SPHINCS_FAST L3/L5 excluded: pvPortMalloc limit)")

    # Phase breakdown — independent section (does not gate sizes/heap)
    phases_with_data = [
        (sc, phases[sc]) for sc in scenario_order
        if sc in phases and sum(phases[sc]) > 0.0
    ]
    if phases_with_data:
        missing = [sc for sc in scenario_order if sc in timings and sc not in phases]
        ph_hdr = (f"{'Scenario':<35} {'SrvHello':>9} {'Cert':>9} {'CertVfy':>9} "
                  f"{'PQCertVfy':>11} {'Finished':>9} {'Sum':>8}")
        ph_sep = "-" * len(ph_hdr)
        rows = []
        for sc, (sh, cert, cv, pqcv, fin) in phases_with_data:
            total = sh + cert + cv + pqcv + fin
            rows.append(f"{sc:<35} {sh:>9.1f} {cert:>9.1f} {cv:>9.1f} "
                        f"{pqcv:>11.1f} {fin:>9.1f} {total:>8.1f}")
        print(f"\n{ph_hdr}")
        print(ph_sep)
        for r in rows:
            print(r)
        footer = (f"\nPhase breakdown: {len(phases_with_data)}/78 scenarios parsed"
                  f"  (Note: Sum < total mean — phases cover only wolfSSL callbacks,"
                  f" not TCP/TLS protocol overhead)")
        if missing:
            footer += f"\nNo phases line captured: {', '.join(missing)}"
        print(footer)
        if phases_file:
            with open(phases_file, 'w', encoding='utf-8') as f:
                f.write(ph_hdr + '\n')
                f.write(ph_sep + '\n')
                for r in rows:
                    f.write(r + '\n')
                f.write(footer + '\n')
            print(f"[saved] {phases_file}")

    # Wire sizes table — independent section
    sizes_with_data = [(sc, sizes[sc]) for sc in scenario_order if sc in (sizes or {})]
    # Heap watermark: cumulative since boot (monotonically non-increasing min_free)
    heap_with_data  = [(sc, heap[sc])  for sc in scenario_order if sc in (heap or {})]

    if sizes_with_data:
        sz_hdr = (f"{'Scenario':<35} {'Cert_B':>8} {'CertVfy_B':>10} {'PQCertVfy_B':>12}")
        sz_sep = "-" * len(sz_hdr)
        sz_rows = []
        for sc, (cb, cvb, pqcvb) in sizes_with_data:
            sz_rows.append(f"{sc:<35} {cb:>8} {cvb:>10} {pqcvb:>12}")
        print(f"\n{sz_hdr}")
        print(sz_sep)
        for r in sz_rows:
            print(r)
        print(f"\nWire sizes: {len(sizes_with_data)} scenarios")

        hp_hdr = hp_sep = hp_rows = None
        if heap_with_data:
            # peak_used_cum_B = total_heap - min_free_B (cumulative since boot, not per-scenario)
            hp_hdr = (f"{'Scenario':<35} {'min_free_B':>10} {'peak_used_cum_B':>16}")
            hp_sep = "-" * len(hp_hdr)
            hp_rows = []
            for sc, (mf, pu) in heap_with_data:
                hp_rows.append(f"{sc:<35} {mf:>10} {pu:>16}")
            print(f"\n{hp_hdr}")
            print(hp_sep)
            for r in hp_rows:
                print(r)
            print(f"\nHeap watermark (cumulative since boot): {len(heap_with_data)} scenarios")

        if sizes_file:
            with open(sizes_file, 'w', encoding='utf-8') as f:
                f.write(sz_hdr + '\n'); f.write(sz_sep + '\n')
                for r in sz_rows:
                    f.write(r + '\n')
                if hp_rows:
                    f.write('\n' + hp_hdr + '\n'); f.write(hp_sep + '\n')
                    for r in hp_rows:
                        f.write(r + '\n')
            print(f"[saved] {sizes_file}")


if __name__ == '__main__':
    ap = argparse.ArgumentParser()
    ap.add_argument('log', nargs='?', default='uart_matrix_v9_1526.log')
    ap.add_argument('-p', '--phases-file', default=None,
                    help='Write phase breakdown table to this file')
    ap.add_argument('-s', '--sizes-file', default=None,
                    help='Write wire-sizes and heap table to this file')
    args = ap.parse_args()
    order, timings, errs, phases, sizes, heap = parse(args.log)
    report(order, timings, errs, phases, sizes, heap,
           phases_file=args.phases_file, sizes_file=args.sizes_file)
