#!/usr/bin/env python3
"""Parse garbled UART matrix benchmark log and compute per-scenario statistics."""
import re, sys, math, argparse
from collections import defaultdict

def mean(xs):   return sum(xs)/len(xs)
def stddev(xs):
    m = mean(xs); return math.sqrt(sum((x-m)**2 for x in xs)/len(xs))
def ci95(xs):
    m = mean(xs); s = stddev(xs); n = len(xs)
    z = 1.96; e = z*s/math.sqrt(n)
    return m-e, m+e

def parse(log_path):
    # Strategy: find "=== SCENARIO ===" headers to track active scenario,
    # then collect timings from "SCENARIO → OK (NNN ms)" lines.
    scenario_timings = defaultdict(list)
    scenario_errors  = defaultdict(int)
    scenario_order   = []  # preserve insertion order
    current = None

    # Patterns
    header_re   = re.compile(r'===\s+([A-Z0-9_]+)\s+===')
    ok_re       = re.compile(r'([A-Z][A-Z0-9_]+(?:L[135]_(?:P256|P384|X25519|HYB\d+|MLKEM\d+|MLKEM\d+)))\s.*?OK\s+\((\d+)\s+ms\)')
    ok_short_re = re.compile(r'\b((?:ECDSA|MLDSA|CATALYST|CHAMELEON|RELATED|DUAL|COMPOSITE|FALCON|SPHINCS_FAST|SPHINCS_SMALL)_L[135]_(?:P256|P384|X25519|HYB768|HYB1024|MLKEM512|MLKEM768|MLKEM1024))\b.*?OK \((\d+) ms\)')
    err_re      = re.compile(r'([A-Z][A-Z0-9_]+)\s.*?errors=(\d+)')
    results_re  = re.compile(r'Results:\s+([A-Z][A-Z0-9_]+)')

    # Also accept phase summary line for mean (fallback)
    mean_re     = re.compile(r'mean=([\d.]+)')
    n_re        = re.compile(r'n=(\d+)')
    nerr_re     = re.compile(r'errors=(\d+)')

    with open(log_path, 'rb') as f:
        raw = f.read()

    # Split into printable lines (handle garbling: split on \n or \r)
    lines = re.split(b'[\r\n]+', raw)

    for raw_line in lines:
        try:
            line = raw_line.decode('ascii', errors='replace')
        except Exception:
            continue

        # Detect scenario header "=== SCENARIO_NAME ==="
        m = header_re.search(line)
        if m:
            current = m.group(1)
            if current not in scenario_order:
                scenario_order.append(current)
            continue

        # Detect results line "--- Results: SCENARIO ---"
        m = results_re.search(line)
        if m:
            current = m.group(1)
            if current not in scenario_order:
                scenario_order.append(current)
            # Try to extract n/errors/mean from same line
            nm = n_re.search(line); em = nerr_re.search(line); mm = mean_re.search(line)
            if nm and em:
                scenario_errors[current] = int(em.group(1))
            continue

        # Extract "SCENARIO → OK (NNN ms)" — the most reliable data source
        m = ok_short_re.search(line)
        if m:
            scen = m.group(1); ms = int(m.group(2))
            if scen not in scenario_order:
                scenario_order.append(scen)
            scenario_timings[scen].append(ms)
            current = scen

    return scenario_order, scenario_timings, scenario_errors


def report(scenario_order, timings, errors):
    print(f"{'Scenario':<35} {'n':>5} {'err':>4} {'mean':>8} {'stddev':>7} {'min':>6} {'max':>6} {'95CI_lo':>8} {'95CI_hi':>8}")
    print("-"*100)
    for sc in scenario_order:
        t = timings.get(sc, [])
        e = errors.get(sc, 0)
        if not t:
            print(f"{sc:<35} {'?':>5} {e:>4}  (no data)")
            continue
        n = len(t); m = mean(t); s = stddev(t) if n>1 else 0
        lo, hi = ci95(t) if n>1 else (m, m)
        print(f"{sc:<35} {n:>5} {e:>4} {m:>8.1f} {s:>7.1f} {min(t):>6} {max(t):>6} {lo:>8.1f} {hi:>8.1f}")

    # Summary: unique scenarios with full 100 handshakes
    complete = [s for s in scenario_order if len(timings.get(s,[])) >= 100]
    print(f"\nComplete (≥100): {len(complete)}/78 scenarios  (SPHINCS_FAST L3/L5 excluded: pvPortMalloc limit)")

if __name__ == '__main__':
    ap = argparse.ArgumentParser()
    ap.add_argument('log', nargs='?', default='uart_matrix_v9_1526.log')
    args = ap.parse_args()
    order, timings, errs = parse(args.log)
    report(order, timings, errs)
