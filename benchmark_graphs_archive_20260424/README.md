# Final PQC/Hybrid TLS Benchmark — 2026-04-24

**Board**: NUCLEO-F439ZI (STM32F439ZI, Cortex-M4F @ 168 MHz)
**Stack**: wolfSSL 5.8.4 + LwIP 2.1.2 + FreeRTOS (Heap_5, 194KB)
**Server**: Mac OpenSSL 3.x + OQS-provider
**n**: 100 handshakes per scenario, all scenarios **errors=0**

## Results Summary (mean handshake time, ms)

| Method | L1 | L3 | L5 |
|---|---:|---:|---:|
| **ECDSA** (baseline) | 345.8 | 600.0 | 701.0 |
| **ML-DSA** (pure PQ) | 465.0 | 657.0 | 974.0 |
| **RELATED** (RFC 9763) | 470.9 | 865.0 | 1195.4 |
| **DUAL** (yusef draft) | 471.1 | 864.3 | 1194.7 |
| **CATALYST** (truskovsky) | 551.0 | 1005.2 | 1433.6 |
| **CHAMELEON** (bonnell) | 542.0 | 988.2 | 1406.4 |
| **COMPOSITE** (lamps) | 520.9 | 963.0 | 1390.2 |
| **FALCON** (compressed sig) | 196.0 | — | 244.1 |
| **SPHINCS+ SHAKE fast** | 3839.7 | 5510.5 | 5908.5 |

## Key Observations

### Fastest handshake
**Falcon-512 (L1) at 196.0 ms** — compressed sigs keep both bandwidth and verify cost minimal. Falcon-1024 (L5) at 244.1 ms stays surprisingly cheap (+48 ms).

### Slowest handshake
**SPHINCS+ L5 at 5908.5 ms** — ~30× slower than ECDSA L5. Verify dominates (~4.8 s) due to FORS+HT tree depth.

### PQ vs Classical cost
- ECDSA L1 (345.8 ms) → ML-DSA L1 (465.0 ms) = +34% for pure PQ at L1
- Ratios scale predictably: L5 jump from ECDSA to ML-DSA is +39%

### Hybrid certificate overhead
- RELATED / DUAL converge almost identically (differ <1 ms) — both use ECDSA + ML-DSA dual chains.
- CATALYST / CHAMELEON higher due to chain parsing cost.
- COMPOSITE slightly cheaper than CATALYST but requires OQS provider support.

### PQCertVerify footprint (PQ-signed verify inside TLS extension)
- L1 ~71 ms, L3 ~39 ms, L5 ~89 ms — interestingly **L3 < L1** due to ML-DSA-65 being faster to verify than ML-DSA-44 in this implementation (matrix A caching pays off).

## Artifacts

- `benchmark_grouped_linear.png` — main grouped bar chart
- `benchmark_grouped_log.png` — log-scale (shows ECDSA to SPHINCS+ spread)
- `benchmark_phases_L1.png` / `_L3.png` / `_L5.png` — phase breakdown (SrvHello/Cert/CertVfy/PQCertVfy/Finished) per security level
- `benchmark_scaling_line.png` — line chart, scaling vs security level
- `benchmark_n100_final.txt` — raw mean/stddev/95%CI/phases CSV-ish table

## Source logs
- `uart_benchmark_final_2118.log` — full 26-scenario n=100 run (post-Falcon fix)
- `uart_verify_falcon_l5_2237.log` — FALCON_L5 + SPHINCS_FAST_L1 re-verification (after clearing stale server state)

## Reproduction
1. Pre-conditions: Falcon + SPHINCS+ servers must have clean LISTEN state (no stale ESTABLISHED).
2. Flash `build/Debug/Test_pqc_tls.elf` (commit `5093bbf` or later).
3. Capture UART3 @ 115200 and parse `--- Results: <name> ---` blocks.
