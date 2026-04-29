#pragma once

/* DWT-based P256 vs X25519 microbenchmark (keygen + ECDH, N=500).
 * Enable with CMake flag: -DBENCH_MODE_MICROBENCH=ON */
void microbench_run(void);
