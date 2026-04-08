#ifndef CERT_BENCH_H
#define CERT_BENCH_H

#ifdef __cplusplus
extern "C" {
#endif

/* FreeRTOS task entry point for certificate benchmarking.
 * Measures:
 *   1. Cert chain transmission time (TCP receive from desktop cert_data_server)
 *   2. ECDSA signature verification time (P-256 / P-384 / P-521)
 *   3. ML-DSA signature verification time (ML-DSA44 / ML-DSA65 / ML-DSA87)
 *
 * Desktop side: start cert_data_server.py before resetting the board.
 * UART output format:
 *   [certbench] recv  name=ECDSA_L1  size=1251  time=5 ms
 *   [certbench] ecdsa p256  keygen=12 ms  sign=8 ms  verify=9 ms
 *   [certbench] mldsa 44    keygen=340 ms  sign=220 ms  verify=105 ms
 */
void cert_bench_task(void *argument);

#ifdef __cplusplus
}
#endif
#endif /* CERT_BENCH_H */
