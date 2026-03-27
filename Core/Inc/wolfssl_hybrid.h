/**
 * wolfssl_hybrid.h
 *
 * API to configure hybrid (Catalyst / Chameleon) certificate type on a
 * WOLFSSL_CTX before connecting.  Requires WOLFSSL_HYBRID_CERT to be defined
 * in wolfSSL.I-CUBE-wolfSSL_conf.h.
 */

#ifndef WOLFSSL_HYBRID_H
#define WOLFSSL_HYBRID_H

#include <stdint.h>
#include <wolfssl/ssl.h>

/* Values for hybridCertType — match the 0xFF10 extension wire encoding */
#define HYBCERT_NONE       0
#define HYBCERT_CHAMELEON  1
#define HYBCERT_CATALYST   2

/**
 * Set the hybrid certificate type hint sent in the ClientHello 0xFF10
 * extension and stored on ctx for Catalyst/Chameleon scenarios.
 *
 * @param ctx   wolfSSL context (must not be NULL).
 * @param type  HYBCERT_NONE | HYBCERT_CHAMELEON | HYBCERT_CATALYST
 */
void wolfSSL_CTX_set_hybrid_cert_type(WOLFSSL_CTX *ctx, uint8_t type);

#endif /* WOLFSSL_HYBRID_H */
