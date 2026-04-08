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

/**
 * Returns 1 if the peer's PQ chain leaf cert contained a RelatedCertificate
 * extension (OID 1.3.6.1.5.5.7.1.36), detected by ProcessPeerCerts during
 * dual-chain parsing.  Returns 0 otherwise.
 */
int wolfSSL_peer_has_related_cert(WOLFSSL *ssl);

/**
 * Returns 1 if the RelatedCertificate hash binding has been verified:
 * the hash stored in the PQ leaf cert's RelatedCertificate extension
 * matches the computed hash of the primary (ECDSA) leaf cert.
 * Returns 0 if the extension was not found, hashes do not match,
 * or an error occurred during parsing.
 */
int wolfSSL_peer_related_hash_ok(WOLFSSL *ssl);

#endif /* WOLFSSL_HYBRID_H */
