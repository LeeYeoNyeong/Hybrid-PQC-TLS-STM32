/**
 * wolfssl_hybrid.c
 *
 * Implementation of wolfSSL_CTX_set_hybrid_cert_type().
 * Requires wolfssl/internal.h for WOLFSSL_CTX struct layout.
 */

#include "wolfssl_hybrid.h"

/* Pull in full WOLFSSL_CTX definition so we can access hybridCertType */
#include <wolfssl/wolfcrypt/settings.h>
#include <wolfssl/internal.h>

void wolfSSL_CTX_set_hybrid_cert_type(WOLFSSL_CTX *ctx, uint8_t type)
{
#ifdef WOLFSSL_HYBRID_CERT
    if (ctx != NULL)
        ctx->hybridCertType = type;
#else
    (void)ctx;
    (void)type;
#endif
}

int wolfSSL_peer_has_related_cert(WOLFSSL *ssl)
{
#ifdef WOLFSSL_HYBRID_CERT
    if (ssl != NULL)
        return ssl->peerHasRelatedCert ? 1 : 0;
#else
    (void)ssl;
#endif
    return 0;
}

int wolfSSL_peer_related_hash_ok(WOLFSSL *ssl)
{
#ifdef WOLFSSL_HYBRID_CERT
    if (ssl != NULL)
        return ssl->peerRelatedHashOk ? 1 : 0;
#else
    (void)ssl;
#endif
    return 0;
}
