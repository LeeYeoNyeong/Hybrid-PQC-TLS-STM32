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
