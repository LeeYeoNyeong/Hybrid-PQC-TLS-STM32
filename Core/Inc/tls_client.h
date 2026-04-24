#ifndef TLS_CLIENT_H
#define TLS_CLIENT_H

#ifdef __cplusplus
extern "C" {
#endif

/* ── Server configuration ── */
#define TLS_SERVER_IP    "192.168.0.27"
#define TLS_SERVER_PORT  11111

/* ── Measurement configuration ── */
#define TLS_REPEAT_COUNT  100

/* ── Scenario definitions ── */
typedef enum {
    CERT_ECDSA        = 0,
    CERT_MLDSA        = 1,
    CERT_COMPOSITE    = 2,
    CERT_CHAMELEON    = 3,
    CERT_CATALYST     = 4,
    CERT_RELATED      = 5,
    CERT_DUAL         = 6,
    CERT_FALCON       = 7,   /* Falcon-512 (L1) / Falcon-1024 (L5) */
    CERT_SPHINCS_FAST  = 8,  /* SPHINCS+-SHAKE-fast (L1=128f) */
    CERT_SPHINCS_SMALL = 9,  /* SPHINCS+-SHAKE-small: 128s(L1) 192s(L3) 256s(L5) */
    CERT_TYPE_COUNT
} CertType;

typedef enum {
    SEC_LEVEL_1 = 1,
    SEC_LEVEL_3 = 3,
    SEC_LEVEL_5 = 5,
} SecurityLevel;

/* FreeRTOS task entry point */
void tls_perf_task(void *argument);

/* For cert_bench: returns root CA PEM(s) for a named scenario */
void tls_get_scenario_ca(const char *name,
                          const char **ca,     unsigned int *ca_sz,
                          const char **ca_alt, unsigned int *ca_alt_sz);

#ifdef __cplusplus
}
#endif
#endif /* TLS_CLIENT_H */
