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
    CERT_ECDSA      = 0,
    CERT_MLDSA      = 1,
    CERT_COMPOSITE  = 2,
    CERT_CHAMELEON  = 3,
    CERT_CATALYST   = 4,
    CERT_RELATED    = 5,
    CERT_DUAL       = 6,
    CERT_TYPE_COUNT
} CertType;

typedef enum {
    SEC_LEVEL_1 = 1,
    SEC_LEVEL_3 = 3,
    SEC_LEVEL_5 = 5,
} SecurityLevel;

/* FreeRTOS task entry point */
void tls_perf_task(void *argument);

#ifdef __cplusplus
}
#endif
#endif /* TLS_CLIENT_H */
