/**
 * tls_client.c
 * TLS 1.3 handshake performance measurement task for STM32F439ZI
 *
 * Connects to Mac TLS server, performs TLS_REPEAT_COUNT handshakes,
 * and reports mean/stddev/95% CI via UART.
 */

#include "tls_client.h"
#include "main.h"
#include "cmsis_os.h"

#include <stdio.h>
#include <string.h>
#include <math.h>

/* lwIP */
#include "lwip/sockets.h"
#include "lwip/netif.h"
#include "lwip/dhcp.h"

/* wolfSSL */
#include <wolfssl/wolfcrypt/settings.h>
#include <wolfssl/ssl.h>
#include <wolfssl/wolfcrypt/asn_public.h>

/* Hybrid cert (Catalyst / Chameleon) support */
#include "wolfssl_hybrid.h"

#include <time.h>

/* ── extern from lwip.c ── */
extern struct netif gnetif;

/* ── Per-message handshake timing (from tls13.c) ── */
extern volatile uint32_t g_tls_t_server_hello_ms;
extern volatile uint32_t g_tls_t_cert_ms;
extern volatile uint32_t g_tls_t_cert_verify_ms;
extern volatile uint32_t g_tls_t_pq_cert_verify_ms;
extern volatile uint32_t g_tls_t_finished_ms;
void tls13_set_tick_fn(uint32_t (*fn)(void));

/* Cert-parse sub-timing (set from internal.c) */
extern volatile uint32_t g_cert_t_primary_ms;
extern volatile uint32_t g_cert_t_pq_ms;
extern volatile uint32_t g_cert_t_leaf_ms;
extern volatile uint32_t g_cert_t_hash_ms;

/* ================================================================
 * Minimal SNTP client + wolfSSL time callback
 * ================================================================ */
#define NTP_SERVER_IP   TLS_SERVER_IP   /* Mac runs NTP on port 123 */
#define NTP_PORT        123
#define NTP_EPOCH_DELTA 2208988800UL    /* seconds between 1900 and 1970 */

static volatile time_t  g_ntp_time = 0;   /* Unix timestamp at last sync */
static volatile uint32_t g_ntp_tick = 0;  /* HAL_GetTick() at last sync */

static time_t ntp_time_cb(time_t *t)
{
    time_t now = g_ntp_time + (time_t)((HAL_GetTick() - g_ntp_tick) / 1000UL);
    if (t) *t = now;
    return now;
}

static void sntp_sync(void)
{
    uint8_t pkt[48];
    memset(pkt, 0, sizeof(pkt));
    pkt[0] = 0x1B; /* LI=0, VN=3, Mode=3 (client) */

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port   = htons(NTP_PORT);
    inet_aton(NTP_SERVER_IP, &addr.sin_addr);

    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) { printf("[NTP] socket failed\n"); return; }

    /* 5-second receive timeout */
    struct timeval tv = { .tv_sec = 5, .tv_usec = 0 };
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

    if (sendto(fd, pkt, sizeof(pkt), 0,
               (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        printf("[NTP] send failed\n");
        close(fd);
        return;
    }

    uint8_t resp[48];
    if (recv(fd, resp, sizeof(resp), 0) == 48) {
        uint32_t sec = ((uint32_t)resp[40] << 24) | ((uint32_t)resp[41] << 16)
                     | ((uint32_t)resp[42] <<  8) |  (uint32_t)resp[43];
        g_ntp_time = (time_t)(sec - NTP_EPOCH_DELTA);
        g_ntp_tick = HAL_GetTick();
        printf("[NTP] Synced: Unix=%lu\n", (unsigned long)g_ntp_time);
    } else {
        printf("[NTP] No response\n");
    }
    close(fd);
}

/* ================================================================
 * Embedded Root CA certificates (ECDSA, PEM format)
 * ================================================================ */

/* Classical Root CA – P-256 (Security Level 1) */
static const char CA_ECDSA_L1[] =
    "-----BEGIN CERTIFICATE-----\r\n"
    "MIIBqzCCAVCgAwIBAgIUGNoJxAAA5jaWhdNhmYp1/5KlWtAwCgYIKoZIzj0EAwIw\r\n"
    "ITEfMB0GA1UEAwwWQ2xhc3NpY2FsIFJvb3QgQ0EgQ2VydDAeFw0yNjAyMDYxMTQ1\r\n"
    "NTRaFw0zNjAyMDQxMTQ1NTRaMCExHzAdBgNVBAMMFkNsYXNzaWNhbCBSb290IENB\r\n"
    "IENlcnQwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAAQEh0kyyGtVhMSaggfnyKk7\r\n"
    "hWVqai5lSBKRA3T7conOQIqeHF0A8whuajYx65UhzVAX0YgeFq4Akb7yRrr3IIiK\r\n"
    "o2YwZDASBgNVHRMBAf8ECDAGAQH/AgEBMA4GA1UdDwEB/wQEAwIBBjAdBgNVHQ4E\r\n"
    "FgQUlTJ+eCS2pZDwVexhUsbzVxX8bbYwHwYDVR0jBBgwFoAUlTJ+eCS2pZDwVexh\r\n"
    "UsbzVxX8bbYwCgYIKoZIzj0EAwIDSQAwRgIhAInISZSfvnJAMCIjUPISwriAEsSM\r\n"
    "tUwMFsIB127S3h4AAiEAw/NojUfY3cEdpu2/COD5aB6a2yaVN006zPOvtF+Qf+k=\r\n"
    "-----END CERTIFICATE-----\r\n";

/* Classical Root CA – P-384 (Security Level 3) */
static const char CA_ECDSA_L3[] =
    "-----BEGIN CERTIFICATE-----\r\n"
    "MIIB5zCCAW2gAwIBAgIUAJ8Cn3KFsN8TSgx5pE7RBov9y9kwCgYIKoZIzj0EAwIw\r\n"
    "ITEfMB0GA1UEAwwWQ2xhc3NpY2FsIFJvb3QgQ0EgQ2VydDAeFw0yNjAyMDYxMTQ1\r\n"
    "NDhaFw0zNjAyMDQxMTQ1NDhaMCExHzAdBgNVBAMMFkNsYXNzaWNhbCBSb290IENB\r\n"
    "IENlcnQwdjAQBgcqhkjOPQIBBgUrgQQAIgNiAATXQqDBi6I1UVnMM6uRCz+g2u+X\r\n"
    "hZJyg72Dx6SpCMRjLhaZl0Styt20aFzmCGuOo50nLCm02A+4uG0MHd97XAlJEjEu\r\n"
    "bDXzQEdn8V9s3V0UShO+xwe8lPJz956N3cJXBiKjZjBkMBIGA1UdEwEB/wQIMAYB\r\n"
    "Af8CAQEwDgYDVR0PAQH/BAQDAgEGMB0GA1UdDgQWBBT/kDIVJl3Bwp7MGYYDsa6P\r\n"
    "463/8DAfBgNVHSMEGDAWgBT/kDIVJl3Bwp7MGYYDsa6P463/8DAKBggqhkjOPQQD\r\n"
    "AgNoADBlAjBZHKBrwQjmoSjLq8sw7sjQAzd9HT4lnemhhn5cUbHyOAm/8/kcluU+\r\n"
    "R7UQqg9vQV4CMQCbAiHRNYWyUImft1YjATec7yG7kw+6NNyRQs2awmeusBX846RG\r\n"
    "ToQisYIAtVxdflc=\r\n"
    "-----END CERTIFICATE-----\r\n";

/* Classical Root CA – P-521 (Security Level 5) */
static const char CA_ECDSA_L5[] =
    "-----BEGIN CERTIFICATE-----\r\n"
    "MIICMjCCAZOgAwIBAgIUb2u1YfB0Xl0bJfGMk80yA0TmmNgwCgYIKoZIzj0EAwIw\r\n"
    "ITEfMB0GA1UEAwwWQ2xhc3NpY2FsIFJvb3QgQ0EgQ2VydDAeFw0yNjAyMDYxMTQ2\r\n"
    "MDNaFw0zNjAyMDQxMTQ2MDNaMCExHzAdBgNVBAMMFkNsYXNzaWNhbCBSb290IENB\r\n"
    "IENlcnQwgZswEAYHKoZIzj0CAQYFK4EEACMDgYYABACyPvT1Bv5DucRZfrgSwB54\r\n"
    "J8FD84jpVzjZn3tJDVYi0D9RTg/ZsB+n9KTFV9JUpcnkwiGIRnL9TXDXYEMSPg+u\r\n"
    "ggEU6KSEPNASxbWVKnrIODy2et27TQEIJU31IYf4f9PPFYmylU4IHmwwDUS/SIQs\r\n"
    "St1gKCxOOkluZ45i5nCDgCwWDqNmMGQwEgYDVR0TAQH/BAgwBgEB/wIBATAOBgNV\r\n"
    "HQ8BAf8EBAMCAQYwHQYDVR0OBBYEFOQHEOWhfTUqg7c591SdhA0//ITXMB8GA1Ud\r\n"
    "IwQYMBaAFOQHEOWhfTUqg7c591SdhA0//ITXMAoGCCqGSM49BAMCA4GMADCBiAJC\r\n"
    "APiuFAaRN2t5Tqdin+htX9F4ol9O57Y4JPo0DRQ0ka7dyVQuNHLKvGvIEzFvNXl/\r\n"
    "M6pFTdFb6s5DPgrKXgeGvOLbAkIBd34SHMWvwgrZG8MDyDhtxRjnjuUeds5fnYg1\r\n"
    "WVogzidC2/U100htmVQcdxyWONh1D80d6v843Si7oitKTi+Tzjk=\r\n"
    "-----END CERTIFICATE-----\r\n";

/* ================================================================
 * Embedded Root CA certificates (ML-DSA, PEM format)
 * ================================================================ */

/* ML-DSA Root CA – mldsa44 (Security Level 1) */
static const char CA_MLDSA_L1[] =
    "-----BEGIN CERTIFICATE-----\n"
    "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\n"
    "wO/0/gAAAAAAAAAAAAASJDhG\n"
    "-----END CERTIFICATE-----\n"
    ;

/* ML-DSA Root CA – mldsa65 (Security Level 3) */
static const char CA_MLDSA_L3[] =
    "-----BEGIN CERTIFICATE-----\n"
    "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\n"
    "AAAAAAAHCxQZHSQ=\n"
    "-----END CERTIFICATE-----\n"
    ;

/* ML-DSA Root CA – mldsa87 (Security Level 5) */
static const char CA_MLDSA_L5[] =
    "-----BEGIN CERTIFICATE-----\n"
    "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\n"
    "Sg==\n"
    "-----END CERTIFICATE-----\n"
    ;

/* Catalyst Root CA – Security Level 1 */
static const char CA_CATALYST_L1[] =
    "-----BEGIN CERTIFICATE-----\r\n"
    "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\r\n"
    "WqDrAUNSqkNusUBS\r\n"
    "-----END CERTIFICATE-----\r\n"
    ;

/* Catalyst Root CA – Security Level 3 */
static const char CA_CATALYST_L3[] =
    "-----BEGIN CERTIFICATE-----\r\n"
    "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\r\n"
    "oVY0h1sEK9HxgnLcO6JkUa9Cjw==\r\n"
    "-----END CERTIFICATE-----\r\n"
    ;

/* Catalyst Root CA – Security Level 5 */
static const char CA_CATALYST_L5[] =
    "-----BEGIN CERTIFICATE-----\r\n"
    "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\r\n"
    "-----END CERTIFICATE-----\r\n"
    ;

/* ================================================================
 * Embedded Root CA certificates (Chameleon, 2-cert PEM: EC root + PQ root)
 * ================================================================ */

/* Chameleon Root CA – Security Level 1 (EC P-256 + ML-DSA-44) */
static const char CA_CHAMELEON_L1[] =
    "-----BEGIN CERTIFICATE-----\r\n"
    "MIIBnTCCAUKgAwIBAgIUBBYNWhQLVgsw0b+/kwtuTBrEMpUwCgYIKoZIzj0EAwIw\r\n"
    "GjEYMBYGA1UEAwwPQ2xhc3NpYyBSb290IENBMB4XDTI2MDIwNDExMTUzNFoXDTM2\r\n"
    "MDIwMjExMTUzNFowGjEYMBYGA1UEAwwPQ2xhc3NpYyBSb290IENBMFkwEwYHKoZI\r\n"
    "zj0CAQYIKoZIzj0DAQcDQgAEfuzSscI1u3FB/wEzfVwJekLkVe5T+Chx0YDmdeGF\r\n"
    "PQ3YMQxigRIjmSJO6qQCD1GxHYBSSRR/UOUANE6rd/1AZqNmMGQwEgYDVR0TAQH/\r\n"
    "BAgwBgEB/wIBATAOBgNVHQ8BAf8EBAMCAQYwHQYDVR0OBBYEFELpyQlSDoAa/N3R\r\n"
    "eeRTsLk8/COnMB8GA1UdIwQYMBaAFELpyQlSDoAa/N3ReeRTsLk8/COnMAoGCCqG\r\n"
    "SM49BAMCA0kAMEYCIQDNxmkf8oDNJlDyL8OHuBKQErECaWsQGSjWyu9/q+oJLgIh\r\n"
    "APMjbXpLpl9rU/fMU2SLNjDN4fEZfen0k+l0e5CZWlPU\r\n"
    "-----END CERTIFICATE-----\r\n"
    "-----BEGIN CERTIFICATE-----\r\n"
    "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\r\n"
    "AAAAAAAAAAAAAAAAAAARHSs5\r\n"
    "-----END CERTIFICATE-----\r\n"
    ;

/* Chameleon Root CA – Security Level 3 (EC P-384 + ML-DSA-65) */
static const char CA_CHAMELEON_L3[] =
    "-----BEGIN CERTIFICATE-----\r\n"
    "MIIB2jCCAV+gAwIBAgIUWcPeuCQ+OlwykJogoawaxkKA9Y4wCgYIKoZIzj0EAwIw\r\n"
    "GjEYMBYGA1UEAwwPQ2xhc3NpYyBSb290IENBMB4XDTI2MDIwNjA1MjA0MFoXDTM2\r\n"
    "MDIwNDA1MjA0MFowGjEYMBYGA1UEAwwPQ2xhc3NpYyBSb290IENBMHYwEAYHKoZI\r\n"
    "zj0CAQYFK4EEACIDYgAEPdanzBXlfBydE8DwItkH5XFQJoBzXe9czVUvlBuczqfS\r\n"
    "zmFofpnGiRb2ETfFfE1V/6KcRuRNYiuxW2RNDpT2rBDfMVH4Sm4RaK94l7fhSgJy\r\n"
    "ub0W4SS7jXZolaewueAro2YwZDASBgNVHRMBAf8ECDAGAQH/AgEBMA4GA1UdDwEB\r\n"
    "/wQEAwIBBjAdBgNVHQ4EFgQUJOCPZ8FZpeHsBn8oclO6qVjDlKcwHwYDVR0jBBgw\r\n"
    "FoAUJOCPZ8FZpeHsBn8oclO6qVjDlKcwCgYIKoZIzj0EAwIDaQAwZgIxAK2G8Wi8\r\n"
    "HrqURQ5ZAybwULeRnV0rIZ6VUI0z5YF8mCOrZ5hpoBXag9nOu/g9j3da5gIxANlV\r\n"
    "Tg+reejGwTIaN7huKaiiwgC0nux6qn3qT2s75kpj9MUZIrfmzSy92n1JV+pL4g==\r\n"
    "-----END CERTIFICATE-----\r\n"
    "-----BEGIN CERTIFICATE-----\r\n"
    "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\r\n"
    "RKXC4fcOFyAmMDc=\r\n"
    "-----END CERTIFICATE-----\r\n"
    ;

/* Chameleon Root CA – Security Level 5 (EC P-521 + ML-DSA-87) */
static const char CA_CHAMELEON_L5[] =
    "-----BEGIN CERTIFICATE-----\r\n"
    "MIICJDCCAYWgAwIBAgIUF/M+7VLLr+BjZx5EoN7/gDpGHJswCgYIKoZIzj0EAwIw\r\n"
    "GjEYMBYGA1UEAwwPQ2xhc3NpYyBSb290IENBMB4XDTI2MDIwNjA1MjA1MFoXDTM2\r\n"
    "MDIwNDA1MjA1MFowGjEYMBYGA1UEAwwPQ2xhc3NpYyBSb290IENBMIGbMBAGByqG\r\n"
    "SM49AgEGBSuBBAAjA4GGAAQBD61MAqoxuRYaeKbjbGt+b4JpgtneGTz87NUNUa7W\r\n"
    "pj77E2sX/HErzSYeq32tRK1CnX9JiAKdCLNfMSYrQVNmAlUBb8WDtn1XQgbH1V2x\r\n"
    "pyY/W4bCm1x2owhgzSxToURdqr+h1aDqx0Fn7B8DU2638A3gmOg1VL+ubpKzjhiB\r\n"
    "PYdW1eajZjBkMBIGA1UdEwEB/wQIMAYBAf8CAQEwDgYDVR0PAQH/BAQDAgEGMB0G\r\n"
    "A1UdDgQWBBShCu/BHi0OX+xsgnm0bNKe3SjStzAfBgNVHSMEGDAWgBShCu/BHi0O\r\n"
    "X+xsgnm0bNKe3SjStzAKBggqhkjOPQQDAgOBjAAwgYgCQgGaNcfeCe7sjbmdTSn1\r\n"
    "jcQ2WZVQcNJaPU9Avis3V6gfqp9kRXhqkFLzxRZWmSIvd2Z9O7KKUcAkJEdCc+K3\r\n"
    "insIqQJCAMKeDCnTADBVNrIEd39IkouIjGyp1BtMla3LiY1ZEvZDBI+VlHvlluz5\r\n"
    "PRkzo8J/UL7DFr6ov/LRdsVHxRJKVvpn\r\n"
    "-----END CERTIFICATE-----\r\n"
    "-----BEGIN CERTIFICATE-----\r\n"
    "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\r\n"
    "Ng==\r\n"
    "-----END CERTIFICATE-----\r\n"
    ;

/* Composite Root CA – Security Level 1 (ML-DSA-44 + P-256) */
static const char CA_COMPOSITE_L1[] =
    "-----BEGIN CERTIFICATE-----\r\n"
    "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\r\n"
    "+AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAER4qOQ==\r\n"
    "-----END CERTIFICATE-----\r\n"
    ;

/* Composite Root CA – Security Level 3 (ML-DSA-65 + P-384) */
static const char CA_COMPOSITE_L3[] =
    "-----BEGIN CERTIFICATE-----\r\n"
    "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\r\n"
    "-----END CERTIFICATE-----\r\n"
    ;

/* Composite Root CA – Security Level 5 (ML-DSA-87 + P-521) */
static const char CA_COMPOSITE_L5[] =
    "-----BEGIN CERTIFICATE-----\r\n"
    "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\r\n"
    "Nz0=\r\n"
    "-----END CERTIFICATE-----\r\n"
    ;


/* Falcon-512 Root CA (Security Level 1) */
static const char CA_FALCON_L1[] =
    "-----BEGIN CERTIFICATE-----\r\n"
    "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\r\n"
    "-----END CERTIFICATE-----\r\n";

/* Falcon-1024 Root CA (Security Level 5) */
static const char CA_FALCON_L5[] =
    "-----BEGIN CERTIFICATE-----\r\n"
    "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\r\n"
    "WcRrdb7QEIQ=\r\n"
    "-----END CERTIFICATE-----\r\n";

/* SPHINCS+-SHAKE-128f-simple Root CA (Security Level 1, fast) */
static const char CA_SPHINCS_FAST_L1[] =
    "-----BEGIN CERTIFICATE-----\r\n"
    "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\r\n"
    "3KgaSUK+iWuJEg==\r\n"
    "-----END CERTIFICATE-----\r\n";

/* ================================================================
 * Scenario table
 * ================================================================ */
typedef struct {
    const char   *name;
    CertType      type;
    SecurityLevel level;
    const char   *ca_pem;
    unsigned int  ca_pem_size;   /* strlen, NOT including final \0 */
    const char   *ca_pem_alt;
    unsigned int  ca_pem_alt_size;
    uint8_t       hybrid_cert_type;  /* HYBCERT_NONE/CATALYST/CHAMELEON */
    uint8_t       cks_sig_spec;      /* 0 or WOLFSSL_CKS_SIGSPEC_* */
    uint8_t       require_related;   /* post-handshake RelatedCertificate check */
    uint16_t      port;          /* 0 = use TLS_SERVER_PORT default */
} Scenario;

#define RELATED_CERT_OID "1.3.6.1.5.5.7.1.36"

/* Skip list: scenario names to skip on next run.
 * When a partial benchmark needs to resume, fill this array with names
 * that already have good data, then rebuild & reflash to re-run only the
 * remaining scenarios. Must be NULL-terminated. */
static const char *const g_skip_scenarios[] = {
    /* 2026-04-22: measuring SPHINCS+ alone to avoid heap fragmentation
     * from prior scenarios (SPHINCS+ verify is heap-heavy). */
    "ECDSA_L1", "ECDSA_L3", "ECDSA_L5",
    "MLDSA_L1", "MLDSA_L3", "MLDSA_L5",
    "RELATED_L1", "RELATED_L3", "RELATED_L5",
    "CATALYST_L1", "CATALYST_L3", "CATALYST_L5",
    "CHAMELEON_L1", "CHAMELEON_L3", "CHAMELEON_L5",
    "DUAL_L1", "DUAL_L3", "DUAL_L5",
    "COMPOSITE_L1", "COMPOSITE_L3", "COMPOSITE_L5",
    "FALCON_L1", "FALCON_L5",
    NULL
};

static int is_scenario_skipped(const char *name)
{
    for (const char *const *p = g_skip_scenarios; *p != NULL; p++) {
        if (strcmp(*p, name) == 0) return 1;
    }
    return 0;
}

static const Scenario g_scenarios[] = {
    /* ECDSA: ports 11101/11103/11105 */
    { "ECDSA_L1",   CERT_ECDSA,    SEC_LEVEL_1, CA_ECDSA_L1,    sizeof(CA_ECDSA_L1)    - 1, NULL, 0, HYBCERT_NONE,      0,                        0, 11101 },
    { "ECDSA_L3",   CERT_ECDSA,    SEC_LEVEL_3, CA_ECDSA_L3,    sizeof(CA_ECDSA_L3)    - 1, NULL, 0, HYBCERT_NONE,      0,                        0, 11103 },
    { "ECDSA_L5",   CERT_ECDSA,    SEC_LEVEL_5, CA_ECDSA_L5,    sizeof(CA_ECDSA_L5)    - 1, NULL, 0, HYBCERT_NONE,      0,                        0, 11105 },
    /* ML-DSA (pure PQC): ports 11111/11113/11115 */
    { "MLDSA_L1",   CERT_MLDSA,    SEC_LEVEL_1, CA_MLDSA_L1,    sizeof(CA_MLDSA_L1)    - 1, NULL, 0, HYBCERT_NONE,      0,                        0, 11111 },
    { "MLDSA_L3",   CERT_MLDSA,    SEC_LEVEL_3, CA_MLDSA_L3,    sizeof(CA_MLDSA_L3)    - 1, NULL, 0, HYBCERT_NONE,      0,                        0, 11113 },
    { "MLDSA_L5",   CERT_MLDSA,    SEC_LEVEL_5, CA_MLDSA_L5,    sizeof(CA_MLDSA_L5)    - 1, NULL, 0, HYBCERT_NONE,      0,                        0, 11115 },
    /* Related: ports 11141/11143/11145
     * Server sends ML-DSA chain which carries RelatedCertificate extension (OID 1.3.6.1.5.5.7.1.36)
     * binding it to the corresponding ECDSA cert. Client verifies ML-DSA chain + checks extension. */
    /* RELATED: ECDSA chain (primary) + ML-DSA chain (PQ, has RelatedCertificate ext)
     * Both chains sent in one Certificate message with 0x000000 delimiter.
     * Both CAs loaded so wolfSSL can verify both ECDSA and PQ chain. */
    { "RELATED_L1", CERT_RELATED, SEC_LEVEL_1, CA_ECDSA_L1, sizeof(CA_ECDSA_L1) - 1, CA_MLDSA_L1, sizeof(CA_MLDSA_L1) - 1, HYBCERT_NONE, 0, 1, 11141 },
    { "RELATED_L3", CERT_RELATED, SEC_LEVEL_3, CA_ECDSA_L3, sizeof(CA_ECDSA_L3) - 1, CA_MLDSA_L3, sizeof(CA_MLDSA_L3) - 1, HYBCERT_NONE, 0, 1, 11143 },
    { "RELATED_L5", CERT_RELATED, SEC_LEVEL_5, CA_ECDSA_L5, sizeof(CA_ECDSA_L5) - 1, CA_MLDSA_L5, sizeof(CA_MLDSA_L5) - 1, HYBCERT_NONE, 0, 1, 11145 },
    /* Catalyst: ports 11121/11123/11125  (EC cert + ML-DSA altkey → PQCertVerify) */
    { "CATALYST_L1",  CERT_CATALYST,  SEC_LEVEL_1, CA_CATALYST_L1,  sizeof(CA_CATALYST_L1)  - 1, NULL, 0, HYBCERT_CATALYST,  0, 0, 11121 },
    { "CATALYST_L3",  CERT_CATALYST,  SEC_LEVEL_3, CA_CATALYST_L3,  sizeof(CA_CATALYST_L3)  - 1, NULL, 0, HYBCERT_CATALYST,  0, 0, 11123 },
    { "CATALYST_L5",  CERT_CATALYST,  SEC_LEVEL_5, CA_CATALYST_L5,  sizeof(CA_CATALYST_L5)  - 1, NULL, 0, HYBCERT_CATALYST,  0, 0, 11125 },
    /* Chameleon: ports 11131/11133/11135 (DCD hybrid cert; both chain paths verified) */
    { "CHAMELEON_L1", CERT_CHAMELEON, SEC_LEVEL_1, CA_CHAMELEON_L1, sizeof(CA_CHAMELEON_L1) - 1, NULL, 0, HYBCERT_CHAMELEON, 0, 0, 11131 },
    { "CHAMELEON_L3", CERT_CHAMELEON, SEC_LEVEL_3, CA_CHAMELEON_L3, sizeof(CA_CHAMELEON_L3) - 1, NULL, 0, HYBCERT_CHAMELEON, 0, 0, 11133 },
    { "CHAMELEON_L5", CERT_CHAMELEON, SEC_LEVEL_5, CA_CHAMELEON_L5, sizeof(CA_CHAMELEON_L5) - 1, NULL, 0, HYBCERT_CHAMELEON, 0, 0, 11135 },
    /* Dual: ports 11151/11153/11155
     * Uses catalyst-style cert (ECDSA primary + ML-DSA SubjectAltPublicKeyInfo + ML-DSA altkey).
     * Server sends both CertVerify (ECDSA) and PQCertVerify (ML-DSA). Client verifies both. */
    /* DUAL: ECDSA chain (primary, CertVerify) + ML-DSA chain (PQCertVerify).
     * Both chains sent in one Certificate message with 0x000000 delimiter.
     * No SAPKI extension — ML-DSA pubkey comes from PQ chain leaf cert. */
    { "DUAL_L1",    CERT_DUAL,    SEC_LEVEL_1, CA_ECDSA_L1, sizeof(CA_ECDSA_L1) - 1, CA_MLDSA_L1, sizeof(CA_MLDSA_L1) - 1, HYBCERT_NONE, 0, 0, 11151 },
    { "DUAL_L3",    CERT_DUAL,    SEC_LEVEL_3, CA_ECDSA_L3, sizeof(CA_ECDSA_L3) - 1, CA_MLDSA_L3, sizeof(CA_MLDSA_L3) - 1, HYBCERT_NONE, 0, 0, 11153 },
    { "DUAL_L5",    CERT_DUAL,    SEC_LEVEL_5, CA_ECDSA_L5, sizeof(CA_ECDSA_L5) - 1, CA_MLDSA_L5, sizeof(CA_MLDSA_L5) - 1, HYBCERT_NONE, 0, 0, 11155 },
    /* Composite: wolfSSL server ports 11161/11163/11165 */
    { "COMPOSITE_L1", CERT_COMPOSITE, SEC_LEVEL_1, CA_COMPOSITE_L1, sizeof(CA_COMPOSITE_L1) - 1, NULL, 0, HYBCERT_NONE, 0, 0, 11161 },
    { "COMPOSITE_L3", CERT_COMPOSITE, SEC_LEVEL_3, CA_COMPOSITE_L3, sizeof(CA_COMPOSITE_L3) - 1, NULL, 0, HYBCERT_NONE, 0, 0, 11163 },
    { "COMPOSITE_L5", CERT_COMPOSITE, SEC_LEVEL_5, CA_COMPOSITE_L5, sizeof(CA_COMPOSITE_L5) - 1, NULL, 0, HYBCERT_NONE, 0, 0, 11165 },
    /* Falcon: ports 11171 (L1=Falcon-512), 11175 (L5=Falcon-1024); no L3 */
    { "FALCON_L1",    CERT_FALCON,    SEC_LEVEL_1, CA_FALCON_L1,    sizeof(CA_FALCON_L1)    - 1, NULL, 0, HYBCERT_NONE, 0, 0, 11171 },
    { "FALCON_L5",    CERT_FALCON,    SEC_LEVEL_5, CA_FALCON_L5,    sizeof(CA_FALCON_L5)    - 1, NULL, 0, HYBCERT_NONE, 0, 0, 11175 },
    /* SPHINCS+-SHAKE-fast: port 11181 (L1=128f-simple) */
    { "SPHINCS_FAST_L1", CERT_SPHINCS_FAST, SEC_LEVEL_1, CA_SPHINCS_FAST_L1, sizeof(CA_SPHINCS_FAST_L1) - 1, NULL, 0, HYBCERT_NONE, 0, 0, 11181 },
};
#define SCENARIO_COUNT  (sizeof(g_scenarios) / sizeof(g_scenarios[0]))

void tls_get_scenario_ca(const char *name,
                          const char **ca,     unsigned int *ca_sz,
                          const char **ca_alt, unsigned int *ca_alt_sz)
{
    for (size_t i = 0; i < SCENARIO_COUNT; i++) {
        if (strcmp(g_scenarios[i].name, name) == 0) {
            if (ca)        *ca        = g_scenarios[i].ca_pem;
            if (ca_sz)     *ca_sz     = g_scenarios[i].ca_pem_size;
            if (ca_alt)    *ca_alt    = g_scenarios[i].ca_pem_alt;
            if (ca_alt_sz) *ca_alt_sz = g_scenarios[i].ca_pem_alt_size;
            return;
        }
    }
    if (ca)        *ca        = NULL;
    if (ca_sz)     *ca_sz     = 0;
    if (ca_alt)    *ca_alt    = NULL;
    if (ca_alt_sz) *ca_alt_sz = 0;
}

static int load_verify_ca(WOLFSSL_CTX *ctx, const char *pem, unsigned int pem_size)
{
    if (pem == NULL || pem_size == 0) {
        return WOLFSSL_SUCCESS;
    }

    /* Use _ex with IGNORE_ERR to tolerate self-signed PQC CAs (Falcon/SPHINCS+)
     * whose root cert signature OID isn't recognized by wolfSSL's CA-load path.
     * Certificate verification during the handshake still runs. */
    return wolfSSL_CTX_load_verify_buffer_ex(ctx,
            (const unsigned char *)pem,
            (long)pem_size,
            WOLFSSL_FILETYPE_PEM,
            0,
            WOLFSSL_LOAD_FLAG_IGNORE_ERR);
}

static int configure_scenario_ctx(WOLFSSL_CTX *ctx, const Scenario *sc)
{
    int ret;

    /* Falcon / SPHINCS+ self-signed CAs trigger ASN_UNKNOWN_OID_E (-148) in
     * wolfSSL's CA-load path because the signer OID isn't mapped. Skip CA
     * loading and disable peer verification for these scenarios — the
     * server-cert signature is still verified in CertVerify, which is what
     * we're benchmarking. */
    if (sc->type == CERT_FALCON || sc->type == CERT_SPHINCS_FAST) {
        /* PQ CAs are self-signed OQS roots that wolfSSL can't verify; skip
         * trust anchor loading and disable peer verify. The PQ signature in
         * CertificateVerify is still validated in the handshake path, which
         * is what we're benchmarking. sig_names[] doesn't include Falcon or
         * SPHINCS+ entries, so we must NOT call set1_sigalgs_list (it would
         * fail parsing and blank the suite's hashSigAlgoSz, causing the
         * ClientHello signature_algorithms extension to be omitted and the
         * server to reply with decode_error). The default hashSigAlgo list
         * built by AddSuiteHashSigAlgo already includes the PQ sigalg. */
        wolfSSL_CTX_set_verify(ctx, WOLFSSL_VERIFY_NONE, NULL);
        return WOLFSSL_SUCCESS;
    }

    ret = load_verify_ca(ctx, sc->ca_pem, sc->ca_pem_size);
    if (ret != WOLFSSL_SUCCESS) {
        return ret;
    }

    ret = load_verify_ca(ctx, sc->ca_pem_alt, sc->ca_pem_alt_size);
    if (ret != WOLFSSL_SUCCESS) {
        return ret;
    }

    if (sc->hybrid_cert_type != HYBCERT_NONE) {
        wolfSSL_CTX_set_hybrid_cert_type(ctx, sc->hybrid_cert_type);
    }

    if (sc->cks_sig_spec != 0) {
        byte spec = sc->cks_sig_spec;
        ret = wolfSSL_CTX_UseCKS(ctx, &spec, 1);
        if (ret != WOLFSSL_SUCCESS) {
            return ret;
        }
    }

    return WOLFSSL_SUCCESS;
}


static int validate_related_certificate_binding(WOLFSSL *ssl)
{
    /* Step 1: extension must be present (OID 1.3.6.1.5.5.7.1.36 found in PQ leaf) */
    if (!wolfSSL_peer_has_related_cert(ssl)) {
        printf("[TLS] related-cert FAIL: RelatedCertificate extension not found in PQ chain\n");
        return 0;
    }

    /* Step 2: hash computed in ProcessPeerCerts must match primary cert hash.
     * wolfSSL sets peerRelatedHashOk=1 inline when the OID is found:
     *   hash(ECDSA leaf DER)  ==  hash stored in RelatedCertificate extension. */
    if (!wolfSSL_peer_related_hash_ok(ssl)) {
        printf("[TLS] related-cert FAIL: hash binding mismatch or parse error\n");
        return 0;
    }

    printf("[TLS] related-cert OK: extension found + hash binding verified\n");
    return 1;
}

static int validate_peer_policy(WOLFSSL *ssl, const Scenario *sc)
{
    if (sc->require_related) {
        return validate_related_certificate_binding(ssl);
    }

    return 1;
}

/* ================================================================
 * Statistics helpers
 * ================================================================ */
typedef struct {
    float mean_ms;
    float stddev_ms;
    float ci95_low_ms;
    float ci95_high_ms;
    uint32_t min_ms;
    uint32_t max_ms;
    int  errors;
} Stats;

static void calc_stats(const uint32_t *samples, int n, int errors, Stats *s)
{
    int valid = n - errors;
    s->errors = errors;
    if (valid <= 0) { memset(s, 0, sizeof(*s)); s->errors = errors; return; }

    uint64_t sum = 0;
    s->min_ms = UINT32_MAX;
    s->max_ms = 0;
    for (int i = 0; i < n; i++) {
        if (samples[i] == 0) continue; /* skip error samples */
        sum += samples[i];
        if (samples[i] < s->min_ms) s->min_ms = samples[i];
        if (samples[i] > s->max_ms) s->max_ms = samples[i];
    }
    s->mean_ms = (float)sum / valid;

    float var = 0.0f;
    for (int i = 0; i < n; i++) {
        if (samples[i] == 0) continue;
        float d = (float)samples[i] - s->mean_ms;
        var += d * d;
    }
    s->stddev_ms = sqrtf(var / valid);

    /* 95% CI: mean ± 1.96 * stddev / sqrt(valid) */
    float margin = 1.96f * s->stddev_ms / sqrtf((float)valid);
    s->ci95_low_ms  = s->mean_ms - margin;
    s->ci95_high_ms = s->mean_ms + margin;
}

/* ================================================================
 * Single TLS handshake: returns elapsed ms, 0 on error
 * ================================================================ */
static uint32_t do_handshake(WOLFSSL_CTX *ctx, const Scenario *sc)
{
    static int hs_count = 0;
    uint16_t port = sc->port;
    if (port == 0) port = TLS_SERVER_PORT;
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port   = htons(port);
    inet_aton(TLS_SERVER_IP, &addr.sin_addr);

    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) return 0;

    /* Blocking connect — fast on LAN, avoids EINPROGRESS complexity. */
    if (connect(fd, (struct sockaddr *)&addr, sizeof(addr)) != 0) {
        printf("[TLS] TCP connect failed errno=%d\n", errno);
        close(fd); return 0;
    }

    /* Switch to non-blocking AFTER connect so wolfSSL_connect() can be
     * given a hard wall-clock deadline (WANT_READ loop with HAL_GetTick). */
    u32_t nb = 1;
    if (ioctlsocket(fd, FIONBIO, &nb) != 0) {
        printf("[TLS] FIONBIO failed errno=%d\n", errno);
        close(fd); return 0;
    }

    WOLFSSL *ssl = wolfSSL_new(ctx);
    if (!ssl) { close(fd); return 0; }

    wolfSSL_set_fd(ssl, fd);

    /* Reset per-message timing before each handshake */
    g_tls_t_server_hello_ms   = 0;
    g_tls_t_cert_ms           = 0;
    g_tls_t_cert_verify_ms    = 0;
    g_tls_t_pq_cert_verify_ms = 0;
    g_tls_t_finished_ms       = 0;
    tls13_set_tick_fn(HAL_GetTick);

    ++hs_count;
    uint32_t t_start = HAL_GetTick();
    int ret;
    do {
        ret = wolfSSL_connect(ssl);
        if (ret == WOLFSSL_SUCCESS) break;
        int err = wolfSSL_get_error(ssl, ret);
        if (err != WOLFSSL_ERROR_WANT_READ && err != WOLFSSL_ERROR_WANT_WRITE) break;
        /* Overflow-safe 15-second deadline: subtract avoids wrap-around issues */
        if ((int32_t)(HAL_GetTick() - t_start) > 15000) break;
        fd_set rfds; struct timeval stv = {0, 10000};   /* 10ms select slice */
        FD_ZERO(&rfds); FD_SET((unsigned)fd, &rfds);
        if (select(fd + 1, &rfds, NULL, NULL, &stv) < 0) break;
        osDelay(1);  /* 1 tick yield so LwIP can drain ETH DMA RX */
    } while (1);
    uint32_t t_end = HAL_GetTick();

    uint32_t elapsed = 0;
    if (ret == WOLFSSL_SUCCESS) {
        if (!validate_peer_policy(ssl, sc)) {
            printf("[TLS] peer policy validation failed for %s\n", sc->name);
        } else {
            elapsed = t_end - t_start;
            if (hs_count <= 3) {
                printf("  #%d OK %lu ms (SH=%lu C=%lu CV=%lu PQ=%lu F=%lu)\n",
                       hs_count, (unsigned long)elapsed,
                       (unsigned long)g_tls_t_server_hello_ms,
                       (unsigned long)g_tls_t_cert_ms,
                       (unsigned long)g_tls_t_cert_verify_ms,
                       (unsigned long)g_tls_t_pq_cert_verify_ms,
                       (unsigned long)g_tls_t_finished_ms);
            }
        }
    } else {
        int err = wolfSSL_get_error(ssl, ret);
        printf("[TLS] connect failed ret=%d err=%d heap_free=%lu heap_min=%lu\n",
               ret, err,
               (unsigned long)xPortGetFreeHeapSize(),
               (unsigned long)xPortGetMinimumEverFreeHeapSize());
    }

    wolfSSL_free(ssl);  /* skip shutdown — just free and close TCP */
    close(fd);

    return elapsed;
}

/* ================================================================
 * Run one scenario: TLS_REPEAT_COUNT handshakes, print results
 * ================================================================ */
/* Wait for ETH link + DHCP to be ready (up to timeout_ms).
 * Returns 1 if ready, 0 if timeout. */
static int wait_for_eth(uint32_t timeout_ms)
{
    uint32_t elapsed = 0;
    while (elapsed < timeout_ms) {
        if (netif_is_link_up(&gnetif) && gnetif.ip_addr.addr != 0)
            return 1;
        osDelay(500);
        elapsed += 500;
    }
    return 0;
}

static void run_scenario(const Scenario *sc)
{
    printf("\n[TLS] === %s ===\n", sc->name);

    /* Ensure ETH link is up before starting — recover from transient drops */
    if (!netif_is_link_up(&gnetif) || gnetif.ip_addr.addr == 0) {
        printf("[TLS] ETH link down, waiting (up to 30s)...\n");
        if (!wait_for_eth(30000)) {
            printf("[TLS] ETH link timeout, skipping %s\n", sc->name);
            return;
        }
        printf("[TLS] ETH link restored\n");
        osDelay(500); /* short settle */
    }

    printf("[TLS] Heap free=%lu min_ever=%lu\n",
           (unsigned long)xPortGetFreeHeapSize(),
           (unsigned long)xPortGetMinimumEverFreeHeapSize());

    WOLFSSL_CTX *ctx = wolfSSL_CTX_new(wolfTLSv1_3_client_method());
    if (!ctx) { printf("[TLS] CTX alloc failed\n"); return; }
    /* COMPOSITE uses OQS-OpenSSL s_server with p256_mldsa* certs.
     * wolfSSL composite chain verification is enabled: both ECDSA and ML-DSA
     * components of each cert signature are verified (see asn.c COMPOSITE_L*k). */
    wolfSSL_CTX_set_verify(ctx, WOLFSSL_VERIFY_PEER, NULL);

    int ca_ret = configure_scenario_ctx(ctx, sc);
    if (ca_ret != WOLFSSL_SUCCESS) {
        printf("[TLS] context setup failed ret=%d\n", ca_ret);
        wolfSSL_CTX_free(ctx);
        return;
    }

    uint32_t samples[TLS_REPEAT_COUNT];
    uint32_t sh_ms[TLS_REPEAT_COUNT];    /* ServerHello cumul */
    uint32_t cert_ms[TLS_REPEAT_COUNT];  /* Certificate cumul */
    uint32_t cv_ms[TLS_REPEAT_COUNT];    /* CertVerify cumul */
    uint32_t pqcv_ms[TLS_REPEAT_COUNT];  /* PQCertVerify cumul */
    uint32_t fin_ms[TLS_REPEAT_COUNT];   /* Finished cumul */
    /* Cert-parse sub-timing arrays */
    uint32_t cp_primary[TLS_REPEAT_COUNT];
    uint32_t cp_pq[TLS_REPEAT_COUNT];
    uint32_t cp_leaf[TLS_REPEAT_COUNT];
    uint32_t cp_hash[TLS_REPEAT_COUNT];
    memset(samples, 0, sizeof(samples));
    memset(sh_ms,   0, sizeof(sh_ms));
    memset(cert_ms, 0, sizeof(cert_ms));
    memset(cv_ms,   0, sizeof(cv_ms));
    memset(pqcv_ms, 0, sizeof(pqcv_ms));
    memset(fin_ms,  0, sizeof(fin_ms));
    memset(cp_primary, 0, sizeof(cp_primary));
    memset(cp_pq,      0, sizeof(cp_pq));
    memset(cp_leaf,    0, sizeof(cp_leaf));
    memset(cp_hash,    0, sizeof(cp_hash));
    int errors = 0;

    printf("[TLS] Running %d handshakes on port %u...\n",
           TLS_REPEAT_COUNT, sc->port ? sc->port : TLS_SERVER_PORT);

    for (int i = 0; i < TLS_REPEAT_COUNT; i++) {
        printf("[TLS] [%d/%d] %s\n", i + 1, TLS_REPEAT_COUNT, sc->name);
        uint32_t ms = do_handshake(ctx, sc);
        samples[i] = ms;
        if (ms > 0) {
            sh_ms[i]   = g_tls_t_server_hello_ms;
            cert_ms[i] = g_tls_t_cert_ms;
            cv_ms[i]   = g_tls_t_cert_verify_ms;
            pqcv_ms[i] = g_tls_t_pq_cert_verify_ms;
            fin_ms[i]  = g_tls_t_finished_ms;
            cp_primary[i] = g_cert_t_primary_ms;
            cp_pq[i]      = g_cert_t_pq_ms;
            cp_leaf[i]    = g_cert_t_leaf_ms;
            cp_hash[i]    = g_cert_t_hash_ms;
        } else {
            errors++;
            if (errors >= 3) break;
        }
        printf("[TLS] [%d/%d] %s → %s (%lu ms)\n",
               i + 1, TLS_REPEAT_COUNT, sc->name,
               ms > 0 ? "OK" : "ERR", (unsigned long)ms);
        osDelay(200);
    }

    wolfSSL_CTX_free(ctx);

    /* Total handshake stats */
    Stats s;
    calc_stats(samples, TLS_REPEAT_COUNT, errors, &s);

    /* Per-phase means from cumulative timestamps (compute incremental) */
    int n = TLS_REPEAT_COUNT - errors;
    float sum_sh = 0, sum_cert = 0, sum_cv = 0, sum_pqcv = 0, sum_fin = 0;
    int   n_pqcv = 0;
    for (int i = 0; i < TLS_REPEAT_COUNT; i++) {
        if (samples[i] == 0) continue;
        sum_sh   += (float)sh_ms[i];
        sum_cert += (float)(cert_ms[i] > sh_ms[i] ? cert_ms[i] - sh_ms[i] : 0);
        sum_cv   += (float)(cv_ms[i]   > cert_ms[i] ? cv_ms[i] - cert_ms[i] : 0);
        if (pqcv_ms[i] > 0) {
            sum_pqcv += (float)(pqcv_ms[i] > cv_ms[i] ? pqcv_ms[i] - cv_ms[i] : 0);
            n_pqcv++;
        }
        uint32_t last = (pqcv_ms[i] > 0) ? pqcv_ms[i] : cv_ms[i];
        sum_fin  += (float)(fin_ms[i]  > last ? fin_ms[i] - last : 0);
    }
    if (n <= 0) n = 1;
    float mean_sh   = sum_sh   / n;
    float mean_cert = sum_cert / n;
    float mean_cv   = sum_cv   / n;
    float mean_pqcv = n_pqcv > 0 ? sum_pqcv / n_pqcv : 0.0f;
    float mean_fin  = sum_fin  / n;

    printf("[TLS] --- Results: %s ---\n", sc->name);
    printf("[TLS] n=%d  errors=%d\n", TLS_REPEAT_COUNT, s.errors);
    printf("[TLS] total  mean=%.1f ms  stddev=%.1f ms  95CI=[%.1f,%.1f]\n",
           s.mean_ms, s.stddev_ms, s.ci95_low_ms, s.ci95_high_ms);
    printf("[TLS] phases SrvHello=%.1f  Cert=%.1f  CertVfy=%.1f  PQCertVfy=%.1f  Finished=%.1f ms\n",
           mean_sh, mean_cert, mean_cv, mean_pqcv, mean_fin);

    /* Cert-parse sub-timing summary */
    float sum_cp_primary = 0, sum_cp_pq = 0, sum_cp_leaf = 0, sum_cp_hash = 0;
    int n_cp = 0;
    for (int i = 0; i < TLS_REPEAT_COUNT; i++) {
        if (samples[i] == 0) continue;
        sum_cp_primary += (float)cp_primary[i];
        sum_cp_pq      += (float)cp_pq[i];
        sum_cp_leaf    += (float)cp_leaf[i];
        sum_cp_hash    += (float)cp_hash[i];
        n_cp++;
    }
    if (n_cp > 0 && sum_cp_pq > 0) {
        printf("[TLS] certparse primary=%.1f pq_block=%.1f pq_leaf=%.1f hash_bind=%.1f ms\n",
               sum_cp_primary / n_cp, sum_cp_pq / n_cp,
               sum_cp_leaf / n_cp, sum_cp_hash / n_cp);
    }
}

/* ================================================================
 * Probe: try one handshake with a given scenario's CA.
 * Returns 1 if server cert validates, 0 otherwise.
 * ================================================================ */
static int probe_scenario(const Scenario *sc)
{
    WOLFSSL_CTX *ctx = wolfSSL_CTX_new(wolfTLSv1_3_client_method());
    if (!ctx) { printf("[probe] CTX alloc failed\n"); return 0; }

    wolfSSL_CTX_set_verify(ctx, WOLFSSL_VERIFY_PEER, NULL);
    int ok = 0;

    int ca_ret = configure_scenario_ctx(ctx, sc);
    if (ca_ret != WOLFSSL_SUCCESS) {
        printf("[probe] %s: context setup failed ret=%d\n", sc->name, ca_ret);
        wolfSSL_CTX_free(ctx);
        return 0;
    }

    uint16_t port = sc->port ? sc->port : (uint16_t)TLS_SERVER_PORT;
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port   = htons(port);
    inet_aton(TLS_SERVER_IP, &addr.sin_addr);

    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0 || connect(fd, (struct sockaddr *)&addr, sizeof(addr)) != 0) {
        printf("[probe] %s: TCP connect failed\n", sc->name);
        if (fd >= 0) close(fd);
        wolfSSL_CTX_free(ctx);
        return 0;
    }

    WOLFSSL *ssl = wolfSSL_new(ctx);
    if (ssl) {
        wolfSSL_set_fd(ssl, fd);
        printf("\n====== [%s] TLS Handshake Start ======\n", sc->name);
        int ret = wolfSSL_connect(ssl);
        if (ret == WOLFSSL_SUCCESS) {
            ok = validate_peer_policy(ssl, sc);
            printf("====== [%s] Handshake %s ======\n\n",
                   sc->name, ok ? "OK" : "POLICY-FAIL");
        } else {
            int err = wolfSSL_get_error(ssl, ret);
            char ebuf[80];
            printf("====== [%s] Handshake FAILED (err=%d %s) ======\n\n",
                   sc->name, err, wolfSSL_ERR_error_string(err, ebuf));
            printf("[probe] %s: connect failed err=%d %s\n",
                   sc->name, err, wolfSSL_ERR_error_string(err, ebuf));
        }
        wolfSSL_free(ssl);  /* skip shutdown — just free and close TCP */
    }
    close(fd);

    wolfSSL_CTX_free(ctx);
    return ok;
}

/* ================================================================
 * wolfSSL logging callback — routes debug msgs to UART via printf
 * ================================================================ */
static void tls_log_cb(const int level, const char *const msg)
{
    (void)level;
    printf("[SSL] %s\n", msg);
}

/* ================================================================
 * FreeRTOS task entry point
 * ================================================================ */
void tls_perf_task(void *argument)
{
    (void)argument;

    /* Wait for DHCP */
    printf("[TLS] Waiting for DHCP...\n");
    while (gnetif.ip_addr.addr == 0) {
        osDelay(500);
    }
    printf("[TLS] DHCP ready: %lu.%lu.%lu.%lu\n",
           (gnetif.ip_addr.addr >>  0) & 0xFF,
           (gnetif.ip_addr.addr >>  8) & 0xFF,
           (gnetif.ip_addr.addr >> 16) & 0xFF,
           (gnetif.ip_addr.addr >> 24) & 0xFF);

    /* Extra settle time */
    osDelay(2000);

    wolfSSL_Init();
    wolfSSL_SetLoggingCb(tls_log_cb);

    /* Use fixed wall-clock time (2026-04-21 12:00:00 UTC = 1776168000).
     * SNTP blocking-recv observed to hang in lwIP; fixed time is sufficient
     * because embedded root CAs have notBefore=2026-02-06, notAfter=2036-02-04. */
    g_ntp_time = (time_t)1776168000UL;
    g_ntp_tick = HAL_GetTick();
    printf("[TLS] Using fixed time: Unix=%lu\n", (unsigned long)g_ntp_time);
    wc_SetTimeCb(ntp_time_cb);

    printf("[TLS] ============================================\n");
    printf("[TLS]  PQC Hybrid TLS Benchmark (STM32F439 168MHz)\n");
    printf("[TLS]  %u scenarios x %d handshakes\n", SCENARIO_COUNT, TLS_REPEAT_COUNT);
    printf("[TLS] ============================================\n");

    for (unsigned int i = 0; i < SCENARIO_COUNT; i++) {
        if (is_scenario_skipped(g_scenarios[i].name)) {
            printf("\n[TLS] === %s === SKIPPED (in skip list)\n",
                   g_scenarios[i].name);
            continue;
        }
        run_scenario(&g_scenarios[i]);
        osDelay(300);
    }

    printf("\n[TLS] ============================================\n");
    printf("[TLS] BENCHMARK COMPLETE\n");
    printf("[TLS] ALL DONE\n");
    printf("[TLS] ============================================\n");

    wolfSSL_Cleanup();
    for (;;) osDelay(portMAX_DELAY);
}
