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

#include <time.h>

/* ── extern from lwip.c ── */
extern struct netif gnetif;

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


/* ================================================================
 * Scenario table
 * ================================================================ */
typedef struct {
    const char   *name;
    CertType      type;
    SecurityLevel level;
    const char   *ca_pem;
    unsigned int  ca_pem_size;   /* strlen, NOT including final \0 */
} Scenario;

static const Scenario g_scenarios[] = {
    { "ECDSA_L1", CERT_ECDSA, SEC_LEVEL_1, CA_ECDSA_L1, sizeof(CA_ECDSA_L1) - 1 },
    { "ECDSA_L3", CERT_ECDSA, SEC_LEVEL_3, CA_ECDSA_L3, sizeof(CA_ECDSA_L3) - 1 },
    { "ECDSA_L5", CERT_ECDSA, SEC_LEVEL_5, CA_ECDSA_L5, sizeof(CA_ECDSA_L5) - 1 },
    { "MLDSA_L1", CERT_MLDSA, SEC_LEVEL_1, CA_MLDSA_L1, sizeof(CA_MLDSA_L1) - 1 },
    { "MLDSA_L3", CERT_MLDSA, SEC_LEVEL_3, CA_MLDSA_L3, sizeof(CA_MLDSA_L3) - 1 },
    { "MLDSA_L5", CERT_MLDSA, SEC_LEVEL_5, CA_MLDSA_L5, sizeof(CA_MLDSA_L5) - 1 },
};
#define SCENARIO_COUNT  (sizeof(g_scenarios) / sizeof(g_scenarios[0]))

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
static uint32_t do_handshake(WOLFSSL_CTX *ctx)
{
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port   = htons(TLS_SERVER_PORT);
    inet_aton(TLS_SERVER_IP, &addr.sin_addr);

    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) return 0;

    if (connect(fd, (struct sockaddr *)&addr, sizeof(addr)) != 0) {
        close(fd);
        return 0;
    }

    WOLFSSL *ssl = wolfSSL_new(ctx);
    if (!ssl) { close(fd); return 0; }

    wolfSSL_set_fd(ssl, fd);

    uint32_t t_start = HAL_GetTick();
    int ret = wolfSSL_connect(ssl);
    uint32_t t_end   = HAL_GetTick();

    uint32_t elapsed = 0;
    if (ret == WOLFSSL_SUCCESS) {
        elapsed = t_end - t_start;
        /* Read server's "OK" response */
        char buf[8];
        wolfSSL_read(ssl, buf, sizeof(buf) - 1);
    } else {
        int err = wolfSSL_get_error(ssl, ret);
        printf("[TLS] connect failed ret=%d err=%d heap_free=%lu heap_min=%lu\n",
               ret, err,
               (unsigned long)xPortGetFreeHeapSize(),
               (unsigned long)xPortGetMinimumEverFreeHeapSize());
    }

    wolfSSL_shutdown(ssl);
    wolfSSL_free(ssl);
    close(fd);

    return elapsed;
}

/* ================================================================
 * Run one scenario: TLS_REPEAT_COUNT handshakes, print results
 * ================================================================ */
static void run_scenario(const Scenario *sc)
{
    printf("\n[TLS] === %s ===\n", sc->name);
    printf("[TLS] Heap free=%lu min_ever=%lu\n",
           (unsigned long)xPortGetFreeHeapSize(),
           (unsigned long)xPortGetMinimumEverFreeHeapSize());

    /* Build wolfSSL context */
    WOLFSSL_CTX *ctx = wolfSSL_CTX_new(wolfTLSv1_3_client_method());
    if (!ctx) {
        printf("[TLS] CTX alloc failed\n");
        return;
    }
    wolfSSL_CTX_set_verify(ctx, WOLFSSL_VERIFY_PEER, NULL);

    /* Load CA cert from buffer (PEM) */
    int ca_ret = wolfSSL_CTX_load_verify_buffer(ctx,
            (const unsigned char *)sc->ca_pem,
            (long)sc->ca_pem_size,
            WOLFSSL_FILETYPE_PEM);
    if (ca_ret != WOLFSSL_SUCCESS) {
        printf("[TLS] CA load failed ret=%d\n", ca_ret);
        wolfSSL_CTX_free(ctx);
        return;
    }

    /* Measurement loop */
    uint32_t samples[TLS_REPEAT_COUNT];
    int errors = 0;

    printf("[TLS] Running %d handshakes...\n", TLS_REPEAT_COUNT);
    for (int i = 0; i < TLS_REPEAT_COUNT; i++) {
        uint32_t ms = do_handshake(ctx);
        samples[i]  = ms;
        if (ms == 0) {
            errors++;
            if (errors == 1) {
                /* Only print error detail once */
                printf("[TLS] First error on handshake %d\n", i);
            }
            if (errors >= 3) break; /* stop early if all failing */
        }

        /* Progress every 10 */
        if ((i + 1) % 10 == 0) {
            printf("[TLS] %d/%d done\n", i + 1, TLS_REPEAT_COUNT);
        }
        osDelay(10); /* brief pause between connections */
    }

    wolfSSL_CTX_free(ctx);

    /* Statistics */
    Stats s;
    calc_stats(samples, TLS_REPEAT_COUNT, errors, &s);

    printf("[TLS] --- Results: %s ---\n", sc->name);
    printf("[TLS] n=%d  errors=%d\n", TLS_REPEAT_COUNT, s.errors);
    printf("[TLS] mean=%.2f ms  stddev=%.2f ms\n", s.mean_ms, s.stddev_ms);
    printf("[TLS] 95%% CI=[%.2f, %.2f] ms\n", s.ci95_low_ms, s.ci95_high_ms);
    printf("[TLS] min=%lu ms  max=%lu ms\n", s.min_ms, s.max_ms);
}

/* ================================================================
 * Probe: try one handshake with a given scenario's CA.
 * Returns 1 if server cert validates, 0 otherwise.
 * ================================================================ */
static int probe_scenario(const Scenario *sc)
{
    WOLFSSL_CTX *ctx = wolfSSL_CTX_new(wolfTLSv1_3_client_method());
    if (!ctx) return 0;

    wolfSSL_CTX_set_verify(ctx, WOLFSSL_VERIFY_PEER, NULL);
    int ok = 0;

    if (wolfSSL_CTX_load_verify_buffer(ctx,
            (const unsigned char *)sc->ca_pem, (long)sc->ca_pem_size,
            WOLFSSL_FILETYPE_PEM) == WOLFSSL_SUCCESS) {

        struct sockaddr_in addr;
        memset(&addr, 0, sizeof(addr));
        addr.sin_family = AF_INET;
        addr.sin_port   = htons(TLS_SERVER_PORT);
        inet_aton(TLS_SERVER_IP, &addr.sin_addr);

        int fd = socket(AF_INET, SOCK_STREAM, 0);
        if (fd >= 0 && connect(fd, (struct sockaddr *)&addr, sizeof(addr)) == 0) {
            WOLFSSL *ssl = wolfSSL_new(ctx);
            if (ssl) {
                wolfSSL_set_fd(ssl, fd);
                if (wolfSSL_connect(ssl) == WOLFSSL_SUCCESS) {
                    ok = 1;
                    char buf[8];
                    wolfSSL_read(ssl, buf, sizeof(buf) - 1);
                }
                wolfSSL_shutdown(ssl);
                wolfSSL_free(ssl);
            }
        }
        if (fd >= 0) close(fd);
    }

    wolfSSL_CTX_free(ctx);
    return ok;
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
    wolfSSL_Debugging_OFF();

    /* Sync time via NTP so wolfSSL cert date validation passes */
    sntp_sync();
    wc_SetTimeCb(ntp_time_cb);

    printf("[TLS] Server: %s:%d\n", TLS_SERVER_IP, TLS_SERVER_PORT);

    /* Auto-detect which scenario matches the running server */
    printf("[TLS] Probing server cert type...\n");
    const Scenario *active = NULL;
    for (unsigned int i = 0; i < SCENARIO_COUNT; i++) {
        printf("[TLS] Trying %s ... ", g_scenarios[i].name);
        if (probe_scenario(&g_scenarios[i])) {
            printf("MATCH\n");
            active = &g_scenarios[i];
            break;
        }
        printf("no\n");
        osDelay(100);
    }

    if (active == NULL) {
        printf("[TLS] No matching scenario found. Check server.\n");
    } else {
        run_scenario(active);
    }

    printf("\n[TLS] Done.\n");

    wolfSSL_Cleanup();
    for (;;) osDelay(portMAX_DELAY);
}
