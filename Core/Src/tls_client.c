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
 * Scenario table  (Stage 2: ECDSA only – extend in Stage 3)
 * ================================================================ */
typedef struct {
    const char   *name;
    CertType      type;
    SecurityLevel level;
    const char   *ca_pem;
    unsigned int  ca_pem_size;   /* strlen, NOT including final \0 */
} Scenario;

static const Scenario g_scenarios[] = {
    { "ECDSA_L5", CERT_ECDSA, SEC_LEVEL_5, CA_ECDSA_L5, sizeof(CA_ECDSA_L5) - 1 },
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
        printf("[TLS] connect failed ret=%d err=%d\n", ret, err);
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
    printf("[TLS] Starting %u scenarios x %d handshakes\n",
           (unsigned)SCENARIO_COUNT, TLS_REPEAT_COUNT);

    for (unsigned int i = 0; i < SCENARIO_COUNT; i++) {
        run_scenario(&g_scenarios[i]);
        osDelay(500);
    }

    printf("\n[TLS] All scenarios complete.\n");

    wolfSSL_Cleanup();
    for (;;) osDelay(portMAX_DELAY);
}
