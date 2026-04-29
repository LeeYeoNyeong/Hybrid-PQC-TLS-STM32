#if BENCH_MODE_MICROBENCH

#include "microbench.h"
#include "main.h"              /* stm32f4xx.h → core_cm4.h (CoreDebug, DWT) */
#include "FreeRTOS.h"
#include "task.h"
#include "wolfssl/wolfcrypt/ecc.h"
#include "wolfssl/wolfcrypt/curve25519.h"
#include "wolfssl/wolfcrypt/random.h"
#include <stdio.h>
#include <math.h>
#include <string.h>

#define N_ITER_P256   500
#define N_ITER_X25519  20
#define CPU_HZ   168000000UL

/* ── DWT helpers ─────────────────────────────────────────────────────────── */

static void dwt_init(void) {
    CoreDebug->DEMCR |= CoreDebug_DEMCR_TRCENA_Msk;
    DWT->CYCCNT = 0;
    DWT->CTRL  |= DWT_CTRL_CYCCNTENA_Msk;
}

static inline uint32_t dwt_now(void) { return DWT->CYCCNT; }

static float cyc_to_us(uint32_t cycles) {
    return (float)cycles * 1000000.0f / (float)CPU_HZ;
}

/* ── Statistics ──────────────────────────────────────────────────────────── */

static void print_stats(const char *label, float *us, int n) {
    float sum = 0.0f, sq = 0.0f, mn = us[0], mx = us[0];
    for (int i = 0; i < n; i++) {
        sum += us[i];  sq += us[i] * us[i];
        if (us[i] < mn) mn = us[i];
        if (us[i] > mx) mx = us[i];
    }
    float mean   = sum / n;
    float var    = sq / n - mean * mean;
    float stddev = sqrtf(var < 0.0f ? 0.0f : var);
    printf("[MICRO] %-22s n=%d  mean=%8.1f us  stddev=%6.1f us  min=%7.1f  max=%7.1f\r\n",
           label, n, mean, stddev, mn, mx);
}

/* ── P-256 keygen ────────────────────────────────────────────────────────── */

static void bench_p256_keygen(WC_RNG *rng) {
    float us[N_ITER_P256];
    for (int i = 0; i < N_ITER_P256; i++) {
        ecc_key k;
        wc_ecc_init(&k);
        uint32_t t0 = dwt_now();
        int ret = wc_ecc_make_key(rng, 32, &k);   /* P-256 */
        us[i] = cyc_to_us(dwt_now() - t0);
        wc_ecc_free(&k);
        if (ret != 0) {
            printf("[MICRO] P256_KEYGEN error ret=%d i=%d\r\n", ret, i);
            return;
        }
        if ((i & 0x3F) == 0) vTaskDelay(1);
    }
    print_stats("P256_KEYGEN", us, N_ITER_P256);
}

/* ── P-256 ECDH (shared secret) ──────────────────────────────────────────── */

static void bench_p256_ecdh(WC_RNG *rng) {
    /* Pre-generate peer public key once */
    ecc_key peer;
    wc_ecc_init(&peer);
    if (wc_ecc_make_key(rng, 32, &peer) != 0) {
        printf("[MICRO] P256_ECDH: peer keygen failed\r\n");
        return;
    }

    ecc_key priv;
    wc_ecc_init(&priv);
    if (wc_ecc_make_key(rng, 32, &priv) != 0) {
        printf("[MICRO] P256_ECDH: priv keygen failed\r\n");
        wc_ecc_free(&peer);
        return;
    }

    float us[N_ITER_P256];
    byte  shared[32];
    word32 sharedSz;
    for (int i = 0; i < N_ITER_P256; i++) {
        sharedSz = sizeof(shared);
        uint32_t t0 = dwt_now();
        int ret = wc_ecc_shared_secret(&priv, &peer, shared, &sharedSz);
        us[i] = cyc_to_us(dwt_now() - t0);
        if (ret != 0) {
            printf("[MICRO] P256_ECDH error ret=%d i=%d\r\n", ret, i);
            wc_ecc_free(&priv);  wc_ecc_free(&peer);
            return;
        }
        if ((i & 0x3F) == 0) vTaskDelay(1);
    }
    wc_ecc_free(&priv);  wc_ecc_free(&peer);
    print_stats("P256_ECDH", us, N_ITER_P256);
}

/* ── X25519 keygen ───────────────────────────────────────────────────────── */

static void bench_x25519_keygen(WC_RNG *rng) {
    float us[N_ITER_X25519];
    for (int i = 0; i < N_ITER_X25519; i++) {
        curve25519_key k;
        wc_curve25519_init(&k);
        uint32_t t0 = dwt_now();
        int ret = wc_curve25519_make_key(rng, 32, &k);
        us[i] = cyc_to_us(dwt_now() - t0);
        wc_curve25519_free(&k);
        if (ret != 0) {
            printf("[MICRO] X25519_KEYGEN error ret=%d i=%d\r\n", ret, i);
            return;
        }
        vTaskDelay(1);
    }
    print_stats("X25519_KEYGEN", us, N_ITER_X25519);
}

/* ── X25519 ECDH (shared secret) ─────────────────────────────────────────── */

static void bench_x25519_ecdh(WC_RNG *rng) {
    curve25519_key peer;
    wc_curve25519_init(&peer);
    if (wc_curve25519_make_key(rng, 32, &peer) != 0) {
        printf("[MICRO] X25519_ECDH: peer keygen failed\r\n");
        return;
    }

    curve25519_key priv;
    wc_curve25519_init(&priv);
    if (wc_curve25519_make_key(rng, 32, &priv) != 0) {
        printf("[MICRO] X25519_ECDH: priv keygen failed\r\n");
        wc_curve25519_free(&peer);
        return;
    }

    float us[N_ITER_X25519];
    byte   shared[32];
    word32 sharedSz;
    for (int i = 0; i < N_ITER_X25519; i++) {
        sharedSz = sizeof(shared);
        uint32_t t0 = dwt_now();
        int ret = wc_curve25519_shared_secret(&priv, &peer, shared, &sharedSz);
        us[i] = cyc_to_us(dwt_now() - t0);
        if (ret != 0) {
            printf("[MICRO] X25519_ECDH error ret=%d i=%d\r\n", ret, i);
            wc_curve25519_free(&priv);  wc_curve25519_free(&peer);
            return;
        }
        vTaskDelay(1);
    }
    wc_curve25519_free(&priv);  wc_curve25519_free(&peer);
    print_stats("X25519_ECDH", us, N_ITER_X25519);
}

/* ── Entry point ─────────────────────────────────────────────────────────── */

void microbench_run(void) {
    dwt_init();
    printf("\r\n[MICRO] ===== DWT Microbenchmark: P256 vs X25519 =====\r\n");
    printf("[MICRO] CPU=%lu Hz  DWT_res=%.2f ns  N_P256=%d N_X25519=%d\r\n\r\n",
           CPU_HZ, 1e9f / (float)CPU_HZ, N_ITER_P256, N_ITER_X25519);

    WC_RNG rng;
    wc_InitRng(&rng);

    bench_p256_keygen(&rng);
    bench_p256_ecdh(&rng);
    bench_x25519_keygen(&rng);
    bench_x25519_ecdh(&rng);

    wc_FreeRng(&rng);
    printf("\r\n[MICRO] ===== Done =====\r\n");
}

#endif /* BENCH_MODE_MICROBENCH */
