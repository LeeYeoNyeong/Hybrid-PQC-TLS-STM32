#if BENCH_MODE_MICROBENCH

#include "microbench.h"
#include "main.h"              /* stm32f4xx.h → core_cm4.h (CoreDebug, DWT) */
#include "FreeRTOS.h"
#include "task.h"
#include "wolfssl/wolfcrypt/wc_port.h"
#include "wolfssl/wolfcrypt/ecc.h"
#include "wolfssl/wolfcrypt/curve25519.h"
#include "wolfssl/wolfcrypt/mlkem.h"
#include "wolfssl/wolfcrypt/random.h"
#include <stdio.h>
#include <math.h>
#include <string.h>

#define N_ITER_P256    500
#define N_ITER_X25519   20
#define N_ITER_MLKEM   500
/* max CT size: ML-KEM-1024 = 1568 B; SS always 32 B */
#define MLKEM_CT_MAX_SZ  1568
#define MLKEM_SS_SZ        32
#define CPU_HZ   168000000UL

/* ── DWT helpers ─────────────────────────────────────────────────────────── */

static void dwt_init(void) {
    CoreDebug->DEMCR |= CoreDebug_DEMCR_TRCENA_Msk;
    DWT->CYCCNT = 0;
    DWT->CTRL  |= DWT_CTRL_CYCCNTENA_Msk;
}

static inline uint32_t dwt_now(void) { return DWT->CYCCNT; }

static float cyc_to_us(uint32_t cycles) {
    /* assumes single measurement < 25.5s (CYCCNT 32-bit wrap at 168 MHz) */
    return (float)cycles * 1000000.0f / (float)CPU_HZ;
}

/* ── Statistics ──────────────────────────────────────────────────────────── */

static void print_stats(const char *label, float *us, int n) {
    double sum = 0.0, sq = 0.0;
    float mn = us[0], mx = us[0];
    for (int i = 0; i < n; i++) {
        sum += us[i];  sq += (double)us[i] * us[i];
        if (us[i] < mn) mn = us[i];
        if (us[i] > mx) mx = us[i];
    }
    double mean   = sum / n;
    double var    = sq / n - mean * mean;
    double stddev = sqrt(var < 0.0 ? 0.0 : var);
    printf("[MICRO] %-22s n=%d  mean=%8.1f us  stddev=%6.1f us  min=%7.1f  max=%7.1f\r\n",
           label, n, (float)mean, (float)stddev, mn, mx);
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

/* ── ML-KEM keygen ───────────────────────────────────────────────────────── */

static void bench_mlkem_keygen(WC_RNG *rng, int type, const char *label) {
    MlKemKey *k = wc_MlKemKey_New(type, NULL, INVALID_DEVID);
    if (k == NULL) {
        printf("[MICRO] %s: wc_MlKemKey_New failed\r\n", label);
        return;
    }
    float us[N_ITER_MLKEM];
    for (int i = 0; i < N_ITER_MLKEM; i++) {
        uint32_t t0 = dwt_now();
        int ret = wc_MlKemKey_MakeKey(k, rng);
        us[i] = cyc_to_us(dwt_now() - t0);
        if (ret != 0) {
            printf("[MICRO] %s error ret=%d i=%d\r\n", label, ret, i);
            wc_MlKemKey_Delete(k, NULL);
            return;
        }
        if ((i & 0x1F) == 0) vTaskDelay(1);
    }
    wc_MlKemKey_Delete(k, NULL);
    print_stats(label, us, N_ITER_MLKEM);
}

/* ── ML-KEM encap ────────────────────────────────────────────────────────── */
/* Note: times Encapsulate only (includes internal RNG call per FIPS 203). */
/* ct/ss on stack (not static): BSS has only 1440 B headroom on this target. */

static void bench_mlkem_encap(WC_RNG *rng, int type, const char *label) {
    byte ct[MLKEM_CT_MAX_SZ];
    byte ss[MLKEM_SS_SZ];

    MlKemKey *k = wc_MlKemKey_New(type, NULL, INVALID_DEVID);
    if (k == NULL) {
        printf("[MICRO] %s: wc_MlKemKey_New failed\r\n", label);
        return;
    }
    if (wc_MlKemKey_MakeKey(k, rng) != 0) {
        printf("[MICRO] %s: keygen failed\r\n", label);
        wc_MlKemKey_Delete(k, NULL);
        return;
    }

    float us[N_ITER_MLKEM];
    for (int i = 0; i < N_ITER_MLKEM; i++) {
        uint32_t t0 = dwt_now();
        int ret = wc_MlKemKey_Encapsulate(k, ct, ss, rng);
        us[i] = cyc_to_us(dwt_now() - t0);
        if (ret != 0) {
            printf("[MICRO] %s error ret=%d i=%d\r\n", label, ret, i);
            wc_MlKemKey_Delete(k, NULL);
            return;
        }
        if ((i & 0x1F) == 0) vTaskDelay(1);
    }
    wc_MlKemKey_Delete(k, NULL);
    print_stats(label, us, N_ITER_MLKEM);
}

/* ── ML-KEM decap ────────────────────────────────────────────────────────── */
/* Fresh ciphertext each iteration: only Decapsulate is timed. */

static void bench_mlkem_decap(WC_RNG *rng, int type, const char *label) {
    byte ct[MLKEM_CT_MAX_SZ];
    byte ss[MLKEM_SS_SZ];
    word32 ctSz;

    MlKemKey *k = wc_MlKemKey_New(type, NULL, INVALID_DEVID);
    if (k == NULL) {
        printf("[MICRO] %s: wc_MlKemKey_New failed\r\n", label);
        return;
    }
    if (wc_MlKemKey_MakeKey(k, rng) != 0) {
        printf("[MICRO] %s: keygen failed\r\n", label);
        wc_MlKemKey_Delete(k, NULL);
        return;
    }
    if (wc_MlKemKey_CipherTextSize(k, &ctSz) != 0) {
        printf("[MICRO] %s: CT size query failed\r\n", label);
        wc_MlKemKey_Delete(k, NULL);
        return;
    }

    float us[N_ITER_MLKEM];
    for (int i = 0; i < N_ITER_MLKEM; i++) {
        if (wc_MlKemKey_Encapsulate(k, ct, ss, rng) != 0) {
            printf("[MICRO] %s: encap failed at i=%d\r\n", label, i);
            wc_MlKemKey_Delete(k, NULL);
            return;
        }
        uint32_t t0 = dwt_now();
        int ret = wc_MlKemKey_Decapsulate(k, ss, ct, ctSz);
        us[i] = cyc_to_us(dwt_now() - t0);
        if (ret != 0) {
            printf("[MICRO] %s error ret=%d i=%d\r\n", label, ret, i);
            wc_MlKemKey_Delete(k, NULL);
            return;
        }
        if ((i & 0x1F) == 0) vTaskDelay(1);
    }
    wc_MlKemKey_Delete(k, NULL);
    print_stats(label, us, N_ITER_MLKEM);
}

/* ── Entry point ─────────────────────────────────────────────────────────── */

void microbench_run(void) {
    dwt_init();
    wolfCrypt_Init();
    printf("\r\n[MICRO] ===== DWT Microbenchmark: P256 / X25519 / ML-KEM =====\r\n");
    printf("[MICRO] CPU=%lu Hz  DWT_res=%.2f ns  N_P256=%d N_X25519=%d N_MLKEM=%d\r\n\r\n",
           CPU_HZ, 1e9f / (float)CPU_HZ, N_ITER_P256, N_ITER_X25519, N_ITER_MLKEM);

    WC_RNG rng;
    int rret = wc_InitRng(&rng);
    if (rret != 0) {
        printf("[MICRO] wc_InitRng failed ret=%d\r\n", rret);
        wolfCrypt_Cleanup();
        return;
    }

    bench_p256_keygen(&rng);
    bench_p256_ecdh(&rng);
    bench_x25519_keygen(&rng);
    bench_x25519_ecdh(&rng);

    printf("\r\n[MICRO] ----- ML-KEM keygen -----\r\n");
    bench_mlkem_keygen(&rng, WC_ML_KEM_512,  "MLKEM512_KEYGEN");
    bench_mlkem_keygen(&rng, WC_ML_KEM_768,  "MLKEM768_KEYGEN");
    bench_mlkem_keygen(&rng, WC_ML_KEM_1024, "MLKEM1024_KEYGEN");

    printf("\r\n[MICRO] ----- ML-KEM encap -----\r\n");
    bench_mlkem_encap(&rng, WC_ML_KEM_512,  "MLKEM512_ENCAP");
    bench_mlkem_encap(&rng, WC_ML_KEM_768,  "MLKEM768_ENCAP");
    bench_mlkem_encap(&rng, WC_ML_KEM_1024, "MLKEM1024_ENCAP");

    printf("\r\n[MICRO] ----- ML-KEM decap -----\r\n");
    bench_mlkem_decap(&rng, WC_ML_KEM_512,  "MLKEM512_DECAP");
    bench_mlkem_decap(&rng, WC_ML_KEM_768,  "MLKEM768_DECAP");
    bench_mlkem_decap(&rng, WC_ML_KEM_1024, "MLKEM1024_DECAP");

    wc_FreeRng(&rng);
    wolfCrypt_Cleanup();
    printf("\r\n[MICRO] ===== Done =====\r\n");
}

#endif /* BENCH_MODE_MICROBENCH */
