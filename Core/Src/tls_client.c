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
    "MIIdPTCCCxSgAwIBAgIURZwDiLkPrFWOofUQ+NizK7kMmm4wCwYJYIZIAWUDBAMT\n"
    "MBUxEzARBgNVBAMMClBRIENBIENlcnQwHhcNMjYwMjA2MTE0NjQxWhcNMjcwMjA2\n"
    "MTE0NjQxWjAVMRMwEQYDVQQDDApQUSBDQSBDZXJ0MIIKMjALBglghkgBZQMEAxMD\n"
    "ggohAHVv6gXddsi6FkNGJlLiU2lXpvJ1JLsxBlNilRnVVnaVlhYnPl1XY3kWx6FP\n"
    "OUZlvPJacDfrMwwp+SZHWxVBMUkxEaU996AVKWpaejnE4MoFFOez5Wq9MuJg5u3D\n"
    "w196jAvPrrgJsBZC4IBq4j08hHeDiv9L/+yefhpQy57jV+Yp3yvNnx8z3iG/hvf3\n"
    "zWwHJS0kTFuUdHe8iy05fe01otYQDLZKT7483LZUcBtpepxusfvICXBFQYatYluH\n"
    "u5HKvr4MkFxw+CEH/Im7C4G1Qd8CLA8md9NwIUfiDkY7LuACiJmxRl8eQx+UNOJj\n"
    "kDoa2OCb6Xdnp3ZxpFKgCzUBOJ3OrOPsrbMx+VpSvtpfjQXr9WyKwJGkhK5bIh1N\n"
    "fc3hBBGVfPkOjrJX0dRmdJEh/CWL1gjaeQ3+1yiXMUS+hzhXDcy1un4t+HAx5NoY\n"
    "fAXonNsRpR8VoP1VthgqhLbSQalBgi6MrnzHonTt0RnbUsnBeYPuREebLvQM1+j7\n"
    "JGLJX3IZW7kY9NZ1byirXtecu+aNHE8MV0EB1heiXBiv5m5Y9ttWNW7mHlzGNqnN\n"
    "CLzgSl902DPWQRlSDc/7dnpGbcVU8hjM1R7DRZbH8TJfWyN3F15HkpTBF4PF+W3Q\n"
    "nBNEJMfiUm9UBvb6r8+0aLXacYhsUrGP7Z8uenuQ6uqEDcTfw1SFzz9k4nntYomw\n"
    "cJqcNwZkZ4CE9mnEIDaxYxDbIfALPfaVdA8IHhdW/D03U3Ry9gx2SqnCJqM4YKTT\n"
    "pfWjuzXkpgcoml/FGfGKjFEq6DrrZVWmIeYEJ+NrLABhaHLxT8JRdTrGUrJ/cTSn\n"
    "8gE1ElWHDBJvIA0B/jGEFkNbtjjimKhyNSlnwOYxedoSyO0T7aMxiHQpboEpNnBA\n"
    "DvRHYAzlktIwPSAz6X9OuZnBFoVCcHqEmRSZoPI5oYz4uOUw8uajVYllaN/dMER1\n"
    "g1Y0mz4PjMXiBJZajk8PZKc3a5iR0IPTapAvjh3leT2gK2q9LBHiSqKe7fZTL2Vd\n"
    "Yok/6U+0QWnCul2ywUVhVGb2DOwcBSeS+a6czTxviJUPEb+Jf+IK9i9FsTtMGYzY\n"
    "dPPKhrgWgo2/D2/rbQilTrXsjuXQ8XO0DxwUhaufJcjdyLae1qDaSW3nLjQ6A3Av\n"
    "mSEJ0qkipZ3ewsbvCB3+/BTBDYbaVF2dPpT94aHYVvGMlxRK5atHJMbOxjuyOeHc\n"
    "ogVOvakxja8WyR+gCk3JoiMYV6z6GpSQuIT4jAJ86b4BJbSrpFvuxkAeUMvKhfMj\n"
    "tS/+USxQggHjem9rWXPRhBnsbkct5Tevj7+JxX3JZXuV8Pvu613GVKdSjo/crdkD\n"
    "H17s6VHhDK5EF9RLdfsThsfhLJb4C4mJSuOpZgENUNZdfp4b1L98a9UkH+phvUqy\n"
    "RewEkUXN92IJuHJhIOEdJX71C5/8jaqbW70OOR8vmwKD6vAcQ0fkQofos8/gYfW4\n"
    "FHRqJcnZ68DiF3klTJY4tCcoBKTgRb1IFS272o5qWMDyU4q7a3OyuZimbh5ne5Ro\n"
    "o2CSfrRxC129OFjbTJ0xyoQu/pxQoukeKXQxjcFxE5cYxzO2k6hd5rbSw4rosN+w\n"
    "iE1RWSUx18RjgFx/THY/3Y95sNhfxJME07bVpWWFc0lLRbGETT1ZDT8blEmy+HII\n"
    "LkixiEm02pz4aU1J5JZuM7VzKr3fVdOh2UVAOSuXe++AcPmbZkob4SFylSVWcT4G\n"
    "B58LEpZrwTQjEJymB+w/fkhAeIlptTPoCxz1SIOlMUyZpS0YSDRZQ3FXcbT9Lmep\n"
    "FkLSY1WLxQ8rLHYQ+eYQnrAM4tOL43mlbzUqNc3sWHNcgxrPaP2Ru310zLq+sC6H\n"
    "NUa2qC5j8BH3yR7/QYxC/awRuKhmH4NhJPmeUXycPDanCav45uU6s+n83rcI5ag1\n"
    "qnuBR7O+Fh5llv1xsPYpsT7KckThRISONyZcrxqj65NN0hdg8BoPjX2VC6pUupFH\n"
    "w3TIny4kGZdDjUVQ67mYFfCruCW67JRSY3Ty8IwU/yc4wniOY6cKW80efSkKkOMb\n"
    "42oDyLuIbqXLhi5IE5Q5ybbpYiBFlDjP/7x7DEKfgmSEePP+EY2oThJuxIbzD46Y\n"
    "gOQmSXN+PYppio6PbBMkeUJc5cHQcMo7YUq7RR3iwlYlaSisAz5OsncOFA1KTz68\n"
    "CNF85n650KdTsFN+M9iVUvwmC9mAqom7Sxxt/R7tu2MAHExedPBdHrqLn0uTOJdx\n"
    "rGqDychgnJrOeLb9sexNLRNBCBSPszo1uWeTpfL6m6YYXj6yiP84Kb9Xu539veoX\n"
    "rcr9OqZEOWEBBoqOKahSonL6tezfGbourrR1Nu5Xho6Cwxn0bCrA6fnCnCkczs2q\n"
    "uBJyIdO0a+JDGhN87hkug7ky+5WG2i3tgX6P2r7QJos8UB5nW7oM8qdvzy9LGbJH\n"
    "aNPCdtmEe9Xka1snJbloKEbG24Sa6ZOMlBBoIZ2F2r1XzCdcSATU6ZSt0C3I8cLk\n"
    "Ap9xnZKnBmg04MoozwvfPYSzU1jQADpWQ0DBbz3vHtfMvASRVLj5yR5gstfasqtB\n"
    "8462KxNC0Ymsa3cz892pq7R3O9ENLXl/caeAgPR2F18sNbOj+l6SL7rpf3toMJOz\n"
    "WGRdNiYfijNr9J7c4s0SZgWYYU6qmCwb4Zqw146sIOHOI2jWtU+uBLBAMdrrSWpr\n"
    "kwcR/FUyuKXgnxu9ApXuF636vRqv62Xh6bIUc7AnlEqFeL5RgyhbtbQXDH2RA082\n"
    "Nf8ksadNsHHQAt4rrzEzk8hTPQdfSa5n+hLec9BeQb2s6kqGaSvv8BE4q6eXhh0S\n"
    "Lt751Os8FxpGcNGpWez7SHgGHHDaKVCyCQVR0pqEY1RBxlMOJEGWvoWJTVK0VRFn\n"
    "KyggslJcwBxUWnvHMWljwOKu6Zx8CY9KVGvUZRY6eASVytNN58q/VZilRPMa2gGd\n"
    "FZ9Rj/IQiHUgM6tRipUhXVkL23WydLT6L7EnMgXF3YlBxMYIAedZ8owM7F2HtEUa\n"
    "DzzL6mVfPBI6URPkWLTd5IVW2Y0+sKdsZj90f7ECFYEGHEpj2x8oTGSwx99ESMr6\n"
    "KgZr8dum4GIJ2B8z+MaSJSNdUUMKkmRSnyo8Awf8yvanDWLdf3x9Yvq/dsUtiss6\n"
    "j2CTvdQrTz6l24qp6TwaaTWbzv23H5vR6nT2ZxE+iZHwcZCoFj5kl+CvpIlsQyYt\n"
    "UCVTygiJBK0HWKk9S2IS2ir+cHr3RLrhVDnRk3ecEvaHCBScecs42rFm9RlM8KYt\n"
    "rjGEfrV6lrsPwonvVE0y9hKvVsCGEPpkLZfDLaf1Uw5mjK5zEpMgdDEDWQ/6V6CY\n"
    "gVhS8pSlf19sGm2WvjY2LaWn9p9V7P1CTEwhY7/URJjhrYBXATitzLapi5ha6SF+\n"
    "XHyCwujseCW1nOIh+Nid9qvYCW9enhBTRucvF4qc1wqCA/EdzcWgvea+3rT52LD9\n"
    "nVe1laNmMGQwEgYDVR0TAQH/BAgwBgEB/wIBATAOBgNVHQ8BAf8EBAMCAQYwHQYD\n"
    "VR0OBBYEFJFh46dJMA1IQV6rB5ijbq39KdzzMB8GA1UdIwQYMBaAFJFh46dJMA1I\n"
    "QV6rB5ijbq39KdzzMAsGCWCGSAFlAwQDEwOCEhQAGxbTePSp9bf2SHt2OENuFegu\n"
    "FpkHmjk3dRuhu0n/yNQwudhiLQVLLwHk1HujSqEmh8AlTfWdanuYIZnW4boMIO0u\n"
    "oultmb1J+n3onoQGkYcYz2Aa4dW1h5DfpI6le6dDJdUpjnWMjc2662+1r8bICmPy\n"
    "n0egThXQ2bbMZUW8C3MYEhfY4g/mYylROvqYPqZNzjX6HLYk/xB9VPcQrrphy89I\n"
    "lI7PROMdQdpFO0HbfWjXL68WJOujpp6GFt8ey5mU0VYyLmoUqvNRNVP/L2vP34j9\n"
    "NH6EGHuc5cDsT9gCQwLmZ33pV8qJbsJ64CDtjfRqKXK0NZx+js9MahTsWGbRl4sE\n"
    "VAE+gPNNbvl+694UN3dlO7mDy2d+Qad8fMTOiXRboCmSsyH/PrqbGVzlM9fHixKV\n"
    "+lLuyGBk/Ze92SLCBntCZjGdwWE9eOWSLBSUEA6ccwMYJHxTZMI5O9w4nS3B0nO6\n"
    "FIBNIxAnZxK3pZIP1c4nMSK7x02HJHfynjfaSzkplmdhF6nML+VTqkCjOe6CqoVN\n"
    "adYXpLX5XQuKk3nVsL52hnl7L3Huz3uUlhIIUFFs8JnqXvxNTQKVVFd2WCAUehgj\n"
    "Dq3fbT+/PbrcrlOmIRhaqfMHLxUp2pdVnSKs0zAEKkXd8Izy6Mno7c3vNOH7iwjo\n"
    "T3wJ2qOmNaBlby8Kc1VPlCMctL8qBVYWN6GTKqziDSqi8TY9aCgEBdv2wY5uIC52\n"
    "jUZZs468bdgvQkW+Oi+RjPmnYKG0OKIxAyg3GK2LYb1GJIBh9C9+QcPmH2fWjJv7\n"
    "pE7gJoYLA6Gn3w3X20zSjOqaQ2zpi3OiwjxCvmq34NIc9kuVh8/l9x0mIHe/8Y6g\n"
    "H9w+aDSGRNf316LD9XQQ+uSBtZ6/A71jm35uebpTtIDl2/AshwFBdbMbUsRQqkjE\n"
    "CiaJmCVQHl2Itx39F1e3INgPvZHRl647IK+QsZV5CilotmNtnkhWevTEUumLuLQ6\n"
    "qUs4xk+ciC7HiNdeePsurAQSde46Cq1B4pMi3BW++BLzvgA81N/1Fg0P1eM1lPvA\n"
    "J1ECpGhEquGP0qnzCVhgLtsugYCzR2XvDtl4YwfH49eW4dz2DGG/z9ZFqAhUt4o4\n"
    "XwyRPesJkmc6cj1l/adMzPD+GsY73r5GrASpnmKlJiHTldrG1gUmYba0jJT2aOH0\n"
    "xukTNSpZQEA9WVqbabSlSXJxdtACD1LCQkPJFHrMwY5xFhZaURhxaH/2uJ8ey931\n"
    "99mx+fD54ZAtFgfEWtjwzN2UCMaL0wI60TpGxc2CoCq3fAxNnVWXbO6H0YOkEouF\n"
    "zrjd2fkjd6YdRcnlweojFfZJwu/8+XXakn8hB4uaeSMJn8QDiFk07VmdB+2bEIsU\n"
    "TI4oCT1FhC5finzaBu3w7bbsogn97s7vwTkwBXqfL8OJa1qPUXhqJqb0DcafjSNK\n"
    "A3Ka+4e4hpOJE6+ekz6mfmTEh5mqnatP5qQSUH5j2a9Iwj8Jkyw+zByq+gm8lOi8\n"
    "TZrV8ffUHnQIILUQxO4/qtZ4Rt/Imdz5ebRdrBcn+FfH3VcJyAASJBCPGTjUeHry\n"
    "6gEwHZOJ+clz7m2Nn6XTAqlcmNevmhn3424OSMGOGO4aLFd4IKFClydzv9rGTwi9\n"
    "HGiPTP4fF4qGSGHmhxddS4uC93P1+guP+lv9BLf3WG3wqUJi4ha5Uem3uBnBm5V+\n"
    "sgGvzLofrdOK0gtzN4FyU8pvbfmsm5OhzZxkhE5zbcOOTRLficyRC/E3egIcTcEU\n"
    "g+mpfQHyuwH2j3cRAm3uxYhHGhMyWBMnliGCxm9t74RLU4fKM9Lo6tUrQ2Lu7xxa\n"
    "+Q3raxCRfEZUPeUmqBb7cFIpUySehz+9rL/cehzKxgUYLKSP8dea9Q4ux9dAy/bw\n"
    "GwDu4AwEO0b4ls/yZbSId8E6pb13UUAPMdoHduKTPINC+xnZDCnq/SQRxVyTPdFN\n"
    "hywurkP3hEshP1CPdNiy2mIpzQI4XOX58/p4o7iYabfFXcON2Gs1DLuexDQm5vEi\n"
    "AbuTGAlLGBFnc6UNQTHJp9v5Do0mDm65XPzec7IvUXOHNzLaI3wFd+EdEyFUPhhM\n"
    "yE2GyIf5h2UhgkwZHFN+mbxFR63RFYIjTwcehBdByzql9sS+xjye90nCKuPnFccV\n"
    "M4hlsda+v73czAyodW2nv2IdtOVrmo1BglHVzlyyfo9mAUklgYL27M3AdaiMeAw8\n"
    "Vr13ksPA2narXOKxvC3MUkDX5kGMDw1cicQsjDAxPUG9Ku7/Kdl0QIXNI0xtG2hk\n"
    "efpCf9tMKB877EvD6HcPUmuCkNpVMIb1z0UJAcOrXv+47nBZ8nQJR6M9SWgQ/4Oo\n"
    "vb9m9F8tFkB/PwIeyFvl//+FeEJtzVOV1E9k6sp1v5hhDCtmY3eB47KBjBXyOzvu\n"
    "3psXMiFGycsd1IWbc/r8MhKYQcusAJvJVkiSuMkxIaD+NNAVl4UavoJm31OYHREV\n"
    "HX+Ktb37iycf5mw4Wc4lOlKCq4lCWxIjQ0cStkCBPkdVTTxnU8ip5tl0Yg+4AO+G\n"
    "McqKvsJ5gzutucQsSBMf3Y5xFl5DF57hgIUelvtaYwpKbOIFwdL4oUYG+zF94ht5\n"
    "HugB7BRbJi2yT9vsDgho6frw3M7SR43Gw36qdQx4/Y/FCJb003HgRLp806BYGQ4U\n"
    "MvlH0Y93SLxFUwpeirJu6uDusnoCJhEh12N2M2zrRNGBFvboOBpWSCeukAgCoDtw\n"
    "tc/H5tryFMmd7Gdxi6ffwBCZHEoL1eAQwoNWriQ3hCiXQYY3LztiXlh/43Jo7fZ1\n"
    "Tl6mJSLR2n0AVDoR3UjnVW6jEDssgweIzHlpDQCjkcsazV2o8Dgg/JvCYTcuCNg0\n"
    "NAPaibwFhBSRo+gIMGt3pEZxuyKx3BUSgu5Ygu/pk2w8Sqjm3tgRN5TU5xt8GLwp\n"
    "b2e+dSNSV7nRcfLKLYacfOoMN0yg6iC03eRAJLxl4jm+YckCHNQ4TeBEGIUfwB2a\n"
    "DSNYECVxynnvnS1tYZYb27R6WYOyF0HZF9YMamnYe7vrff9Oouv8b/qNvLmjEFl5\n"
    "zQzJI3WHqpgSqI/YufOUQoyiaO8ffJLO90gO/nXisa3qE0eDQ5LBH3ZFWRBcfU00\n"
    "W8dGevpewoGi4sKUA22KKMdmLlZnZ5qWhJrWqUSmQaW9MrmksRijZ+xGMQTHPEaN\n"
    "UZfXqqwwCZdKd4lJOCzYjRjH6v364e+hjNOXP7Xcz1FpBNm9/K4OqBGbF7aSm9tG\n"
    "hkZrHXvrqKBMA0JGHtVsssIYydQZIvSLXz8Lg+bL6tPBXpcEEpprAFoF4Y4V607n\n"
    "M+YhLRZHj5E1U7YeFqGCJhXZGGzOCfO6MeZYdZfwsAnW5L9PSPshOTm41Gkw/+NR\n"
    "taDS1MrPGc4+VWdwdkUpsHB1y5hTEyJzmY8EeHoELYxeNqUP4+OUge1e4dnEik4T\n"
    "j48IEEg8cfwqdBoP7NJXg9KQ0sdgprlr8+c39jXvJeHI1lNP/Ao75iwbV0LoT1pQ\n"
    "hE0boMqGU1gB8Lu9fBnh2wXIOkmmp2hjmBJjPPsrYopTjuVWkyunIbO98vyHyp1p\n"
    "bVUeQvTwY7r8O8EHAYaAnoJMSrT+fqcxaQL/ipNbFZY3Jyjry12LiT2zC6F2Hdot\n"
    "5G0BsKyIIDd9698WDpMm1jlnte6Yrv7IiMY5IEyRZJMNRxtp3Hgj9rYLhg51OmrR\n"
    "d7sVzznRdP54yth9tHDQVjgiMkVYgCfox8g8vF/xr2+ehdg0nx/xYP6CmghisnDv\n"
    "gHJ5s/76L/63NT+OfETSHjBy9wDhI260+yoU6IAvAhcBo8ocu7TSynWhWIgC+SLY\n"
    "asJBT1orAxcedBbZIhvzqDeQCyb2f/0RLnLcToBF5IhuLjgmXurIMLRCNyCvPMro\n"
    "CbcXFHtLC3Bdfx3vTQ0SueZt6vTIY1dfdoX3y4x5XSLK/xfhFEspJ81l3rRyer1M\n"
    "A6gC8BxQeyQ5rkQ2ORpq17m9oH1iHF+bVdaxOn9PEmY4o0N1CyD1bI0wQriX6lMZ\n"
    "g7ddcnwM9QUmo/4igdAApIicrO6PYEjmVKfUmdjsp/6/OzlzLmm3UXhJFfs4834D\n"
    "FskRvPEYkCrO3yQ84HMStDzN2rq44LwCWg8RnUm+Q19BNycJu2qjfM769slmCB7m\n"
    "unBA0PbxVTf3V8go963mVm+KNmD9eHFdcFOTqaYpeDYvwTdJSW7s7vUztvljOR8l\n"
    "MRktAM+PuIVV/Knu/HlOZawsKI2nWgnZDEGK1LuLD+ntNKvVeo8es6Hq7QIYd4iX\n"
    "g+XGY/sK8pL5PqS5M+0nuLlksXP7JsVjoZtGWBZUFA+ObNw7Fj+rX9zikBg3ntPN\n"
    "ZmZjdAE+0KQ9iPH+qrFAcAibhHNhrcQxvg7uEo8T8IQxyyqMAyUo6FU4yoxJuB/v\n"
    "Q5Jop86mIMeTRivSnkQBKYkZooRmGT7oXt9tmsB2AB030+AcQ6xhTNnIfCQcjEvG\n"
    "6svf2jBag10gZCU+NX+BzK921jJpGHy9sqSkN5db67aUgUJKK2KjWCpGy/se9CtF\n"
    "VusIwS5JeZMRoFi8dRBlLRa5tDhJJiPwEETCRni7U7C6Bcs6MKZDqKYcxRC9TvZN\n"
    "THVzf1yuy+uQytUTJcQ3jcYc4Yb7yfa1h6f7TXN0Is6hJkYMUs2yQd4L9GIRTDjS\n"
    "PFPmtaK9rtRLbBAIrh0x8WZAqaaK7rnKBHQL1vFix+thOBLQFq0VCxrBTnqyONqF\n"
    "nYOhJRTdRqG/xRSuf9o9kpZ1JfhVozQqgvop9xJRxQUTM3R/nXowAymBF+ug41O2\n"
    "BFJMWz7CqQv+prJSAEGznQ6dL6ddsAq+c7RzDk82Q+1bFYae3do7w5XCHwq1ejU9\n"
    "t1yma5SZi/3ahLP5AQDFEJKPC60WwKC6ZYoARTcJVMfbL0koewjqncQiFasZ/mbz\n"
    "8oprakdHuxpoMNeh+dIjOLPETuco7/7W29a0+OZj1e16QL4f6Df+4Uy5XUAOgVPT\n"
    "APQtv2IKTGiE489T6fDfCcH1dT+mqtc5DyDS4DMKR0iOAVaPEDy7R2ZR3rjsDyUD\n"
    "9v0SNjGuhbeOU7LEJAMOO0rpXqWJl7zQ7L1IQJC5UwfQdkiapTsys+RhJ+wqrqnZ\n"
    "TM9PaGZxAcHAv3EGI9wgejQszHCDBMh6i8En9UCxs50Qy9PazIBQE6QSsACn4AeN\n"
    "iAuc4SIxDn3eEafoDksL9pjM/kLg/WVOunS2fgjUxo/FqnvWjys+HQoU1zUX0ial\n"
    "qYxrywzb+1wwJC7VXOenWWMhQUb0yw/PPvFs9a3dJqZi9WgNth9KQWUpaS1Uihyj\n"
    "clEAR7gWVOM8dJbxaJewrBQMeWytKqOaXCcFf2rcapoRt9Al1huShCs0mlPX6/Td\n"
    "tfNmvyOg5SGNj9uOFpnQY1mXk1uRy2GRPPITQEgWQ4YjTqei+5uWymM+AM1RcOSr\n"
    "5DmWZzC6dGgLtjeRVdVEfhxnYWO++Ud9qAQdybA+022Gq+MtsmqkZzRX7ty1g23u\n"
    "M1Z2IoZDczkFSMvcWn30ke8BRKv394YcOjxoldaHl9LZ7q9e8hUZc5aoNH+nBdUz\n"
    "330zKY1HUMAAspmgU5DvRyIgpDQh/IFjrtpHURJI/3aABSBLYFgvOtampT0a8PAm\n"
    "cv+YrPtcA+oxsi88E8KCMhmIpA79FcFQ8MWhaApiFXeEb4e4cvTFNxTNTEz60k4W\n"
    "wZ0bgKIg2R+M124U8GrhdldaN7PO4FBOw5tKvRSwCKTTOcruNXZIK0DYnkaEgDXW\n"
    "cS75efabZoDDZ9fWfHQ/xWzMxQBuKX7YUJpi9eQ7i0VnZ6EDEvWHnQ/wIQ1Jgs0a\n"
    "onj2aIPIja1JofT6Gj7j2FMMqhNnbG7fBGbW39V58PG5pp+9+aZR8rRCCO8mb4xm\n"
    "SJAG//PtML3H4r0CjSD6IBgETO06dgRHaPRbr3dhZwXuxRHTnZlV1DScgn/jfR0L\n"
    "aTa6Aerwx8p5Xey31vfrW7uKG4GSS1xqHv8uBfqQJCSxmxOCTLAIq1OIYlm/8kOb\n"
    "QUjkcn6kydrXJt3AN+UjUvGj5N2cZhOZmP5wIj6p8uuGzoW2GBfyszj4b9aVxRCX\n"
    "+UzJFoX5MSGOr0GWCyAkOUxrgIrTDh4vQ3ORnfYmKi84Pnp9j5zO0Q4UGRodOj9L\n"
    "YGtsba/nGzI4goiOp8vh6O8ZUnqGxNXnARsmJ0difH2JoSdbaHrS3gAHDxooMzpE\n"
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
 * Scenario table
 * ================================================================ */
typedef struct {
    const char   *name;
    CertType      type;
    SecurityLevel level;
    const char   *ca_pem;
    unsigned int  ca_pem_size;   /* strlen, NOT including final \0 */
    uint8_t       hybrid_cert_type;  /* HYBCERT_NONE/CATALYST/CHAMELEON */
} Scenario;

static const Scenario g_scenarios[] = {
    { "ECDSA_L1",   CERT_ECDSA,    SEC_LEVEL_1, CA_ECDSA_L1,    sizeof(CA_ECDSA_L1)    - 1, HYBCERT_NONE },
    { "ECDSA_L3",   CERT_ECDSA,    SEC_LEVEL_3, CA_ECDSA_L3,    sizeof(CA_ECDSA_L3)    - 1, HYBCERT_NONE },
    { "ECDSA_L5",   CERT_ECDSA,    SEC_LEVEL_5, CA_ECDSA_L5,    sizeof(CA_ECDSA_L5)    - 1, HYBCERT_NONE },
    { "MLDSA_L1",   CERT_MLDSA,    SEC_LEVEL_1, CA_MLDSA_L1,    sizeof(CA_MLDSA_L1)    - 1, HYBCERT_NONE },
    { "MLDSA_L3",   CERT_MLDSA,    SEC_LEVEL_3, CA_MLDSA_L3,    sizeof(CA_MLDSA_L3)    - 1, HYBCERT_NONE },
    { "MLDSA_L5",   CERT_MLDSA,    SEC_LEVEL_5, CA_MLDSA_L5,    sizeof(CA_MLDSA_L5)    - 1, HYBCERT_NONE },
    { "CATALYST_L1", CERT_CATALYST, SEC_LEVEL_1, CA_CATALYST_L1, sizeof(CA_CATALYST_L1) - 1, HYBCERT_CATALYST },
    { "CATALYST_L3", CERT_CATALYST, SEC_LEVEL_3, CA_CATALYST_L3, sizeof(CA_CATALYST_L3) - 1, HYBCERT_CATALYST },
    { "CATALYST_L5", CERT_CATALYST, SEC_LEVEL_5, CA_CATALYST_L5, sizeof(CA_CATALYST_L5) - 1, HYBCERT_CATALYST },
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
    static int hs_count = 0;
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

    printf("\n------ Handshake #%d ------\n", ++hs_count);
    uint32_t t_start = HAL_GetTick();
    int ret = wolfSSL_connect(ssl);
    uint32_t t_end   = HAL_GetTick();

    uint32_t elapsed = 0;
    if (ret == WOLFSSL_SUCCESS) {
        elapsed = t_end - t_start;
        printf("------ #%d OK (%lu ms) ------\n", hs_count, (unsigned long)elapsed);
        char buf[8];
        wolfSSL_read(ssl, buf, sizeof(buf) - 1);
    } else {
        int err = wolfSSL_get_error(ssl, ret);
        char ebuf[80];
        printf("[TLS] connect failed ret=%d err=%d heap_free=%lu heap_min=%lu\n",
               ret, err,
               (unsigned long)xPortGetFreeHeapSize(),
               (unsigned long)xPortGetMinimumEverFreeHeapSize());
        (void)ebuf;
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

    /* Set hybrid cert type (sends 0xFF10 extension in ClientHello) */
    if (sc->hybrid_cert_type != HYBCERT_NONE)
        wolfSSL_CTX_set_hybrid_cert_type(ctx, sc->hybrid_cert_type);

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
    if (!ctx) { printf("[probe] CTX alloc failed\n"); return 0; }

    wolfSSL_CTX_set_verify(ctx, WOLFSSL_VERIFY_PEER, NULL);
    int ok = 0;

    int ca_ret = wolfSSL_CTX_load_verify_buffer(ctx,
            (const unsigned char *)sc->ca_pem, (long)sc->ca_pem_size,
            WOLFSSL_FILETYPE_PEM);
    if (ca_ret != WOLFSSL_SUCCESS) {
        printf("[probe] %s: CA load failed ret=%d\n", sc->name, ca_ret);
        wolfSSL_CTX_free(ctx);
        return 0;
    }

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port   = htons(TLS_SERVER_PORT);
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
            ok = 1;
            printf("====== [%s] Handshake OK ======\n\n", sc->name);
            char buf[8];
            wolfSSL_read(ssl, buf, sizeof(buf) - 1);
        } else {
            int err = wolfSSL_get_error(ssl, ret);
            char ebuf[80];
            printf("====== [%s] Handshake FAILED (err=%d %s) ======\n\n",
                   sc->name, err, wolfSSL_ERR_error_string(err, ebuf));
            printf("[probe] %s: connect failed err=%d %s\n",
                   sc->name, err, wolfSSL_ERR_error_string(err, ebuf));
        }
        wolfSSL_shutdown(ssl);
        wolfSSL_free(ssl);
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

    /* Sync time via NTP so wolfSSL cert date validation passes */
    sntp_sync();
    wc_SetTimeCb(ntp_time_cb);

    printf("[TLS] Server: %s:%d\n", TLS_SERVER_IP, TLS_SERVER_PORT);

    /* Auto-detect which scenario — debug ON so every handshake message is visible */
    printf("[TLS] Probing server cert type...\n");
    wolfSSL_Debugging_ON();
    const Scenario *active = NULL;
    for (unsigned int i = 0; i < SCENARIO_COUNT; i++) {
        printf("[TLS] Trying %s ...\n", g_scenarios[i].name);
        if (probe_scenario(&g_scenarios[i])) {
            printf("[TLS] MATCH: %s\n", g_scenarios[i].name);
            active = &g_scenarios[i];
            break;
        }
        printf("[TLS] no match\n");
        osDelay(100);
    }
    wolfSSL_Debugging_OFF();   /* quiet during 30-handshake measurement */

    if (active == NULL) {
        printf("[TLS] No matching scenario found. Check server.\n");
    } else {
        run_scenario(active);
    }

    printf("\n[TLS] Done.\n");

    wolfSSL_Cleanup();
    for (;;) osDelay(portMAX_DELAY);
}
