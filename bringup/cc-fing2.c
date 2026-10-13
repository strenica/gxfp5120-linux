// cc-imageread.c — replay full D0Entry+TLS session, then replay the Windows
// capture sequence (36#1 -> 50-nav -> 36#2 -> 82 -> 20-image) byte-exact, and
// collect the EC parcel stream (one [4+256] window per gpio17 pulse, Windows ISR
// cadence) into a binary file for offline assembly + TLS decryption.
//
// cc-bg: one mount -> background frame (no finger) + 5 finger frames.
// usage: cc-bg <spidev> <gpiochipN> <line> <mode> <hz> <outdir>
//   writes <outprefix>.frames.txt  (every parsed frame, hex, with timestamp)
//          <outprefix>.parcels.bin (per parcel: u64 usec | u32 status | 256B window)
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <poll.h>
#include <sys/ioctl.h>
#include <linux/spi/spidev.h>
#include <linux/gpio.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <time.h>

static int fd;                 // spidev
static int gfd = -1;           // gpio line
static uint32_t HZ;
static double T0;
static FILE *frames_fp, *parcels_fp;

static double now_s(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return ts.tv_sec + ts.tv_nsec / 1e9;
}
static uint64_t now_us(void) { return (uint64_t)(now_s() * 1e6); }
static void tag(void) { printf("[%9.3f] ", now_s() - T0); }

static int xfer(const uint8_t *tx, uint8_t *rx, size_t len) {
    struct spi_ioc_transfer tr;
    memset(&tr, 0, sizeof(tr));
    tr.tx_buf = (unsigned long)tx;
    tr.rx_buf = (unsigned long)rx;
    tr.len = (uint32_t)len;
    tr.speed_hz = HZ;
    tr.bits_per_word = 8;
    return ioctl(fd, SPI_IOC_MESSAGE(1), &tr);
}

// Windows-style parcel read: two descriptors in one ioctl:
//   [bb f1 00 00] (4B, rx = 4B status)  then  [00 x256] (rx = 256B window)
static int parcel_read(uint8_t st[4], uint8_t win[256]) {
    uint8_t op[4] = {0xbb, 0xf1, 0x00, 0x00};
    uint8_t zeros[256];
    memset(zeros, 0, sizeof(zeros));
    struct spi_ioc_transfer tr[2];
    memset(tr, 0, sizeof(tr));
    tr[0].tx_buf = (unsigned long)op;
    tr[0].rx_buf = (unsigned long)st;
    tr[0].len = 4;
    tr[0].speed_hz = HZ;
    tr[0].bits_per_word = 8;
    tr[1].tx_buf = (unsigned long)zeros;
    tr[1].rx_buf = (unsigned long)win;
    tr[1].len = 256;
    tr[1].speed_hz = HZ;
    tr[1].bits_per_word = 8;
    return ioctl(fd, SPI_IOC_MESSAGE(2), tr);
}

static size_t hex2bin(const char *h, uint8_t *out, size_t max) {
    size_t n = 0;
    for (const char *p = h; p[0] && p[1]; p += 2) {
        unsigned v;
        if (n >= max || sscanf(p, "%2x", &v) != 1) break;
        out[n++] = (uint8_t)v;
    }
    return n;
}

static size_t build_ae_frame(uint8_t fr[16]) {
    uint16_t ts = (uint16_t)((now_us() / 1000) & 0xffff);
    uint8_t inner[9];
    inner[0] = 0xaf; inner[1] = 0x06; inner[2] = 0x00;
    inner[3] = 0x55; inner[4] = (uint8_t)(ts & 0xff); inner[5] = (uint8_t)(ts >> 8);
    inner[6] = 0; inner[7] = 0;
    inner[8] = (uint8_t)(0xAA - 0xaf - 0x06 - 0x00 - 0x55 - inner[4] - inner[5]);
    fr[0] = 0xa0; fr[1] = 0x09; fr[2] = 0x00; fr[3] = (uint8_t)((0xa0 + 0x09) & 0xff);
    memcpy(fr + 4, inner, 9);
    return 13;
}
static void ae_hex(char *hx, const uint8_t *fr, size_t fl) {
    for (size_t k = 0; k < fl; k++) sprintf(hx + 2 * k, "%02x", fr[k]);
    hx[2 * fl] = 0;
}

static size_t load_hex_file(const char *path, uint8_t *out, size_t max) {
    char line[2048];
    FILE *fp = fopen(path, "r");
    if (!fp) { fprintf(stderr, "missing %s\n", path); return 0; }
    if (!fgets(line, sizeof(line), fp)) { fclose(fp); return 0; }
    fclose(fp);
    line[strcspn(line, "\r\n")] = 0;
    return hex2bin(line, out, max);
}


/* ---------- crypto: SHA-256 / HMAC / TLS-1.2 PRF / AES-CBC ---------- */
static void sha256_oneshot(const uint8_t *in, size_t len, uint8_t out[32]) {
    unsigned int n;
    EVP_Digest(in, len, out, &n, EVP_sha256(), NULL);
}
static void hmac256(const uint8_t *key, size_t klen, const uint8_t *in, size_t len, uint8_t out[32]) {
    unsigned int n;
    HMAC(EVP_sha256(), key, (int)klen, in, len, out, &n);
}
static void tls_prf(const uint8_t *secret, size_t slen, const char *label,
                    const uint8_t *seed, size_t seedlen, uint8_t *out, size_t outlen) {
    size_t ll = strlen(label);
    uint8_t ls[512]; memcpy(ls, label, ll); memcpy(ls + ll, seed, seedlen);
    uint8_t A[32]; hmac256(secret, slen, ls, ll + seedlen, A);
    size_t done = 0;
    while (done < outlen) {
        uint8_t block[32], tmp[1024];
        memcpy(tmp, A, 32); memcpy(tmp + 32, ls, ll + seedlen);
        hmac256(secret, slen, tmp, 32 + ll + seedlen, block);
        size_t take = (outlen - done) < 32 ? (outlen - done) : 32;
        memcpy(out + done, block, take); done += take;
        hmac256(secret, slen, A, 32, A);
    }
}
static int aes_cbc_encrypt(const uint8_t key[16], const uint8_t iv[16],
                           const uint8_t *in, size_t len, uint8_t *out) {
    EVP_CIPHER_CTX *c = EVP_CIPHER_CTX_new();
    int n = 0, f = 0;
    if (!c) return -1;
    if (EVP_EncryptInit_ex(c, EVP_aes_128_cbc(), NULL, key, iv) != 1 ||
        EVP_CIPHER_CTX_set_padding(c, 0) != 1 ||
        EVP_EncryptUpdate(c, out, &n, in, (int)len) != 1 ||
        EVP_EncryptFinal_ex(c, out + n, &f) != 1) { EVP_CIPHER_CTX_free(c); return -1; }
    EVP_CIPHER_CTX_free(c);
    return n + f;
}
static int aes_cbc_decrypt(const uint8_t key[16], const uint8_t iv[16],
                           const uint8_t *in, size_t len, uint8_t *out) {
    EVP_CIPHER_CTX *c = EVP_CIPHER_CTX_new();
    int n = 0, f = 0;
    if (!c) return -1;
    if (EVP_DecryptInit_ex(c, EVP_aes_128_cbc(), NULL, key, iv) != 1 ||
        EVP_CIPHER_CTX_set_padding(c, 0) != 1 ||
        EVP_DecryptUpdate(c, out, &n, in, (int)len) != 1 ||
        EVP_DecryptFinal_ex(c, out + n, &f) != 1) { EVP_CIPHER_CTX_free(c); return -1; }
    EVP_CIPHER_CTX_free(c);
    return n + f;
}

/* ---------- live TLS server flight ---------- */
static int g_mcu_tls = -1;
static uint8_t g_cwk[16], g_cmac[32];
static uint8_t g_fdt_frame[32];
static int g_fdt_ok = 0;
static uint8_t CH_msg[64], CKE_msg[64];
static size_t CH_msg_len = 0, CKE_msg_len = 0;
static uint8_t SR[32], SH_msg[96];
static size_t SH_msg_len = 0;
static uint8_t g_master[48], g_smac[32], g_swk[16];

static void rand_bytes(uint8_t *out, size_t n) {
    FILE *f = fopen("/dev/urandom", "rb");
    if (f) { size_t r = fread(out, 1, n, f); fclose(f); if (r == n) return; }
    for (size_t i = 0; i < n; i++) out[i] = (uint8_t)(0x5a + i * 7);
}

static size_t build_sh(uint8_t *frame) {
    uint8_t sid[32];
    rand_bytes(SR, 32); rand_bytes(sid, 32);
    uint8_t h[81]; size_t n = 0;
    h[n++] = 0x02; h[n++] = 0x00; h[n++] = 0x00; h[n++] = 0x4d;
    h[n++] = 0x03; h[n++] = 0x03;
    memcpy(h + n, SR, 32); n += 32;
    h[n++] = 0x20; memcpy(h + n, sid, 32); n += 32;
    h[n++] = 0x00; h[n++] = 0xae; h[n++] = 0x00;
    h[n++] = 0x00; h[n++] = 0x05;
    h[n++] = 0xff; h[n++] = 0x01; h[n++] = 0x00; h[n++] = 0x01; h[n++] = 0x00;
    memcpy(SH_msg, h, n); SH_msg_len = n;
    size_t rec_len = 5 + n;
    frame[0] = 0xb0; frame[1] = (uint8_t)(rec_len & 0xff); frame[2] = (uint8_t)(rec_len >> 8);
    frame[3] = (uint8_t)((0xb0 + frame[1] + frame[2]) & 0xff);
    frame[4] = 0x16; frame[5] = 0x03; frame[6] = 0x03; frame[7] = 0x00; frame[8] = (uint8_t)n;
    memcpy(frame + 9, h, n);
    return 4 + rec_len;
}

static void derive_keys2(const uint8_t cr_in[32], const uint8_t sr_in[32]) {
    uint8_t psk[64]; size_t plen = 0;
    const char *paths[] = {"../psk_raw32.bin", "psk_raw32.bin",
                           "/etc/gxfp5120/psk.bin"};
    for (int i = 0; i < 3 && !plen; i++) {
        FILE *f = fopen(paths[i], "rb");
        if (f) { plen = fread(psk, 1, 64, f); fclose(f); }
    }
    if (plen != 32) { tag(); printf("!! psk load failed\n"); }
    uint8_t prem[72]; size_t p = 0;
    prem[p++] = 0x00; prem[p++] = (uint8_t)plen; memset(prem + p, 0, plen); p += plen;
    prem[p++] = 0x00; prem[p++] = (uint8_t)plen; memcpy(prem + p, psk, plen); p += plen;
    uint8_t seed[64]; memcpy(seed, cr_in, 32); memcpy(seed + 32, sr_in, 32);
    tls_prf(prem, p, "master secret", seed, 64, g_master, 48);
    uint8_t kseed[64]; memcpy(kseed, sr_in, 32); memcpy(kseed + 32, cr_in, 32);
    uint8_t kb[96];
    tls_prf(g_master, 48, "key expansion", kseed, 64, kb, 96);
    memcpy(g_cmac, kb, 32);
    memcpy(g_smac, kb + 32, 32);
    memcpy(g_cwk, kb + 64, 16);
    memcpy(g_swk, kb + 80, 16);
}
static void derive_keys(void) {
    uint8_t cr[32]; memcpy(cr, CH_msg + 6, 32);
    derive_keys2(cr, SR);
}
static void save_session(const uint8_t cr[32], const uint8_t sr[32]) {
    FILE *f = fopen("/tmp/gxfp-session.txt", "w");
    if (!f) return;
    for (int k = 0; k < 32; k++) fprintf(f, "%02x", cr[k]); fprintf(f, "\n");
    for (int k = 0; k < 32; k++) fprintf(f, "%02x", sr[k]); fprintf(f, "\n");
    fclose(f);
}
static int load_session(uint8_t cr[32], uint8_t sr[32]) {
    FILE *f = fopen("/var/lib/fprint/gxfp5120-session.txt", "r");
    char l1[96], l2[96];
    if (!f) f = fopen("/tmp/gxfp-session.txt", "r");
    if (!f) return 0;
    if (!fgets(l1, sizeof l1, f) || !fgets(l2, sizeof l2, f)) { fclose(f); return 0; }
    fclose(f);
    return hex2bin(l1, cr, 32) == 32 && hex2bin(l2, sr, 32) == 32;
}

static size_t build_finished(uint8_t *frame) {
    uint8_t shd_msg[4] = {0x0e, 0x00, 0x00, 0x00};
    EVP_MD_CTX *mc = EVP_MD_CTX_new();
    uint8_t th[32]; unsigned int thn = 0;
    EVP_DigestInit_ex(mc, EVP_sha256(), NULL);
    EVP_DigestUpdate(mc, CH_msg, CH_msg_len);
    EVP_DigestUpdate(mc, SH_msg, SH_msg_len);
    EVP_DigestUpdate(mc, shd_msg, 4);
    EVP_DigestUpdate(mc, CKE_msg, CKE_msg_len);
    EVP_DigestFinal_ex(mc, th, &thn);
    uint8_t cvd[12], svd[12], seed2[32];
    tls_prf(g_master, 48, "client finished", th, 32, cvd, 12);
    uint8_t cfm[16] = {0x14, 0x00, 0x00, 0x0c};
    memcpy(cfm + 4, cvd, 12);
    EVP_DigestInit_ex(mc, EVP_sha256(), NULL);
    EVP_DigestUpdate(mc, CH_msg, CH_msg_len);
    EVP_DigestUpdate(mc, SH_msg, SH_msg_len);
    EVP_DigestUpdate(mc, shd_msg, 4);
    EVP_DigestUpdate(mc, CKE_msg, CKE_msg_len);
    EVP_DigestUpdate(mc, cfm, 16);
    EVP_DigestFinal_ex(mc, seed2, &thn);
    EVP_MD_CTX_free(mc);
    tls_prf(g_master, 48, "server finished", seed2, 32, svd, 12);
    uint8_t fin_msg[16] = {0x14, 0x00, 0x00, 0x0c};
    memcpy(fin_msg + 4, svd, 12);
    uint8_t mac_in[29];
    memset(mac_in, 0, 8);
    mac_in[8] = 0x16; mac_in[9] = 0x03; mac_in[10] = 0x03; mac_in[11] = 0x00; mac_in[12] = 0x10;
    memcpy(mac_in + 13, fin_msg, 16);
    uint8_t hm[32], plain[64], ctbuf[80], iv[16];
    hmac256(g_smac, 32, mac_in, 29, hm);
    memcpy(plain, fin_msg, 16); memcpy(plain + 16, hm, 32); memset(plain + 48, 0x0f, 16);
    rand_bytes(iv, 16);
    if (aes_cbc_encrypt(g_swk, iv, plain, 64, ctbuf) != 64) { tag(); printf("!! cbc failed\n"); }
    frame[0] = 0xb0; frame[1] = 0x55; frame[2] = 0x00; frame[3] = 0x05;
    frame[4] = 0x16; frame[5] = 0x03; frame[6] = 0x03; frame[7] = 0x00; frame[8] = 0x50;
    memcpy(frame + 9, iv, 16); memcpy(frame + 25, ctbuf, 64);
    return 4 + 5 + 80;
}

static void save_frame(const uint8_t *f, size_t total, const char *kind) {
    if (!frames_fp) return;
    fprintf(frames_fp, "%.6f %s %zu ", now_s() - T0, kind, total);
    for (size_t k = 0; k < total; k++) fprintf(frames_fp, "%02x", f[k]);
    fprintf(frames_fp, "\n");
}

static void write_milan(const uint8_t *frame, size_t flen) {
    uint8_t tx[1024], rx[1024];
    if (flen > sizeof(tx) - 4) flen = sizeof(tx) - 4;
    tx[0] = 0xcc; tx[1] = 0xf2; tx[2] = 0x00; tx[3] = 0x01;
    memcpy(tx + 4, frame, flen);
    size_t pad = (4 - (flen & 3)) & 3;
    memset(tx + 4 + flen, 0, pad);
    if (xfer(tx, rx, 4 + flen + pad) < 0) perror("write xfer");
    save_frame(frame, flen, "TX");
}

static void report_frame(const uint8_t *f, size_t total) {
    tag();
    if (f[0] == 0xb0 && total >= 6 && f[4] == 0x16 && f[5] == 0x03) {
        printf("*** TLS RECORD (%zu B) ***\n", total);
    } else if (f[4] == 0xb0) {
        printf("ACK for cmd 0x%02x\n", total >= 9 ? f[7] : 0);
    } else {
        printf("frame %zu B cmd=0x%02x :", total, f[4]);
        for (size_t k = 0; k < total && k < 48; k++) printf(" %02x", f[k]);
        if (total > 48) printf(" ...");
        printf("\n");
    }
    if (total >= 28 && f[4] == 0xae && f[5] == 0x15) {
        g_mcu_tls = (f[8] >> 1) & 1;
        printf("    [mcu: ver=%d tls=%d tail=%02x%02x]\n", f[7], g_mcu_tls, f[25], f[26]);
    }
    fflush(stdout);
}

// parse frames out of a byte stream accumulator; returns frames consumed
static uint8_t exit_prefix[8];
static size_t exit_prefix_len = 0;
static int exit_hit = 0;

static int parse_stream(uint8_t *acc, size_t *accn) {
    int nf = 0;
    for (;;) {
        size_t i = 0, hit = 0;
        while (i + 4 <= *accn) {
            uint8_t b0 = acc[i];
            if ((b0 == 0xa0 || b0 == 0xb0 || b0 == 0xc0) &&
                ((b0 + acc[i+1] + acc[i+2]) & 0xff) == acc[i+3]) {
                size_t total = 4 + (size_t)acc[i+1] + ((size_t)acc[i+2] << 8);
                if (total >= 6 && total <= 65536 && i + total <= *accn) {
                    save_frame(acc + i, total, "RX");
                    report_frame(acc + i, total);
                    nf++;
                    if (CH_msg_len == 0 && total == 56 && acc[i + 4] == 0x16 && acc[i + 9] == 0x01) {
                        memcpy(CH_msg, acc + i + 9, 47); CH_msg_len = 47;
                    }
                    if (CKE_msg_len == 0 && total == 30 && acc[i + 4] == 0x16 && acc[i + 9] == 0x10) {
                        memcpy(CKE_msg, acc + i + 9, 21); CKE_msg_len = 21;
                    }
                    if (total == 24 && acc[i + 4] == 0x36 && acc[i + 5] == 0x11) {
                        memcpy(g_fdt_frame, acc + i, 24); g_fdt_ok = 1;
                    }
                    if (exit_prefix_len && total >= exit_prefix_len &&
                        memcmp(acc + i, exit_prefix, exit_prefix_len) == 0)
                        exit_hit = 1;
                    memmove(acc, acc + i + total, *accn - i - total);
                    *accn -= i + total;
                    hit = 1;
                    break;
                }
            }
            i++;
        }
        if (!hit) break;
    }
    return nf;
}

static void set_exit(const char *hex) {
    exit_prefix_len = hex2bin(hex, exit_prefix, sizeof(exit_prefix));
    exit_hit = 0;
}

static int read_phase(const char *label, double seconds) {
    uint8_t acc[65536]; size_t accn = 0;
    double t0 = now_s();
    int nf = 0;
    tag(); printf("--- %s (%.1fs) ---\n", label, seconds);
    while (now_s() - t0 < seconds && !exit_hit) {
        uint8_t tx[64], rx[64];
        memset(tx, 0, 64); tx[0] = 0xbb; tx[1] = 0xf1;
        if (xfer(tx, rx, 64) < 0) break;
        if (accn + 60 < sizeof(acc)) { memcpy(acc + accn, rx + 4, 60); accn += 60; }
        nf += parse_stream(acc, &accn);
        if (accn > 48000) { memmove(acc, acc + 4096, accn - 4096); accn -= 4096; }
        usleep(1000);
    }
    return nf;
}

static int send_cmd(const char *name, const char *hex, int drain) {
    uint8_t f[1024];
    size_t fl = hex2bin(hex, f, sizeof(f));
    if (fl < 6) return 0;
    tag(); printf(">> %s (%zu B)\n", name, fl);
    write_milan(f, fl);
    usleep(4000);
    int nf = 0;
    uint8_t acc[8192]; size_t accn = 0;
    for (int r = 0; r < drain; r++) {
        uint8_t tx[64], rx[64];
        memset(tx, 0, 64); tx[0] = 0xbb; tx[1] = 0xf1;
        if (xfer(tx, rx, 64) < 0) break;
        if (accn + 60 < sizeof(acc)) { memcpy(acc + accn, rx + 4, 60); accn += 60; }
        nf += parse_stream(acc, &accn);
        usleep(1000);
    }
    return nf;
}

// ---- capture phase: interleave scheduled writes with gpio-paced parcel reads ----
struct sched { double at; const char *name; const char *hex; };
static const struct sched CAPTURE[] = {
    {0.014, "36-fdt1",  "a01200b2360f000901b0b0c0c0a7a7b9b9aeaebebee3"},
    {0.045, "50-nav",   "a00600a6500300010056"},
    {0.077, "36-fdt2",  "a01200b2360f00090180b080c180a780b880ad80be20"},
    {0.109, "82-regrw", "a00900a982060000820002009e"},
    {0.141, "20-image", "a00600a6200300010086"},
};

static const struct sched FINGER[] = {
    {0.014, "34-arm",   "a01200b2340f000a01808980a7808a809280818090ff"},
    {0.045, "36-fdt2",  "a01200b2360f00090180b080c180a780b880ad80be20"},
    {0.077, "20-image", "a00600a6200300010086"},
};


static const struct sched *g_sched = CAPTURE;
static int g_nsched = (int)(sizeof(CAPTURE)/sizeof(CAPTURE[0]));

static void capture_phase(double seconds, long max_parcels) {
    double t0 = now_s();
    size_t si = 0;
    long got = 0;
        tag(); printf("--- capture phase (%.1fs, max %ld parcels) ---\n", seconds, max_parcels);
    while (now_s() - t0 < seconds && got < max_parcels) {
        double el = now_s() - t0;
        while (si < (size_t)g_nsched && el >= g_sched[si].at) {
            tag(); printf(">> %s @+%.0fms\n", g_sched[si].name, g_sched[si].at * 1000);
            uint8_t f[64]; size_t fl = hex2bin(g_sched[si].hex, f, sizeof(f));
            write_milan(f, fl);
            si++;
        }
        struct pollfd pfd = { .fd = gfd, .events = POLLIN };
        int pr = poll(&pfd, 1, 1);
        if (pr <= 0) continue;
        struct gpio_v2_line_event ev;
        if (read(gfd, &ev, sizeof(ev)) < 0) continue;

        uint8_t st1[4], w1[256];
        if (parcel_read(st1, w1) < 0) break;
        // ONE read per pulse (Windows ISR cadence; reads consume the stream)
        uint64_t us = now_us();
        fwrite(&us, 8, 1, parcels_fp);
        fwrite(st1, 1, 4, parcels_fp);
        fwrite(w1, 1, 256, parcels_fp);
        fflush(parcels_fp);
        got++;
        printf("p%03ld st=%02x%02x%02x%02x win:", got-1, st1[0], st1[1], st1[2], st1[3]);
        for (int k = 0; k < 16; k++) printf(" %02x", w1[k]);
        // scan window for frame heads at any offset
        for (int off = 0; off + 4 <= 256; off++) {
            uint8_t b0 = w1[off];
            if ((b0 == 0xa0 || b0 == 0xb0 || b0 == 0xc0) &&
                ((b0 + w1[off+1] + w1[off+2]) & 0xff) == w1[off+3]) {
                size_t tot = 4 + (size_t)w1[off+1] + ((size_t)w1[off+2] << 8);
                printf(" [head@%d type=%02x len=%zu%s]", off, b0, tot,
                       (b0 == 0xa0 && tot == 10 && w1[off+4] == 0xb0) ? " ACK" : "");
                if (b0 == 0xa0 && tot == 10 && w1[off+4] == 0xb0)
                    printf(" [acked=0x%02x]", off + 6 + 2 <= 255 ? w1[off + 8] : 0);
                break;
            }
        }
        printf("\n");
        fflush(stdout);
    }
    fflush(parcels_fp);
    printf("=== capture phase done: %ld parcels ===\n", got);
}

static int process_parcels(const char *pfx) {
    char pth[512];
    snprintf(pth, sizeof(pth), "%s.parcels.bin", pfx);
    FILE *f = fopen(pth, "rb");
    if (!f) { tag(); printf("!! no parcels file\n"); return -1; }
    fseek(f, 0, SEEK_END); long sz = ftell(f); fseek(f, 0, SEEK_SET);
    long n = sz / 268;
    uint8_t *pb = malloc(n * 268);
    if (!pb) { fclose(f); return -1; }
    if (fread(pb, 268, n, f) != (size_t)n) { fclose(f); free(pb); return -1; }
    fclose(f);
    int img_idx = -1, nav_idx = -1;
    for (long i = 0; i < n; i++) {
        uint8_t *w = pb + i * 268 + 12;
        if (img_idx < 0 && memcmp(w, "\xb0\x45\x1e\x13", 4) == 0) img_idx = (int)i;
        if (nav_idx < 0 && memcmp(w, "\xa0\x6d\x09\x16", 4) == 0) nav_idx = (int)i;
    }
    tag(); printf("parcels %ld: image@p%d nav@p%d\n", n, img_idx, nav_idx);
    if (img_idx < 0) { tag(); printf("!! no image record in parcels\n"); free(pb); return -1; }
    uint8_t frame[8192]; size_t flen = 0;
    uint8_t *w0 = pb + img_idx * 268 + 12;
    size_t expected = 4 + (size_t)w0[1] + ((size_t)w0[2] << 8);
    for (long i = img_idx; i < n && flen < expected; i++) {
        size_t take = 256; if (flen + take > expected) take = expected - flen;
        memcpy(frame + flen, pb + i * 268 + 12, take); flen += take;
    }
    int cok = ((frame[0] + frame[1] + frame[2]) & 0xff) == frame[3];
    tag(); printf("image frame %zu B (expect %zu) csum %s\n", flen, expected, cok ? "OK" : "BAD");
    if (nav_idx >= 0) {
        uint8_t nav[8192]; size_t nlen = 0;
        uint8_t *v0 = pb + nav_idx * 268 + 12;
        size_t nexpect = 4 + (size_t)v0[1] + ((size_t)v0[2] << 8);
        for (long i = nav_idx; i < n && nlen < nexpect; i++) {
            size_t take = 256; if (nlen + take > nexpect) take = nexpect - nlen;
            memcpy(nav + nlen, pb + i * 268 + 12, take); nlen += take;
        }
        snprintf(pth, sizeof(pth), "%s.nav.bin", pfx);
        FILE *nf = fopen(pth, "wb");
        if (nf) { fwrite(nav, 1, nlen, nf); fclose(nf); tag(); printf("nav saved %zu B -> %s\n", nlen, pth); }
    }
    if (flen >= 4 + 5 + 16 + 16 && frame[4] == 0x17) {
        const uint8_t *body = frame + 9;
        uint8_t pt[8192];
        int ptlen = aes_cbc_decrypt(g_cwk, body, body + 16, (flen - 4 - 5 - 16) & ~15u, pt);
        if (ptlen < 7696) { tag(); printf("!! decrypt failed (%d)\n", ptlen); free(pb); return -1; }
        if (memcmp(pt, "\x20\x0a\x1e\x00", 4) != 0)
            { tag(); printf("pt header %02x %02x %02x %02x (expect 20 0a 1e 00)\n", pt[0], pt[1], pt[2], pt[3]); }
        snprintf(pth, sizeof(pth), "%s.content.bin", pfx);
        FILE *cf = fopen(pth, "wb");
        if (cf) { fwrite(pt, 1, 7688, cf); fclose(cf); tag(); printf("content saved 7688 B -> %s\n", pth); }
    } else {
        tag(); printf("!! frame not a TLS app record\n"); free(pb); return -1;
    }
    free(pb);
    return 0;
}

int main(int argc, char **argv) {
    if (argc < 7) {
        fprintf(stderr, "usage: %s spidev gpiochipN line mode hz outprefix\n", argv[0]);
        return 2;
    }
    uint8_t mode = (uint8_t)strtoul(argv[4], 0, 0);
    HZ = (uint32_t)strtoul(argv[5], 0, 0);
    const char *pfx = argv[6];
    setvbuf(stdout, NULL, _IOLBF, 0);

    fd = open(argv[1], O_RDWR);
    if (fd < 0) { perror("spidev open"); return 1; }
    uint8_t bits = 8;
    ioctl(fd, SPI_IOC_WR_MODE, &mode);
    ioctl(fd, SPI_IOC_WR_BITS_PER_WORD, &bits);
    ioctl(fd, SPI_IOC_WR_MAX_SPEED_HZ, &HZ);

    int chip = open(argv[2], O_RDWR);
    if (chip < 0) { perror("gpiochip open"); return 1; }
    struct gpio_v2_line_request req;
    memset(&req, 0, sizeof(req));
    req.offsets[0] = (unsigned)atoi(argv[3]);
    req.num_lines = 1;
    req.config.flags = GPIO_V2_LINE_FLAG_INPUT | GPIO_V2_LINE_FLAG_EDGE_RISING;
    snprintf(req.consumer, sizeof(req.consumer), "cc-imageread");
    if (ioctl(chip, GPIO_V2_GET_LINE_IOCTL, &req) < 0) { perror("GPIO_V2_GET_LINE"); return 1; }
    gfd = req.fd;

    char path[512];
    snprintf(path, sizeof(path), "%s.frames.txt", pfx);
    frames_fp = fopen(path, "w");
    snprintf(path, sizeof(path), "%s.parcels.bin", pfx);
    parcels_fp = fopen(path, "wb");
    if (!frames_fp || !parcels_fp) { perror("fopen out"); return 1; }
    setvbuf(frames_fp, NULL, _IOLBF, 0);

    T0 = now_s();

    char cfg90[1024];
    {
        FILE *fp = fopen("/tmp/cc90.hex", "r");
        if (!fp) { fprintf(stderr, "missing /tmp/cc90.hex\n"); return 1; }
        if (!fgets(cfg90, sizeof(cfg90), fp)) return 1;
        fclose(fp);
        cfg90[strcspn(cfg90, "\r\n")] = 0;
    }

    // ---- probe: warm session? ----
    {
        uint8_t frb[16]; char hx[40];
        size_t flb = build_ae_frame(frb); ae_hex(hx, frb, flb);
        g_mcu_tls = -1;
        send_cmd("probe-ae", hx, 8);
    }
    uint8_t cr32[32], sr32[32];
    if (g_mcu_tls == 1 && load_session(cr32, sr32)) {
        tag(); printf("== warm session (tls=1, keys cached): skip init ==\n");
        derive_keys2(cr32, sr32);
    } else {
        tag(); printf("== cold start: init + live handshake ==\n");
    // ---- pre-TLS init (proven sequence; first frame is D5 session-cleanup) ----
    send_cmd("D5-cleanup",  "a00600a6d503000000d2", 12);
    send_cmd("A8-version",  "a00600a6a803000000ff", 12);
    send_cmd("97-Install",  "a00600a697030001010e", 12);
    {
        uint8_t frb[16]; char hx[40];
        size_t flb = build_ae_frame(frb); ae_hex(hx, frb, flb);
        send_cmd("AE-mcu-state", hx, 12);
    }
    send_cmd("A8-again",    "a00600a6a803000000ff", 12);
    send_cmd("E4-challenge","a00c00ace40900030002bb00000000fd", 16);
    send_cmd("A2-1",        "a00600a6a203000114f0", 12);
    send_cmd("82",          "a00900a982060000000004001e", 12);
    send_cmd("A6-s2h",      "a00600a6a60300000001", 16);
    send_cmd("A2-2",        "a00600a6a203000114f0", 12);
    send_cmd("70",          "a00600a6700300140023", 12);
    send_cmd("98",          "a00c00ac980900780bb900b800b7005e", 12);
    send_cmd("90-config",   cfg90, 20);
    send_cmd("D1",          "a00600a6d103000000d6", 12);

    // ---- TLS handshake: LIVE server flight (valid for the live client random) ----
    // The ClientHello usually arrives during the D1 drain (Windows: +16ms after D1).
    if (CH_msg_len != 47) {
        set_exit("b03400e4");
        read_phase("waiting for ClientHello", 2.0);
    }
    if (CH_msg_len != 47) { tag(); printf("!! CH not captured (len=%zu)\n", CH_msg_len); }
    else { tag(); printf("ClientHello captured during init (msg %zu B)\n", CH_msg_len); }
    {
        uint8_t fr2[256];
        size_t fl2 = build_sh(fr2);
        tag(); printf(">> ServerHello (live, %zu B)\n", fl2);
        write_milan(fr2, fl2);
        usleep(4000);
        fl2 = hex2bin("b00900b916030300040e000000", fr2, sizeof(fr2));
        tag(); printf(">> ServerHelloDone (%zu B)\n", fl2);
        write_milan(fr2, fl2);
        usleep(4000);
    }
    set_exit("b0550005");
    read_phase("sensor key-exchange/CCS/Finished", 1.5);
    if (CKE_msg_len != 21) { tag(); printf("!! CKE not captured (len=%zu)\n", CKE_msg_len); }
    derive_keys();
    usleep(100000);
    {
        uint8_t fr2[64];
        size_t fl2 = hex2bin("b00600b6140303000101", fr2, sizeof(fr2));
        tag(); printf(">> CCS (%zu B)\n", fl2);
        write_milan(fr2, fl2);
    }
    usleep(400000);
    {
        uint8_t fr2[256];
        size_t fl2 = build_finished(fr2);
        tag(); printf(">> Finished (live, %zu B)\n", fl2);
        write_milan(fr2, fl2);
    }
    read_phase("post-finished", 0.1);

    // ---- post-TLS session setup (Windows: +48ms, +48ms) ----
    send_cmd("D4-2",   "a00600a6d403000000d3", 6);
    {
        uint8_t frb[16]; char hx[40];
        size_t flb = build_ae_frame(frb); ae_hex(hx, frb, flb);
        send_cmd("AE-af", hx, 6);
        if (g_mcu_tls != 1) {
            usleep(20000);
            send_cmd("D5-retry", "a00600a6d503000000d2", 6);
            usleep(20000);
            flb = build_ae_frame(frb); ae_hex(hx, frb, flb);
            send_cmd("AE-af-retry", hx, 6);
        }
    }

    // ---- capture sequence + parcel collection ----

    tag(); printf("== cc-imageread done ==\n");        save_session(CH_msg + 6, SR);
        if (g_mcu_tls != 1) { tag(); printf("!! tls=0 after handshake - abort\n"); return 1; }
    }

    // ---- phase A: background frame (sensor must be CLEAR) ----
    tag(); printf("== keep the sensor CLEAR (no finger) for the background frame ==\n");
    {
        int clear_ok = 0;
        for (int attempt = 0; attempt < 150 && !clear_ok; attempt++) {
            uint8_t fdtf[64];
            size_t flf = hex2bin("a01200b2360f000901b0b0c0c0a7a7b9b9aeaebebee3", fdtf, sizeof(fdtf));
            write_milan(fdtf, flf);
            usleep(4000);
            uint8_t acc2[4096]; size_t accn2 = 0; g_fdt_ok = 0;
            for (int r2 = 0; r2 < 12 && !g_fdt_ok; r2++) {
                uint8_t tx2[64], rx2[64];
                memset(tx2, 0, 64); tx2[0] = 0xbb; tx2[1] = 0xf1;
                if (xfer(tx2, rx2, 64) < 0) break;
                if (accn2 + 60 < sizeof(acc2)) { memcpy(acc2 + accn2, rx2 + 4, 60); accn2 += 60; }
                parse_stream(acc2, &accn2);
                usleep(1000);
            }
            if (g_fdt_ok) {
                int mean = 0;
                for (int k2 = 0; k2 < 6; k2++)
                    mean += g_fdt_frame[11 + 2 * k2] | (g_fdt_frame[12 + 2 * k2] << 8);
                mean /= 6;
                tag(); printf("clear-check mean 0x%03x%s\n", mean, mean >= 0x120 ? "  CLEAR" : "");
                if (mean >= 0x120) { clear_ok = 1; }
            }
            if (!clear_ok) usleep(150000);
        }
        if (!clear_ok) { tag(); printf("!! sensor never went clear\n"); return 1; }
    }
    /* ImageBase: the session-start capture (no finger) uses the full
     * boot/nav/finger-mode/read/regrw/image sequence - exactly like the
     * first capture in the Windows log. */
    {
        char pth[512];
        snprintf(pth, sizeof(pth), "%s.bg.parcels.bin", pfx);
        fclose(parcels_fp);
        parcels_fp = fopen(pth, "wb");
        if (!parcels_fp) { perror("fopen bg parcels"); return 1; }
    }
    tag(); printf("== capturing ImageBase (no finger) ==\n");
    capture_phase(4.0, 400);
    {
        char bp[512];
        snprintf(bp, sizeof(bp), "%s.bg", pfx);
        process_parcels(bp);
    }

    // ---- phase B: five finger frames, fresh press each ----
    for (int shot = 1; shot <= 5; shot++) {
        tag(); printf("== shot %d/5: press the finger FIRMLY ==\n", shot);
        int detected = 0;
        for (int attempt = 0; attempt < 200 && !detected; attempt++) {
            uint8_t fdtf[64];
            size_t flf = hex2bin("a01200b2360f000901b0b0c0c0a7a7b9b9aeaebebee3", fdtf, sizeof(fdtf));
            write_milan(fdtf, flf);
            usleep(4000);
            uint8_t acc2[4096]; size_t accn2 = 0; g_fdt_ok = 0;
            for (int r2 = 0; r2 < 12 && !g_fdt_ok; r2++) {
                uint8_t tx2[64], rx2[64];
                memset(tx2, 0, 64); tx2[0] = 0xbb; tx2[1] = 0xf1;
                if (xfer(tx2, rx2, 64) < 0) break;
                if (accn2 + 60 < sizeof(acc2)) { memcpy(acc2 + accn2, rx2 + 4, 60); accn2 += 60; }
                parse_stream(acc2, &accn2);
                usleep(1000);
            }
            if (g_fdt_ok) {
                int mean = 0;
                for (int k2 = 0; k2 < 6; k2++)
                    mean += g_fdt_frame[11 + 2 * k2] | (g_fdt_frame[12 + 2 * k2] << 8);
                mean /= 6;
                tag(); printf("fdt mean 0x%03x%s\n", mean, mean < 0x120 ? "  FINGER" : "");
                if (mean < 0x120) detected = 1;
            }
            if (!detected) usleep(120000);
        }
        if (!detected) { tag(); printf("!! no finger detected for shot %d\n", shot); return 1; }
        usleep(500000); /* settle like the driver */
        {
            char pth[512];
            snprintf(pth, sizeof(pth), "%s.cap%d.parcels.bin", pfx, shot);
            fclose(parcels_fp);
            parcels_fp = fopen(pth, "wb");
            if (!parcels_fp) { perror("fopen parcels"); return 1; }
        }
        tag(); printf("== capturing shot %d (34->36->20) ==\n", shot);
        g_sched = FINGER;
        g_nsched = (int)(sizeof(FINGER)/sizeof(FINGER[0]));
        capture_phase(4.0, 400);
        g_sched = CAPTURE;
        g_nsched = (int)(sizeof(CAPTURE)/sizeof(CAPTURE[0]));
        {
            char cp[512];
            snprintf(cp, sizeof(cp), "%s.cap%d", pfx, shot);
            process_parcels(cp);
        }
        tag(); printf("== LIFT the finger ==\n");
        usleep(800000);
    }

    tag(); printf("== cc-fing2 done ==\n");
    fclose(frames_fp);
    fclose(parcels_fp);
    close(fd);
    return 0;
}
