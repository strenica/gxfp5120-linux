/* SPDX-License-Identifier: LGPL-2.1-or-later
 *
 * GXFP5120 — live TLS 1.2 server flight (PSK-AES128-CBC-SHA256, suite 0x00AE).
 *
 * The sensor is the TLS client and validates our Finished before it will
 * mount; nothing about the Windows flight can be replayed (fresh random
 * from the sensor each session). Everything here mirrors the validated
 * implementation in bringup/cc-cap.c.
 */
#include "gxfp5120.h"

#include <fcntl.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

static void
rand_bytes (uint8_t *out, size_t n)
{
    FILE *f = fopen ("/dev/urandom", "rb");
    if (f) {
        size_t r = fread (out, 1, n, f);
        fclose (f);
        if (r == n)
            return;
    }
    for (size_t i = 0; i < n; i++)
        out[i] = (uint8_t) (gx_now_us () >> ((i % 8) * 8)) ^ (uint8_t) (0x5a + i * 7);
}

static void
hmac256 (const uint8_t *key, size_t klen, const uint8_t *in, size_t len,
         uint8_t out[32])
{
    unsigned int n;
    HMAC (EVP_sha256 (), key, (int) klen, in, len, out, &n);
}

/* RFC 5246 P_SHA256 */
static void
tls_prf (const uint8_t *secret, size_t slen, const char *label,
         const uint8_t *seed, size_t seedlen, uint8_t *out, size_t outlen)
{
    size_t ll = strlen (label);
    uint8_t ls[512];
    uint8_t a[32];
    size_t done = 0;

    memcpy (ls, label, ll);
    memcpy (ls + ll, seed, seedlen);
    hmac256 (secret, slen, ls, ll + seedlen, a);
    while (done < outlen) {
        uint8_t block[32], tmp[1024];
        memcpy (tmp, a, 32);
        memcpy (tmp + 32, ls, ll + seedlen);
        hmac256 (secret, slen, tmp, 32 + ll + seedlen, block);
        size_t take = (outlen - done) < 32 ? (outlen - done) : 32;
        memcpy (out + done, block, take);
        done += take;
        hmac256 (secret, slen, a, 32, a);
    }
}

static int
aes_cbc_encrypt (const uint8_t key[16], const uint8_t iv[16],
                 const uint8_t *in, size_t len, uint8_t *out)
{
    EVP_CIPHER_CTX *c = EVP_CIPHER_CTX_new ();
    int n = 0, f = 0;
    if (!c)
        return -1;
    if (EVP_EncryptInit_ex (c, EVP_aes_128_cbc (), NULL, key, iv) != 1 ||
        EVP_CIPHER_CTX_set_padding (c, 0) != 1 ||
        EVP_EncryptUpdate (c, out, &n, in, (int) len) != 1 ||
        EVP_EncryptFinal_ex (c, out + n, &f) != 1) {
        EVP_CIPHER_CTX_free (c);
        return -1;
    }
    EVP_CIPHER_CTX_free (c);
    return n + f;
}

static int
aes_cbc_decrypt (const uint8_t key[16], const uint8_t iv[16],
                 const uint8_t *in, size_t len, uint8_t *out)
{
    EVP_CIPHER_CTX *c = EVP_CIPHER_CTX_new ();
    int n = 0, f = 0;
    if (!c)
        return -1;
    if (EVP_DecryptInit_ex (c, EVP_aes_128_cbc (), NULL, key, iv) != 1 ||
        EVP_CIPHER_CTX_set_padding (c, 0) != 1 ||
        EVP_DecryptUpdate (c, out, &n, in, (int) len) != 1 ||
        EVP_DecryptFinal_ex (c, out + n, &f) != 1) {
        EVP_CIPHER_CTX_free (c);
        return -1;
    }
    EVP_CIPHER_CTX_free (c);
    return n + f;
}

/* ---- PSK ---- */

static const char *psk_paths[] = {
    "/etc/gxfp5120/psk.bin",
    "psk_raw32.bin",
};

int
gx_tls_load_psk (GxTls *t, GError **error)
{
    const char *env = g_getenv ("GXFP5120_PSK");
    FILE *f = NULL;

    if (env && *env)
        f = fopen (env, "rb");
    for (size_t i = 0; !f && i < G_N_ELEMENTS (psk_paths); i++)
        f = fopen (psk_paths[i], "rb");
    if (!f) {
        g_set_error (error, G_IO_ERROR, G_IO_ERROR_NOT_FOUND,
                     "PSK file not found (tried $GXFP5120_PSK, %s)",
                     psk_paths[0]);
        return -1;
    }
    t->psk_len = fread (t->psk, 1, sizeof (t->psk), f);
    fclose (f);
    if (t->psk_len != 32) {
        g_set_error (error, G_IO_ERROR, G_IO_ERROR_INVALID_DATA,
                     "PSK must be 32 bytes (got %zu)", t->psk_len);
        t->psk_len = 0;
        return -1;
    }
    t->have_psk = TRUE;
    return 0;
}

void
gx_tls_clear (GxTls *t)
{
    gboolean have_psk = t->have_psk;
    uint8_t psk[64];
    size_t psk_len = t->psk_len;

    memcpy (psk, t->psk, sizeof (psk));
    memset (t, 0, sizeof (*t));
    t->have_psk = have_psk;
    memcpy (t->psk, psk, sizeof (psk));
    t->psk_len = psk_len;
}

/* ---- server flight ---- */

size_t
gx_tls_build_sh (GxTls *t, uint8_t *frame)
{
    uint8_t sid[32];
    uint8_t h[81];
    size_t n = 0;

    rand_bytes (t->sr, 32);
    rand_bytes (sid, 32);

    h[n++] = 0x02; h[n++] = 0x00; h[n++] = 0x00; h[n++] = 0x4d;
    h[n++] = 0x03; h[n++] = 0x03;
    memcpy (h + n, t->sr, 32); n += 32;
    h[n++] = 0x20; memcpy (h + n, sid, 32); n += 32;
    h[n++] = 0x00; h[n++] = 0xae; h[n++] = 0x00;
    h[n++] = 0x00; h[n++] = 0x05;
    h[n++] = 0xff; h[n++] = 0x01; h[n++] = 0x00; h[n++] = 0x01; h[n++] = 0x00;
    memcpy (t->sh_msg, h, n);
    t->sh_len = n;

    size_t rec_len = 5 + n;
    frame[0] = 0xb0;
    frame[1] = (uint8_t) (rec_len & 0xff);
    frame[2] = (uint8_t) (rec_len >> 8);
    frame[3] = (uint8_t) ((0xb0 + frame[1] + frame[2]) & 0xff);
    frame[4] = 0x16; frame[5] = 0x03; frame[6] = 0x03;
    frame[7] = 0x00; frame[8] = (uint8_t) n;
    memcpy (frame + 9, h, n);
    return 4 + rec_len;
}

size_t
gx_tls_build_shd (uint8_t *frame)
{
    static const uint8_t shd[] = { 0xb0, 0x09, 0x00, 0xb9,
                                   0x16, 0x03, 0x03, 0x00, 0x04,
                                   0x0e, 0x00, 0x00, 0x00 };
    memcpy (frame, shd, sizeof (shd));
    return sizeof (shd);
}

size_t
gx_tls_build_ccs (uint8_t *frame)
{
    static const uint8_t ccs[] = { 0xb0, 0x06, 0x00, 0xb6,
                                   0x14, 0x03, 0x03, 0x00, 0x01, 0x01 };
    memcpy (frame, ccs, sizeof (ccs));
    return sizeof (ccs);
}

void
gx_tls_derive (GxTls *t)
{
    uint8_t prem[72];
    uint8_t seed[64], kseed[64], kb[96];
    size_t p = 0;

    g_return_if_fail (t->have_psk && t->psk_len == 32);

    /* RFC 4279 PSK premaster: len||zeros||len||psk */
    prem[p++] = 0x00; prem[p++] = (uint8_t) t->psk_len;
    memset (prem + p, 0, t->psk_len); p += t->psk_len;
    prem[p++] = 0x00; prem[p++] = (uint8_t) t->psk_len;
    memcpy (prem + p, t->psk, t->psk_len); p += t->psk_len;

    memcpy (seed, t->cr, 32);
    memcpy (seed + 32, t->sr, 32);
    tls_prf (prem, p, "master secret", seed, 64, t->master, 48);

    memcpy (kseed, t->sr, 32);
    memcpy (kseed + 32, t->cr, 32);
    tls_prf (t->master, 48, "key expansion", kseed, 64, kb, 96);

    memcpy (t->cmac, kb, 32);
    memcpy (t->smac, kb + 32, 32);
    memcpy (t->cwk, kb + 64, 16);
    memcpy (t->swk, kb + 80, 16);
    t->have_keys = TRUE;
}

size_t
gx_tls_build_finished (GxTls *t, uint8_t *frame)
{
    static const uint8_t shd_msg[4] = { 0x0e, 0x00, 0x00, 0x00 };
    EVP_MD_CTX *mc = EVP_MD_CTX_new ();
    uint8_t th[32], cvd[12], seed2[32];
    unsigned int thn = 0;
    uint8_t cfm[16] = { 0x14, 0x00, 0x00, 0x0c };
    uint8_t fin_msg[16] = { 0x14, 0x00, 0x00, 0x0c };
    uint8_t mac_in[29], hm[32], plain[64], ctbuf[80], iv[16];

    /* transcript so far (server side): CH + SH + SHD + CKE */
    EVP_DigestInit_ex (mc, EVP_sha256 (), NULL);
    EVP_DigestUpdate (mc, t->ch_msg, t->ch_len);
    EVP_DigestUpdate (mc, t->sh_msg, t->sh_len);
    EVP_DigestUpdate (mc, shd_msg, sizeof (shd_msg));
    EVP_DigestUpdate (mc, t->cke_msg, t->cke_len);
    EVP_DigestFinal_ex (mc, th, &thn);

    tls_prf (t->master, 48, "client finished", th, 32, cvd, 12);
    memcpy (cfm + 4, cvd, 12);

    /* server Finished transcript: ... + client-Finished message */
    EVP_DigestInit_ex (mc, EVP_sha256 (), NULL);
    EVP_DigestUpdate (mc, t->ch_msg, t->ch_len);
    EVP_DigestUpdate (mc, t->sh_msg, t->sh_len);
    EVP_DigestUpdate (mc, shd_msg, sizeof (shd_msg));
    EVP_DigestUpdate (mc, t->cke_msg, t->cke_len);
    EVP_DigestUpdate (mc, cfm, sizeof (cfm));
    EVP_DigestFinal_ex (mc, seed2, &thn);
    EVP_MD_CTX_free (mc);

    tls_prf (t->master, 48, "server finished", seed2, 32, fin_msg + 4, 12);

    /* MAC over TLS record header + Finished message */
    memset (mac_in, 0, 8);
    mac_in[8] = 0x16; mac_in[9] = 0x03; mac_in[10] = 0x03;
    mac_in[11] = 0x00; mac_in[12] = 0x10;
    memcpy (mac_in + 13, fin_msg, 16);
    hmac256 (t->smac, 32, mac_in, 29, hm);

    memcpy (plain, fin_msg, 16);
    memcpy (plain + 16, hm, 32);
    memset (plain + 48, 0x0f, 16);
    rand_bytes (iv, 16);
    if (aes_cbc_encrypt (t->swk, iv, plain, 64, ctbuf) != 64)
        return 0;

    frame[0] = 0xb0; frame[1] = 0x55; frame[2] = 0x00; frame[3] = 0x05;
    frame[4] = 0x16; frame[5] = 0x03; frame[6] = 0x03;
    frame[7] = 0x00; frame[8] = 0x50;
    memcpy (frame + 9, iv, 16);
    memcpy (frame + 25, ctbuf, 64);
    return 4 + 5 + 80;
}

int
gx_tls_decrypt_app (const GxTls *t, const uint8_t *frame, size_t flen,
                    uint8_t *pt, size_t pt_cap)
{
    if (flen < 4 + 5 + 16 + 16 || frame[4] != 0x17 || !t->have_keys)
        return -1;
    const uint8_t *body = frame + 9;
    size_t ct_len = (flen - 4 - 5 - 16) & ~(size_t) 15;
    if (ct_len > pt_cap)
        ct_len = (pt_cap) & ~(size_t) 15;
    return aes_cbc_decrypt (t->cwk, body, body + 16, ct_len, pt);
}

/* ---- session cache ---- */

void
gx_tls_save_session (const GxTls *t, const char *path)
{
    FILE *f = fopen (path, "w");
    if (!f)
        return;
    for (int k = 0; k < 32; k++)
        fprintf (f, "%02x", t->cr[k]);
    fprintf (f, "\n");
    for (int k = 0; k < 32; k++)
        fprintf (f, "%02x", t->sr[k]);
    fprintf (f, "\n");
    fclose (f);
}

gboolean
gx_tls_load_session (GxTls *t, const char *path)
{
    char l1[96], l2[96];
    FILE *f = fopen (path, "r");
    if (!f)
        return FALSE;
    if (!fgets (l1, sizeof (l1), f) || !fgets (l2, sizeof (l2), f)) {
        fclose (f);
        return FALSE;
    }
    fclose (f);
    for (int i = 0; i < 2; i++) {
        char *line = i == 0 ? l1 : l2;
        uint8_t *dst = i == 0 ? t->cr : t->sr;
        for (int k = 0; k < 32; k++) {
            unsigned v;
            if (sscanf (line + 2 * k, "%2x", &v) != 1)
                return FALSE;
            dst[k] = (uint8_t) v;
        }
    }
    return TRUE;
}
