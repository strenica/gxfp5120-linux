/* SPDX-License-Identifier: LGPL-2.1-or-later
 *
 * GXFP5120 — session mount, FDT finger gating, capture + decrypt, features.
 * Ported from the proven bringup/cc-cap.c flow (see PORT-PLAN §13/§14).
 */
#include "gxfp5120.h"
#include "goodix_sift.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

/* Primary path is the fprintd StateDirectory (writable inside the service
 * sandbox; /tmp is private there). Fallback keeps manual-run compatibility. */
/* TLS session cache. Kept OUT of /var/lib/fprint: fprintd scans that
 * directory for per-user subdirs and probed the file as a username. */
#define GX_SESSION_FILE "/var/lib/gxfp5120/tls-session.txt"
#define GX_SESSION_FILE_ALT "/tmp/gxfp-session.txt"
#define GX_FDT_FRAME_HEX "a01200b2360f000901b0b0c0c0a7a7b9b9aeaebebee3"
#define GX_FDT_FINGER_MEAN 0x120
#define GX_GATE_STD 25.0
#define GX_MIN_KEYPOINTS 40

/* ---- small helpers ---- */

static size_t
hex2bin (const char *h, uint8_t *out, size_t max)
{
    size_t n = 0;
    for (const char *p = h; p[0] && p[1]; p += 2) {
        unsigned v;
        if (n >= max || sscanf (p, "%2x", &v) != 1)
            break;
        out[n++] = (uint8_t) v;
    }
    return n;
}

static size_t
build_ae_frame (uint8_t fr[16])
{
    /* mcu-state query MUST carry a live ms timestamp:
     * a0 09 00 a9 | af 06 00 | 55 <ms LE16> 00 00 | csum */
    uint16_t ts = (uint16_t) ((gx_now_us () / 1000) & 0xffff);
    uint8_t inner[9];

    inner[0] = 0xaf; inner[1] = 0x06; inner[2] = 0x00;
    inner[3] = 0x55;
    inner[4] = (uint8_t) (ts & 0xff);
    inner[5] = (uint8_t) (ts >> 8);
    inner[6] = 0; inner[7] = 0;
    inner[8] = (uint8_t) (0xAA - 0xaf - 0x06 - 0x00 - 0x55 - inner[4] - inner[5]);
    fr[0] = 0xa0; fr[1] = 0x09; fr[2] = 0x00;
    fr[3] = (uint8_t) ((0xa0 + 0x09) & 0xff);
    memcpy (fr + 4, inner, 9);
    return 13;
}

static gboolean
check_cancel (GxDev *d, GError **error)
{
    if (g_atomic_int_get (&d->cancelled)) {
        g_set_error (error, G_IO_ERROR, G_IO_ERROR_CANCELLED, "cancelled");
        return TRUE;
    }
    return FALSE;
}

/* ---- frame stream parser (as cc-cap parse_stream) ---- */

static void
parse_stream (GxDev *d, uint8_t *acc, size_t *accn)
{
    for (;;) {
        size_t i = 0, hit = 0;

        while (i + 4 <= *accn) {
            uint8_t b0 = acc[i];
            if ((b0 == 0xa0 || b0 == 0xb0 || b0 == 0xc0) &&
                ((b0 + acc[i + 1] + acc[i + 2]) & 0xff) == acc[i + 3]) {
                size_t total = 4 + (size_t) acc[i + 1] + ((size_t) acc[i + 2] << 8);
                if (total >= 6 && total <= 65536 && i + total <= *accn) {
                    if (d->tls.ch_len == 0 && total == 56 &&
                        acc[i + 4] == 0x16 && acc[i + 9] == 0x01) {
                        memcpy (d->tls.ch_msg, acc + i + 9, 47);
                        d->tls.ch_len = 47;
                        memcpy (d->tls.cr, acc + i + 9 + 6, 32);
                    }
                    if (d->tls.cke_len == 0 && total == 30 &&
                        acc[i + 4] == 0x16 && acc[i + 9] == 0x10) {
                        memcpy (d->tls.cke_msg, acc + i + 9, 21);
                        d->tls.cke_len = 21;
                    }
                    if (total == 24 && acc[i + 4] == 0x36 && acc[i + 5] == 0x11) {
                        memcpy (d->fdt_frame, acc + i, 24);
                        d->fdt_ok = TRUE;
                    }
                    if (total >= 28 && acc[i + 4] == 0xae && acc[i + 5] == 0x15)
                        d->ae_tls = (acc[i + 8] >> 1) & 1; /* payload[1] bit 0x02 */
                    if (d->exit_prefix_len && total >= d->exit_prefix_len &&
                        memcmp (acc + i, d->exit_prefix, d->exit_prefix_len) == 0)
                        d->exit_hit = TRUE;
                    memmove (acc, acc + i + total, *accn - i - total);
                    *accn -= i + total;
                    hit = 1;
                    break;
                }
            }
            i++;
        }
        if (!hit)
            break;
    }
}

/* one drain read: bb f1 + 64B transfer, 60 payload bytes */
static int
drain_read (GxDev *d, uint8_t *acc, size_t *accn, size_t acc_cap)
{
    uint8_t tx[64], rx[64];
    memset (tx, 0, sizeof (tx));
    tx[0] = 0xbb; tx[1] = 0xf1;
    if (gx_ec_xfer (&d->ec, tx, rx, 64) < 0)
        return -1;
    if (*accn + 60 < acc_cap) {
        memcpy (acc + *accn, rx + 4, 60);
        *accn += 60;
    }
    parse_stream (d, acc, accn);
    return 0;
}

static int
send_cmd (GxDev *d, const char *hex, int drain)
{
    uint8_t f[1024];
    size_t fl = hex2bin (hex, f, sizeof (f));
    uint8_t acc[8192];
    size_t accn = 0;

    if (fl < 6)
        return -1;
    gx_ec_write_milan (&d->ec, f, fl);
    g_usleep (4000);
    for (int r = 0; r < drain; r++) {
        if (drain_read (d, acc, &accn, sizeof (acc)) < 0)
            return -1;
        g_usleep (1000);
    }
    return 0;
}

static void
set_exit (GxDev *d, const char *hex)
{
    d->exit_prefix_len = hex2bin (hex, d->exit_prefix, sizeof (d->exit_prefix));
    d->exit_hit = FALSE;
}

/* full-rate read window, discard/parse everything, until timeout or the
 * exit frame prefix arrives (same cadence as bringup/cc-cap.c) */
static void
read_phase (GxDev *d, double seconds)
{
    uint8_t acc[65536];
    size_t accn = 0;
    double t0 = gx_now_s ();

    while (gx_now_s () - t0 < seconds && !d->exit_hit) {
        if (g_atomic_int_get (&d->cancelled))
            return;
        if (drain_read (d, acc, &accn, sizeof (acc)) < 0)
            return;
        if (accn > 48000) {
            memmove (acc, acc + 4096, accn - 4096);
            accn -= 4096;
        }
        g_usleep (1000);
    }
}

/* ---- config ---- */

static gboolean
load_hex_file (const char *path, uint8_t *out, size_t max, size_t *out_len)
{
    char line[4096];
    FILE *fp = fopen (path, "r");
    if (!fp)
        return FALSE;
    if (!fgets (line, sizeof (line), fp)) {
        fclose (fp);
        return FALSE;
    }
    fclose (fp);
    line[strcspn (line, "\r\n")] = 0;
    *out_len = hex2bin (line, out, max);
    return *out_len > 0;
}

static const char *cfg_paths[] = {
    "/etc/gxfp5120/cc90.hex",
    "cc90.hex",
};

static gboolean
load_cfg90 (GxDev *d, GError **error)
{
    const char *env = g_getenv ("GXFP5120_CONFIG");

    if (env && *env && load_hex_file (env, d->cfg90, sizeof (d->cfg90), &d->cfg90_len))
        return TRUE;
    for (size_t i = 0; i < G_N_ELEMENTS (cfg_paths); i++)
        if (load_hex_file (cfg_paths[i], d->cfg90, sizeof (d->cfg90), &d->cfg90_len))
            return TRUE;
    g_set_error (error, G_IO_ERROR, G_IO_ERROR_NOT_FOUND,
                 "90-config frame not found (tried $GXFP5120_CONFIG, %s)",
                 cfg_paths[0]);
    return FALSE;
}

/* ---- mount ---- */

static gboolean
mount_cold (GxDev *d, GError **error)
{
    char cfg_hex[2048];
    uint8_t fr[256];
    size_t fl;

    gx_tls_clear (&d->tls);

    send_cmd (d, "a00600a6d503000000d2", 12);  /* D5 session-cleanup */
    send_cmd (d, "a00600a6a803000000ff", 12);  /* A8 version */
    send_cmd (d, "a00600a697030001010e", 12);  /* 97 install */
    fl = build_ae_frame (fr);
    {
        char hx[40];
        for (size_t k = 0; k < fl; k++)
            sprintf (hx + 2 * k, "%02x", fr[k]);
        hx[2 * fl] = 0;
        send_cmd (d, hx, 12);
    }
    send_cmd (d, "a00600a6a803000000ff", 12);  /* A8 again */
    send_cmd (d, "a00c00ace40900030002bb00000000fd", 16);  /* E4 challenge */
    send_cmd (d, "a00600a6a203000114f0", 12);  /* A2-1 */
    send_cmd (d, "a00900a982060000000004001e", 12);  /* 82 */
    send_cmd (d, "a00600a6a60300000001", 16);  /* A6 s2h */
    send_cmd (d, "a00600a6a203000114f0", 12);  /* A2-2 */
    send_cmd (d, "a00600a6700300140023", 12);  /* 70 */
    send_cmd (d, "a00c00ac980900780bb900b800b7005e", 12);  /* 98 */
    for (size_t k = 0; k < d->cfg90_len; k++)
        sprintf (cfg_hex + 2 * k, "%02x", d->cfg90[k]);
    cfg_hex[2 * d->cfg90_len] = 0;
    send_cmd (d, cfg_hex, 20);                 /* 90 config */
    send_cmd (d, "a00600a6d103000000d6", 12);  /* D1 */

    /* ClientHello arrives during/after the D1 drain */
    if (d->tls.ch_len != 47) {
        set_exit (d, "b03400e4");
        read_phase (d, 2.0);
    }
    if (d->tls.ch_len != 47) {
        g_set_error (error, G_IO_ERROR, G_IO_ERROR_FAILED,
                     "ClientHello not captured");
        return FALSE;
    }
    g_debug ("mount: ClientHello captured (%zu)", d->tls.ch_len);

    fl = gx_tls_build_sh (&d->tls, fr);
    gx_ec_write_milan (&d->ec, fr, fl);
    g_usleep (4000);
    fl = gx_tls_build_shd (fr);
    gx_ec_write_milan (&d->ec, fr, fl);
    g_usleep (4000);

    /* sensor CKE / CCS / Finished flight: read until the sensor's own
     * Finished record (b0550005) is seen, exactly like cc-cap. A cold
     * sensor after power-on can take several seconds for this. */
    set_exit (d, "b0550005");
    for (int i = 0; i < 6 && d->tls.cke_len != 21 && !d->exit_hit; i++)
        read_phase (d, 1.0);
    if (d->tls.cke_len != 21) {
        g_set_error (error, G_IO_ERROR, G_IO_ERROR_FAILED,
                     "client key exchange not captured");
        return FALSE;
    }
    g_debug ("mount: CKE captured, sensor finished seen=%d", d->exit_hit);

    gx_tls_derive (&d->tls);
    g_usleep (100000);
    fl = gx_tls_build_ccs (fr);
    gx_ec_write_milan (&d->ec, fr, fl);
    g_usleep (400000);
    fl = gx_tls_build_finished (&d->tls, fr);
    if (fl == 0) {
        g_set_error (error, G_IO_ERROR, G_IO_ERROR_FAILED, "finished build failed");
        return FALSE;
    }
    gx_ec_write_milan (&d->ec, fr, fl);
    read_phase (d, 0.1);

    /* post-TLS session setup */
    send_cmd (d, "a00600a6d403000000d3", 6);   /* D4-2 */
    d->ae_tls = -1;
    {
        char hx[40];
        fl = build_ae_frame (fr);
        for (size_t k = 0; k < fl; k++)
            sprintf (hx + 2 * k, "%02x", fr[k]);
        hx[2 * fl] = 0;
        send_cmd (d, hx, 6);
        if (d->ae_tls != 1) {
            g_usleep (20000);
            send_cmd (d, "a00600a6d503000000d2", 6);
            g_usleep (20000);
            fl = build_ae_frame (fr);
            for (size_t k = 0; k < fl; k++)
                sprintf (hx + 2 * k, "%02x", fr[k]);
            hx[2 * fl] = 0;
            send_cmd (d, hx, 6);
        }
    }
    g_debug ("mount: post-finished AE tls=%d", d->ae_tls);
    if (d->ae_tls != 1) {
        g_set_error (error, G_IO_ERROR, G_IO_ERROR_FAILED,
                     "sensor did not mount (tls=0)");
        return FALSE;
    }
    gx_tls_save_session (&d->tls, GX_SESSION_FILE);
    d->mounted = TRUE;
    return TRUE;
}

gboolean
gx_dev_ensure_mounted (GxDev *d, GError **error)
{
    uint8_t fr[16];
    char hx[40];
    size_t fl;

    fl = build_ae_frame (fr);
    for (size_t k = 0; k < fl; k++)
        sprintf (hx + 2 * k, "%02x", fr[k]);
    hx[2 * fl] = 0;
    d->ae_tls = -1;
    send_cmd (d, hx, 8);

    if (d->ae_tls == 1) {
        if (d->tls.have_keys) {
            d->mounted = TRUE;
            return TRUE;
        }
        if (d->tls.have_psk &&
            (gx_tls_load_session (&d->tls, GX_SESSION_FILE) ||
             gx_tls_load_session (&d->tls, GX_SESSION_FILE_ALT))) {
            gx_tls_derive (&d->tls);
            d->mounted = TRUE;
            return TRUE;
        }
        /* mounted sensor but lost keys: re-init */
    }

    d->mounted = FALSE;
    return mount_cold (d, error);
}

/* ---- finger detection ---- */

static gboolean
fdt_probe (GxDev *d, int *mean)
{
    uint8_t fdtf[64];
    size_t flf = hex2bin (GX_FDT_FRAME_HEX, fdtf, sizeof (fdtf));
    uint8_t acc[4096];
    size_t accn = 0;

    gx_ec_write_milan (&d->ec, fdtf, flf);
    g_usleep (4000);
    d->fdt_ok = FALSE;
    for (int r = 0; r < 12 && !d->fdt_ok; r++) {
        if (drain_read (d, acc, &accn, sizeof (acc)) < 0)
            return FALSE;
        g_usleep (1000);
    }
    if (!d->fdt_ok)
        return FALSE;
    int m = 0;
    for (int k = 0; k < 6; k++)
        m += d->fdt_frame[11 + 2 * k] | (d->fdt_frame[12 + 2 * k] << 8);
    *mean = m / 6;
    return TRUE;
}

gboolean
gx_dev_wait_finger (GxDev *d, GError **error)
{
    int mean;

    /* flush stale stream from a previous operation so old FDT replies
     * cannot trigger a capture on the spot */
    {
        uint8_t acc[4096];
        size_t accn = 0;
        double t0 = gx_now_s ();
        while (gx_now_s () - t0 < 0.12)
            drain_read (d, acc, &accn, sizeof (acc));
    }

    /* phase 1: if a finger is already resting on the sensor, wait (bounded)
     * for a lift, so every operation starts from a fresh press */
    for (int waited = 0; waited < 5000; waited += 120) {
        if (check_cancel (d, error))
            return FALSE;
        if (!fdt_probe (d, &mean)) {
            g_usleep (120000);
            continue;
        }
        if (mean >= GX_FDT_FINGER_MEAN)
            break;
        g_usleep (120000);
    }

    /* phase 2: wait for the press, then let the contact settle */
    for (;;) {
        if (check_cancel (d, error))
            return FALSE;
        if (!fdt_probe (d, &mean)) {
            g_usleep (120000);
            continue;
        }
        if (mean < GX_FDT_FINGER_MEAN)
            break;
        g_usleep (120000);
    }

    /* first contact is often a partial blob; wait for the press to settle
     * and confirm the finger is still down before arming the capture */
    g_usleep (500000);
    for (;;) {
        if (check_cancel (d, error))
            return FALSE;
        if (!fdt_probe (d, &mean))
            break; /* assume still down on read trouble */
        if (mean < GX_FDT_FINGER_MEAN)
            break;
        /* lifted mid-settle: back to waiting for a real press */
        for (;;) {
            if (check_cancel (d, error))
                return FALSE;
            if (!fdt_probe (d, &mean)) {
                g_usleep (120000);
                continue;
            }
            if (mean < GX_FDT_FINGER_MEAN) {
                g_usleep (500000);
                break;
            }
            g_usleep (120000);
        }
        break;
    }
    return TRUE;
}

/* ---- capture ---- */

struct sched {
    double at;
    const char *hex;
};

/* session-start capture (no finger): the full boot/nav/finger-mode sequence
 * seen as the first capture in the Windows log ("ImageBase") */
static const struct sched SCHED_IMAGEBASE[] = {
    { 0.014, "a01200b2360f000901b0b0c0c0a7a7b9b9aeaebebee3" },
    { 0.045, "a00600a6500300010056" },
    { 0.077, "a01200b2360f00090180b080c180a780b880ad80be20" },
    { 0.109, "a00900a982060000820002009e" },
    { 0.141, "a00600a6200300010086" },
};

/* every finger press after the session-start capture uses this short arm
 * (Windows log: 34-frame -> 36-finger-mode -> 20-image) */
static const struct sched SCHED_FINGER[] = {
    { 0.014, "a01200b2340f000a01808980a7808a809280818090ff" },
    { 0.045, "a01200b2360f00090180b080c180a780b880ad80be20" },
    { 0.077, "a00600a6200300010086" },
};

/* ---- live-FDT mode frames ----
 * The Windows driver derives the FDT operating parameters from the raw
 * baselines the device reports in its fdt replies (6x raw16 LE at offset 11
 * of the `a01400b4 36 11` frame) and re-sets the mode frames with them.
 * params[k] = raw_le16 >> 1, carried as "80 xx" pairs. Enabled by default;
 * set GXFP5120_LIVEFDT=0 to fall back to the frozen replay values.
 * Frame + checksums verified against the Windows driver debug log:
 *   header csum = (0xa0 + len_lo + len_hi) & 0xff
 *   inner  csum = (0xaa - cmd - sum(payload after cmd)) & 0xff      (2026-10-14)
 */
static size_t
build_mode_frame (char *hex, size_t hexcap, uint8_t cmd, const uint8_t sub[4],
                  const uint8_t params[6])
{
    uint8_t f[32];
    size_t n = 0;
    uint8_t sum = 0;

    f[n++] = 0xa0;
    f[n++] = 0x12; /* len_lo: 18 payload bytes */
    f[n++] = 0x00;
    f[n++] = (uint8_t) (0xa0 + 0x12 + 0x00);

    f[n++] = cmd;
    for (int i = 0; i < 4; i++)
        f[n++] = sub[i];
    for (int k = 0; k < 6; k++) {
        f[n++] = 0x80;
        f[n++] = params[k];
    }
    for (size_t i = 5; i < n; i++) /* everything after cmd */
        sum += f[i];
    f[n++] = (uint8_t) (0xaa - cmd - sum);

    for (size_t i = 0; i < n; i++)
        g_snprintf (hex + i * 2, hexcap - i * 2, "%02x", f[i]);
    return n;
}

/* returns SCHED_FINGER or a filled @buf with live-derived 34/36 frames.
 * The derived parameters are LOCKED at the first press of the fprintd
 * session: the raw baselines drift slightly between presses, and re-setting
 * per press made consecutive captures image under different setpoints
 * (same-hold frames matched at ~106 but separate presses only 2-10 --
 * 2026-10-14). One lock per session keeps the imaging regime stable. */
static const struct sched *
finger_sched_live (GxDev *d, struct sched buf[3], char h34[64], char h36[64])
{
    static const uint8_t sub34[4] = { 0x0f, 0x00, 0x0a, 0x01 };
    static const uint8_t sub36[4] = { 0x0f, 0x00, 0x09, 0x01 };
    static int live = -1;
    static gboolean locked = FALSE;
    static uint8_t params[6];

    if (live < 0) {
        const char *env = g_getenv ("GXFP5120_LIVEFDT");

        live = !(env && env[0] == '0'); /* on by default; =0 disables */
    }
    if (!live || !d->fdt_ok)
        return SCHED_FINGER;

    if (!locked) {
        for (int k = 0; k < 6; k++)
            params[k] = (uint8_t) ((d->fdt_frame[11 + 2 * k] |
                                    (d->fdt_frame[12 + 2 * k] << 8)) >> 1);
        locked = TRUE;
        g_debug ("live-fdt: locked params %02x %02x %02x %02x %02x %02x",
                 params[0], params[1], params[2], params[3], params[4],
                 params[5]);
    }

    build_mode_frame (h34, 64, 0x34, sub34, params);
    build_mode_frame (h36, 64, 0x36, sub36, params);

    memcpy (buf, SCHED_FINGER, sizeof (SCHED_FINGER));
    buf[0].hex = h34;
    buf[1].hex = h36;
    return buf;
}

#define GX_MAX_PARCELS 400
#define GX_IMG_HEAD_LEN 4

static gboolean
capture_run (GxDev *d, const struct sched *sch, int nsch, double dur,
             uint8_t content[GX_IMG_CONTENT_LEN], GError **error)
{
    size_t cap = GX_MAX_PARCELS * 256;
    uint8_t *stream = g_malloc (cap);
    size_t slen = 0, search_from = 0;
    long img_pos = -1;
    size_t img_expect = 0;
    double t0 = gx_now_s ();
    size_t si = 0;
    long got = 0;
    gboolean ok = FALSE;

    while (gx_now_s () - t0 < dur && got < GX_MAX_PARCELS) {
        if (check_cancel (d, error))
            goto out;

        double el = gx_now_s () - t0;
        while (si < (size_t) nsch && el >= sch[si].at) {
            uint8_t f[64];
            size_t fl = hex2bin (sch[si].hex, f, sizeof (f));
            gx_ec_write_milan (&d->ec, f, fl);
            si++;
        }

        if (gx_ec_wait_irq (&d->ec, 1) <= 0)
            continue;

        uint8_t st1[4], w1[256];
        if (gx_ec_parcel_read (&d->ec, st1, w1) < 0)
            break;
        got++;

        if (slen + 256 <= cap) {
            memcpy (stream + slen, w1, 256);
            slen += 256;
        }

        /* incremental search for the image record head (b0 45 1e 13) */
        if (img_pos < 0 && slen >= GX_IMG_HEAD_LEN) {
            for (size_t i = search_from; i + GX_IMG_HEAD_LEN <= slen; i++) {
                if (stream[i] == 0xb0 && stream[i + 1] == 0x45 &&
                    stream[i + 2] == 0x1e && stream[i + 3] == 0x13) {
                    img_pos = (long) i;
                    img_expect = 4 + (size_t) stream[i + 1] +
                                 ((size_t) stream[i + 2] << 8);
                    break;
                }
            }
            search_from = slen > 3 ? slen - 3 : 0;
        }
        if (img_pos >= 0 && slen >= (size_t) img_pos + img_expect) {
            ok = TRUE;
            break;
        }
    }

    if (ok) {
        uint8_t pt[8192];
        int ptlen = gx_tls_decrypt_app (&d->tls, stream + img_pos, img_expect,
                                        pt, sizeof (pt));
        if (ptlen < GX_IMG_CONTENT_LEN) {
            g_set_error (error, G_IO_ERROR, G_IO_ERROR_FAILED,
                         "image decrypt failed (%d)", ptlen);
            ok = FALSE;
        } else if (memcmp (pt, "\x20\x0a\x1e\x00", 4) != 0) {
            g_set_error (error, G_IO_ERROR, G_IO_ERROR_FAILED,
                         "image header mismatch");
            ok = FALSE;
        } else {
            memcpy (content, pt, GX_IMG_CONTENT_LEN);
        }
    } else if (!*error) {
        g_set_error (error, G_IO_ERROR, G_IO_ERROR_TIMED_OUT,
                     "no image record in %ld parcels", got);
    }

    if (ok && d->dump_dir) {
        static int seq;
        g_autofree char *p = g_strdup_printf ("%s/cap%03d.content.bin",
                                              d->dump_dir, ++seq);
        if (g_file_set_contents (p, (const char *) content, GX_IMG_CONTENT_LEN, NULL))
            g_debug ("dump: wrote %s", p);
        else
            g_debug ("dump: FAILED %s", p);
    }

out:
    g_free (stream);
    return ok;
}

gboolean
gx_dev_capture_image (GxDev *d, uint8_t content[GX_IMG_CONTENT_LEN], GError **error)
{
    struct sched live[3];
    char h34[64], h36[64];
    const struct sched *sch;

    g_usleep (80000);

    sch = finger_sched_live (d, live, h34, h36);

    if (capture_run (d, sch, G_N_ELEMENTS (SCHED_FINGER), 4.0,
                     content, error))
        return TRUE;

    if (check_cancel (d, error))
        return FALSE;

    /* maybe the session dropped between presses: re-mount and retry once */
    g_clear_error (error);
    if (!gx_dev_ensure_mounted (d, error))
        return FALSE;
    if (capture_run (d, sch, G_N_ELEMENTS (SCHED_FINGER), 4.0,
                     content, error))
        return TRUE;
    return FALSE;
}

/* ---- features ---- */

/* One capture attempt: capture + decode + quality gates + feature
 * extraction. On failure @error is set and the attempt is retryable. */
static gboolean
capture_features_once (GxDev *d, const char *tag, void **out, GError **error)
{
    uint8_t content[GX_IMG_CONTENT_LEN];
    double img[GX_IMG_W * GX_IMG_H];
    double std, mn;

    if (!gx_dev_capture_image (d, content, error))
        return FALSE;

    gx_img_decode_content (content, img);

    std = gx_img_std (img, GX_IMG_W * GX_IMG_H);
    mn = gx_img_min (img, GX_IMG_W * GX_IMG_H);

    g_debug ("capture%s: raw std %.1f min %.0f", tag, std, mn);

    if (mn > GX_NOFINGER_MIN) {
        /* sensor returned a no-contact / mid-transition frame instead of
         * the finger; the caller re-captures while the finger is held */
        g_debug ("capture%s rejected: no finger in frame (min %.0f)", tag, mn);
        g_set_error (error, G_IO_ERROR, G_IO_ERROR_NOT_FOUND,
                     "no finger in frame");
        return FALSE;
    }

    if (std < GX_GATE_STD) {
        g_debug ("capture%s rejected: contrast %.1f (no finger?)", tag, std);
        g_set_error (error, G_IO_ERROR, G_IO_ERROR_NOT_FOUND, "low contrast");
        return FALSE;
    }

    gx_img_deband (img, GX_IMG_W, GX_IMG_H);

    int w, h;
    double *up = gx_img_upscale (img, GX_IMG_W, GX_IMG_H, GX_UPSCALE, &w, &h);
    GxSiftFeatures *f = gx_sift_extract (up, w, h);
    g_free (up);

    if (!f || gx_sift_keypoints (f) < GX_MIN_KEYPOINTS) {
        g_debug ("capture%s rejected: %u keypoints", tag,
                 f ? gx_sift_keypoints (f) : 0);
        gx_sift_free (f);
        g_set_error (error, G_IO_ERROR, G_IO_ERROR_NOT_FOUND, "few keypoints");
        return FALSE;
    }

    *out = f;
    return TRUE;
}

/* Capture one press into up to two feature sets from the same hold. The
 * second frame is a bonus: it stays NULL if it failed any quality gate.
 * Callers take the better match of the two, which removes most of the
 * per-press capture-quality luck (2026-10-14). */
gboolean
gx_dev_capture_features (GxDev *d, void **out_a, void **out_b, GError **error)
{
    for (int attempt = 0; attempt < 3; attempt++) {
        g_autoptr(GError) aerr = NULL;

        if (check_cancel (d, error))
            return FALSE;
        if (!gx_dev_ensure_mounted (d, error))
            return FALSE;
        if (attempt == 0) {
            if (!gx_dev_wait_finger (d, error))
                return FALSE;
            g_usleep (350000); /* let the contact settle after finger detect */
        } else {
            g_usleep (300000);
        }
        if (capture_features_once (d, "", out_a, &aerr))
            break;

        if (attempt == 2) {
            g_set_error (error, G_IO_ERROR, G_IO_ERROR_INVALID_DATA,
                         "no usable fingerprint capture (%s)",
                         aerr ? aerr->message : "unknown");
            return FALSE;
        }
    }

    /* bonus second frame from the same hold */
    *out_b = NULL;
    {
        g_autoptr(GError) berr = NULL;

        g_usleep (150000);
        if (!capture_features_once (d, " (2nd)", out_b, &berr))
            g_debug ("second capture unavailable: %s", berr->message);
    }

    return TRUE;
}

void
gx_dev_free_features (void *features)
{
    if (features)
        gx_sift_free (features);
}

int
gx_dev_match_features (void *probe, void *enrolled)
{
    return gx_sift_match (probe, enrolled);
}

unsigned
gx_dev_features_keypoints (void *features)
{
    return features ? gx_sift_keypoints (features) : 0;
}

/* ---- lifecycle ---- */

gboolean
gx_dev_open (GxDev *d, const char *spidev_override, GError **error)
{
    const char *env;

    env = g_getenv ("GXFP5120_SPIDEV");
    if (env && *env)
        d->spi_path = g_strdup (env);
    else if (spidev_override && *spidev_override)
        d->spi_path = g_strdup (spidev_override);
    else
        d->spi_path = g_strdup ("/dev/spidev0.0");
    env = g_getenv ("GXFP5120_GPIOCHIP");
    d->gpio_path = g_strdup (env && *env ? env : "/dev/gpiochip0");
    env = g_getenv ("GXFP5120_GPIO_LINE");
    d->gpio_line = env && *env ? atoi (env) : 17;
    env = g_getenv ("GXFP5120_SPI_HZ");
    d->spi_hz = env && *env ? (uint32_t) strtoul (env, NULL, 0) : 10000000;
    d->spi_mode = 0;
    d->dump_dir = g_getenv ("GXFP5120_DUMP_DIR");
    g_debug ("open: spidev=%s gpio=%s dump_dir=%s", d->spi_path, d->gpio_path,
             d->dump_dir && *d->dump_dir ? d->dump_dir : "(unset)");
    g_atomic_int_set (&d->cancelled, 0);

    if (gx_ec_open (&d->ec, d->spi_path, d->gpio_path, d->gpio_line,
                    d->spi_mode, d->spi_hz, error) < 0)
        return FALSE;
    d->ec_open = TRUE;

    if (!d->tls.have_psk && gx_tls_load_psk (&d->tls, error) < 0)
        return FALSE;
    if (!d->cfg90_len && !load_cfg90 (d, error))
        return FALSE;

    if (!gx_dev_ensure_mounted (d, error))
        return FALSE;

    /* Windows takes a session-start (no finger) capture before any press;
     * best-effort here - a failure must not block device open */
    {
        uint8_t scratch[GX_IMG_CONTENT_LEN];
        g_autoptr(GError) ig_err = NULL;

        if (capture_run (d, SCHED_IMAGEBASE, G_N_ELEMENTS (SCHED_IMAGEBASE),
                         4.0, scratch, &ig_err))
            g_debug ("open: ImageBase capture done");
        else
            g_debug ("open: ImageBase capture skipped (%s)",
                     ig_err ? ig_err->message : "?");
    }

    return TRUE;
}

void
gx_dev_close (GxDev *d)
{
    if (d->ec_open)
        gx_ec_close (&d->ec);
    d->ec_open = FALSE;
}
