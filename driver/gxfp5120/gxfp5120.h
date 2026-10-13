/* SPDX-License-Identifier: LGPL-2.1-or-later
 *
 * GXFP5120 (GF3658 "Milan" via ITE EC bridge) — shared driver definitions.
 *
 * Transport : ITE EC SPI bridge intercepted through /dev/spidevX.Y + GPIO IRQ
 *             line (raw uapi ioctls, same model as bringup/cc-cap.c).
 * TLS       : PSK-AES128-CBC-SHA256 (0x00AE), host = TLS server, sensor =
 *             client. Server flight is generated live per session.
 * Image     : one TLS record; plaintext = 8B header + 5120 px 12-bit.
 * Matcher   : mb13 SigFM (FAST-9 + BRIEF-256 + RANSAC), see goodix_sift.h.
 */
#pragma once

#include <stdint.h>
#include <stddef.h>
#include <glib.h>
#include <gio/gio.h>

#define GX_IMG_W 80
#define GX_IMG_H 61
#define GX_IMG_PIXELS_RAW 5120
#define GX_IMG_CONTENT_LEN 7688
#define GX_UPSCALE 2
#define GX_MATCH_THRESHOLD 40 /* in-session separation: genuine 61+, other finger <=37 */
#define GX_ZNCC_FLOOR 300  /* raster ZNCC sanity floor (junk-capture reject) */
#define GX_ENROLL_MIN_MATCH 10 /* a new view must match some prior view this well */
#define GX_ENROLL_STAGES 5

/* ---- transport ---- */

typedef struct {
    int fd;        /* spidev */
    int chip_fd;   /* gpiochip */
    int line_fd;   /* requested GPIO line event fd */
    uint32_t hz;
    uint8_t mode;
} GxEc;

int  gx_ec_open (GxEc *ec, const char *spidev, const char *gpiochip,
                 int line, uint8_t mode, uint32_t hz, GError **error);
void gx_ec_close (GxEc *ec);
int  gx_ec_xfer (GxEc *ec, const uint8_t *tx, uint8_t *rx, size_t len);
int  gx_ec_parcel_read (GxEc *ec, uint8_t st[4], uint8_t win[256]);
int  gx_ec_write_milan (GxEc *ec, const uint8_t *frame, size_t flen);
int  gx_ec_wait_irq (GxEc *ec, int timeout_ms);

double   gx_now_s (void);
uint64_t gx_now_us (void);

/* ---- TLS ---- */

typedef struct {
    gboolean  have_psk;
    uint8_t   psk[64];
    size_t    psk_len;
    uint8_t   sr[32];          /* our ServerHello random */
    uint8_t   cr[32];          /* sensor ClientHello random */
    uint8_t   master[48];
    uint8_t   cmac[32], smac[32], cwk[16], swk[16];
    uint8_t   ch_msg[64];  size_t ch_len;
    uint8_t   cke_msg[64]; size_t cke_len;
    uint8_t   sh_msg[96];  size_t sh_len;
    gboolean  have_keys;
} GxTls;

int      gx_tls_load_psk (GxTls *t, GError **error);
void     gx_tls_clear (GxTls *t);
size_t   gx_tls_build_sh (GxTls *t, uint8_t *frame);   /* generates sr */
size_t   gx_tls_build_shd (uint8_t *frame);
size_t   gx_tls_build_ccs (uint8_t *frame);
void     gx_tls_derive (GxTls *t);
size_t   gx_tls_build_finished (GxTls *t, uint8_t *frame);
int      gx_tls_decrypt_app (const GxTls *t, const uint8_t *frame,
                             size_t flen, uint8_t *pt, size_t pt_cap);
/* session cache: two hex lines (client random, server random) */
void     gx_tls_save_session (const GxTls *t, const char *path);
gboolean gx_tls_load_session (GxTls *t, const char *path);

/* ---- image pipeline ---- */

void         gx_img_decode_content (const uint8_t content[GX_IMG_CONTENT_LEN],
                                    double *out /* GX_IMG_W*GX_IMG_H */);
double       gx_img_std (const double *img, int n);
void         gx_img_deband (double *img, int w, int h);
double      *gx_img_upscale (const double *img, int w, int h, int scale,
                             int *out_w, int *out_h);

/* ---- protocol / capture flow ---- */

typedef struct {
    GxEc     ec;
    GxTls    tls;
    gboolean ec_open;
    gboolean mounted;             /* last AE probe said tls=1 and keys ready */
    volatile gint cancelled;

    uint8_t  fdt_frame[32];
    gboolean fdt_ok;
    int      ae_tls;              /* last mcu-state query: isTlsConnected bit */

    uint8_t  exit_prefix[8];
    size_t   exit_prefix_len;
    gboolean exit_hit;

    uint8_t  cfg90[1024];
    size_t   cfg90_len;
    const char *dump_dir;         /* optional debug dumps */

    char    *spi_path;
    char    *gpio_path;
    int      gpio_line;
    uint32_t spi_hz;
    uint8_t  spi_mode;
} GxDev;

gboolean gx_dev_open (GxDev *d, const char *spidev_override, GError **error);
void     gx_dev_close (GxDev *d);
gboolean gx_dev_ensure_mounted (GxDev *d, GError **error);
gboolean gx_dev_wait_finger (GxDev *d, GError **error);
gboolean gx_dev_capture_image (GxDev *d, uint8_t content[GX_IMG_CONTENT_LEN],
                               GError **error);

/* shared helpers (proto) */
gboolean gx_dev_capture_features (GxDev *d, void **out_features /* GxSiftFeatures */,
                                  GError **error);
void     gx_dev_free_features (void *features);
int      gx_dev_match_features (void *probe, void *enrolled);
unsigned gx_dev_features_keypoints (void *features);
