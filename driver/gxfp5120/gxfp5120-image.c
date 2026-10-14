/* SPDX-License-Identifier: LGPL-2.1-or-later
 *
 * GXFP5120 — image pipeline: 6->4 unpack, display orientation, wire-row
 * banding removal, bilinear upscale. This is the pipeline validated in
 * PORT-PLAN §14 (genuine min 26 vs impostor max 12, gap +14).
 */
#include "gxfp5120.h"

#include <math.h>
#include <string.h>

void
gx_img_decode_content (const uint8_t content[GX_IMG_CONTENT_LEN],
                       double *out)
{
    /* content = 8B header (20 0a 1e 00 ...) + 7680B = 5120 px 12-bit */
    double px[GX_IMG_PIXELS_RAW];
    int n = 0;

    for (int i = 8; i + 5 < GX_IMG_CONTENT_LEN && n < GX_IMG_PIXELS_RAW; i += 6) {
        const uint8_t *c = content + i;
        px[n++] = ((c[0] & 0xf) << 8) | c[1];
        px[n++] = (c[3] << 4) | (c[0] >> 4);
        px[n++] = ((c[5] & 0xf) << 8) | c[2];
        px[n++] = (c[4] << 4) | (c[5] >> 4);
    }

    /* display orientation: disp[y*80+x] = wire[x*64+y];
     * drop the first 3 marker rows -> 80x61 */
    for (int y = 3; y < 64; y++)
        for (int x = 0; x < 80; x++)
            out[(y - 3) * GX_IMG_W + x] = px[x * 64 + y];
}

double
gx_img_std (const double *img, int n)
{
    double m = 0, v = 0;
    int i;

    for (i = 0; i < n; i++)
        m += img[i];
    m /= n;
    for (i = 0; i < n; i++) {
        double d = img[i] - m;
        v += d * d;
    }
    return sqrt (v / n);
}

double
gx_img_min (const double *img, int n)
{
    double m = img[0];

    for (int i = 1; i < n; i++)
        if (img[i] < m)
            m = img[i];
    return m;
}

static int
cmp_dbl (const void *a, const void *b)
{
    double da = *(const double *) a, db = *(const double *) b;
    return (da > db) - (da < db);
}

void
gx_img_deband (double *img, int w, int h)
{
    double buf[512];

    /* per-row then per-column median subtraction; kills the strong
     * per-wire-row stripe pattern present in every capture. */
    for (int y = 0; y < h; y++) {
        for (int x = 0; x < w; x++)
            buf[x] = img[(gsize) y * w + x];
        qsort (buf, w, sizeof (double), cmp_dbl);
        double m = buf[w / 2];
        for (int x = 0; x < w; x++)
            img[(gsize) y * w + x] -= m;
    }
    for (int x = 0; x < w; x++) {
        for (int y = 0; y < h; y++)
            buf[y] = img[(gsize) y * w + x];
        qsort (buf, h, sizeof (double), cmp_dbl);
        double m = buf[h / 2];
        for (int y = 0; y < h; y++)
            img[(gsize) y * w + x] -= m;
    }
}

double *
gx_img_upscale (const double *src, int sw, int sh, int scale,
                int *out_w, int *out_h)
{
    if (scale <= 1) {
        double *cpy = g_memdup2 (src, sizeof (double) * sw * sh);
        *out_w = sw;
        *out_h = sh;
        return cpy;
    }

    int dw = sw * scale, dh = sh * scale;
    double *out = g_malloc (sizeof (double) * dw * dh);

    for (int y = 0; y < dh; y++) {
        double fy = (y + 0.5) * sh / dh - 0.5;
        int y0 = (int) floor (fy);
        double wy = fy - y0;
        int y1 = CLAMP (y0 + 1, 0, sh - 1);
        y0 = CLAMP (y0, 0, sh - 1);
        for (int x = 0; x < dw; x++) {
            double fx = (x + 0.5) * sw / dw - 0.5;
            int x0 = (int) floor (fx);
            double wx = fx - x0;
            int x1 = CLAMP (x0 + 1, 0, sw - 1);
            x0 = CLAMP (x0, 0, sw - 1);
            out[(gsize) y * dw + x] =
                src[y0 * sw + x0] * (1 - wx) * (1 - wy) +
                src[y0 * sw + x1] * wx * (1 - wy) +
                src[y1 * sw + x0] * (1 - wx) * wy +
                src[y1 * sw + x1] * wx * wy;
        }
    }
    *out_w = dw;
    *out_h = dh;
    return out;
}
