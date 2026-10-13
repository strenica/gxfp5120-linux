// gxfp-match.c — evaluate the mb13 FAST/BRIEF (SigFM) matcher on cc-cap
// captures: extract features from every <dir>/capN.content.bin and print the
// genuine/impostor score matrices + separation.
//
// The matcher = refs/mb13-godsquantum driver/goodix51a0 goodix_sift.c +
// fastbrief/sigfm.c (FAST-9 + unsteered BRIEF-256 + RANSAC rigid transform).
// gx_sift_extract does its own 1-99% percentile stretch + unsharp mask, so we
// feed raw 12-bit pixel values (native regime = 80x61 display orientation).
//
// build: gcc -O2 -o gxfp-match gxfp-match.c \
//          ../refs/mb13-godsquantum/fingerprint/driver/goodix51a0/goodix_sift.c \
//          ../refs/mb13-godsquantum/fingerprint/driver/goodix51a0/fastbrief/sigfm.c \
//          -I../refs/mb13-godsquantum/fingerprint/driver/goodix51a0 \
//          $(pkg-config --cflags --libs glib-2.0) -lm
// usage: gxfp-match <enroll_dir> <other_dir> [scale]
#include <glib.h>
#include <math.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dirent.h>

#include "goodix_sift.h"

#define W 80
#define H 61

static double *bilinear(const double *src, int sw, int sh, int dw, int dh) {
    double *out = g_malloc(sizeof(double) * dw * dh);
    for (int y = 0; y < dh; y++) {
        double fy = (y + 0.5) * sh / dh - 0.5;
        int y0 = (int)floor(fy);
        double wy = fy - y0;
        int y1 = CLAMP(y0 + 1, 0, sh - 1);
        y0 = CLAMP(y0, 0, sh - 1);
        for (int x = 0; x < dw; x++) {
            double fx = (x + 0.5) * sw / dw - 0.5;
            int x0 = (int)floor(fx);
            double wx = fx - x0;
            int x1 = CLAMP(x0 + 1, 0, sw - 1);
            x0 = CLAMP(x0, 0, sw - 1);
            out[(gsize)y * dw + x] =
                src[y0 * sw + x0] * (1 - wx) * (1 - wy) +
                src[y0 * sw + x1] * wx * (1 - wy) +
                src[y1 * sw + x0] * (1 - wx) * wy +
                src[y1 * sw + x1] * wx * wy;
        }
    }
    return out;
}

static int cmp_dbl(const void *a, const void *b) {
    double da = *(const double *)a, db = *(const double *)b;
    return (da > db) - (da < db);
}

// Banding removal variants, selected via $GXFP_VARIANT (default 0):
//  0: per-row + per-column MEDIAN subtraction (current driver)
//  1: per-row + per-column MEAN subtraction (full destripe)
//  2: variant 1 + z-score over the whole image
static int g_variant;
static void deband(double *img, int w, int h) {
    double buf[512];
    if (g_variant == 0) {
        for (int y = 0; y < h; y++) {
            for (int x = 0; x < w; x++) buf[x] = img[(gsize)y * w + x];
            qsort(buf, w, sizeof(double), cmp_dbl);
            double m = buf[w / 2];
            for (int x = 0; x < w; x++) img[(gsize)y * w + x] -= m;
        }
        for (int x = 0; x < w; x++) {
            for (int y = 0; y < h; y++) buf[y] = img[(gsize)y * w + x];
            qsort(buf, h, sizeof(double), cmp_dbl);
            double m = buf[h / 2];
            for (int y = 0; y < h; y++) img[(gsize)y * w + x] -= m;
        }
        return;
    }
    for (int y = 0; y < h; y++) {
        double s = 0;
        for (int x = 0; x < w; x++) s += img[(gsize)y * w + x];
        s /= w;
        for (int x = 0; x < w; x++) img[(gsize)y * w + x] -= s;
    }
    for (int x = 0; x < w; x++) {
        double s = 0;
        for (int y = 0; y < h; y++) s += img[(gsize)y * w + x];
        s /= h;
        for (int y = 0; y < h; y++) img[(gsize)y * w + x] -= s;
    }
    if (g_variant == 2) {
        double m = 0, v = 0;
        int n = w * h;
        for (int i = 0; i < n; i++) m += img[i];
        m /= n;
        for (int i = 0; i < n; i++) { double d = img[i] - m; v += d * d; }
        v = sqrt(v / n);
        if (v > 1e-9)
            for (int i = 0; i < n; i++) img[i] = (img[i] - m) / v;
    }
}

static double *decode_display(const char *path) {
    FILE *f = fopen(path, "rb");
    if (!f) return NULL;
    unsigned char data[7688];
    if (fread(data, 1, sizeof data, f) != sizeof data) { fclose(f); return NULL; }
    fclose(f);
    double px[5120];
    int n = 0;
    for (int i = 8; i + 5 < 7688 && n < 5120; i += 6) {
        const unsigned char *c = data + i;
        px[n++] = ((c[0] & 0xf) << 8) | c[1];
        px[n++] = (c[3] << 4) | (c[0] >> 4);
        px[n++] = ((c[5] & 0xf) << 8) | c[2];
        px[n++] = (c[4] << 4) | (c[5] >> 4);
    }
    double *raw = g_malloc(sizeof(double) * W * H);
    for (int y = 3; y < 64; y++)
        for (int x = 0; x < 80; x++)
            raw[(y - 3) * 80 + x] = px[x * 64 + y];
    return raw;
}

static double *g_bg;

static int gx_cmp_d(const void *a, const void *b) {
    double da = *(const double *)a, db = *(const double *)b;
    return (da > db) - (da < db);
}

/* mb13 adaptive54: recenter at the 54th percentile, clip negatives */
static void recenter54(double *img, int n) {
    double *s = g_memdup2(img, sizeof(double) * n);
    qsort(s, n, sizeof(double), gx_cmp_d);
    double p = s[(int)(0.54 * (n - 1))];
    g_free(s);
    for (int i = 0; i < n; i++) {
        img[i] -= p;
        if (img[i] < 0) img[i] = 0;
    }
}

static double *load_content(const char *path, int scale, int *out_w, int *out_h) {
    double *raw = decode_display(path);
    if (!raw) return NULL;
    if (g_variant == 5 || g_variant == 6)
        recenter54(raw, W * H);
    if (g_bg && g_variant != 6) {
        for (int i = 0; i < W * H; i++) {
            raw[i] -= g_bg[i];
            if (raw[i] < 0) raw[i] = 0;
        }
    }
    if (g_variant != 3)
        deband(raw, W, H);
    if (scale <= 1) { *out_w = W; *out_h = H; return raw; }
    int dw = W * scale, dh = H * scale;
    double *up = bilinear(raw, W, H, dw, dh);
    g_free(raw);
    *out_w = dw; *out_h = dh;
    return up;
}

static int cmp_str(const void *a, const void *b) {
    return strcmp((const char *)a, (const char *)b);
}

static int collect(const char *dir, char paths[][512], int max) {
    DIR *d = opendir(dir);
    if (!d) { fprintf(stderr, "opendir %s failed\n", dir); return 0; }
    struct dirent *e;
    int n = 0;
    while ((e = readdir(d)) && n < max) {
        if (!strstr(e->d_name, ".content.bin")) continue;
        snprintf(paths[n], 512, "%s/%s", dir, e->d_name);
        n++;
    }
    closedir(d);
    qsort(paths, n, 512, cmp_str);
    return n;
}

int main(int argc, char **argv) {
    if (argc < 3) { fprintf(stderr, "usage: %s enroll_dir other_dir [scale]\n", argv[0]); return 2; }
    int scale = argc > 3 ? atoi(argv[3]) : 1;
    const char *var = getenv("GXFP_VARIANT");
    g_variant = var ? atoi(var) : 0;
    {
        const char *bgp = getenv("GXFP_BG");
        if (bgp && *bgp) {
            g_bg = decode_display(bgp);
            if (g_bg) {
                recenter54(g_bg, W * H);
                printf("bg frame loaded (p54-recentered): %s\n", bgp);
            }
            else
                printf("bg frame FAILED to load: %s\n", bgp);
        }
    }
    char ep[64][512], op[64][512];
    int ne = collect(argv[1], ep, 64);
    int no = collect(argv[2], op, 64);
    printf("scale %d: enroll %d, other %d\n", scale, ne, no);
    GxSiftFeatures *E[64], *O[64];
    for (int i = 0; i < ne; i++) {
        int w, h;
        double *img = load_content(ep[i], scale, &w, &h);
        E[i] = img ? gx_sift_extract(img, w, h) : NULL;
        g_free(img);
        printf("  %s: %u keypoints\n", strrchr(ep[i], '/') + 1,
               E[i] ? gx_sift_keypoints(E[i]) : 0);
    }
    for (int j = 0; j < no; j++) {
        int w, h;
        double *img = load_content(op[j], scale, &w, &h);
        O[j] = img ? gx_sift_extract(img, w, h) : NULL;
        g_free(img);
        printf("  %s: %u keypoints\n", strrchr(op[j], '/') + 1,
               O[j] ? gx_sift_keypoints(O[j]) : 0);
    }
    if (getenv("GXFP_MATRIX")) {
        printf("matrix (rows=enroll, cols=other):\n     ");
        for (int j = 0; j < no; j++) printf("%4d", j);
        printf("\n");
        for (int i = 0; i < ne; i++) {
            printf("%3d: ", i);
            for (int j = 0; j < no; j++)
                printf("%4d", (E[i] && O[j]) ? gx_sift_match(E[i], O[j]) : -1);
            printf("\n");
        }
    }

    int gmin = 1 << 30, omax = -1;
    printf("--- genuine (max pair) ---\n");
    for (int i = 0; i < ne; i++) {
        int best = 0;
        for (int j = 0; j < ne; j++) {
            if (i == j || !E[i] || !E[j]) continue;
            int s = gx_sift_match(E[i], E[j]);
            if (s > best) best = s;
        }
        printf("  enroll[%2d] best = %d\n", i, best);
        if (best < gmin) gmin = best;
    }
    printf("--- impostor (max pair) ---\n");
    for (int j = 0; j < no; j++) {
        int best = 0;
        for (int i = 0; i < ne; i++) {
            if (!O[j] || !E[i]) continue;
            int s = gx_sift_match(O[j], E[i]);
            if (s > best) best = s;
        }
        printf("  other [%d] best = %d\n", j, best);
        if (best > omax) omax = best;
    }
    printf("\nSEPARATION: genuine min %d vs impostor max %d (gap %+d)\n", gmin, omax, gmin - omax);
    return 0;
}
