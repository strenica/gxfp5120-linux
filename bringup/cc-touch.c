// cc-touch.c — GXFP5120 (GF3658 Milan) ITE-bridge: arm finger-detection and
// auto-capture the image on touch. Replays the byte-exact Windows D0Entry +
// ChicagoHUSetMode sequence from the live EVTX log (10:43:17), then watches
// the read stream (bb f1, 64-byte chunks) and:
//   - decodes fdt frames (cmd 0x32/0x34/0x36) -> six LE16 values; finger => values drop
//   - on finger: writes 0x20 (get-one-frame) -> sensor streams image frame (cmd 0x20, ~7697 B)
//   - saves every image frame (payload) to /tmp/fp-image-N.bin
// Optional periodic re-arm (mode cycle) like the Windows driver does when idle.
//
// usage: cc-touch <node> <mode> <hz> [seconds] [rearm-seconds]
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <linux/spi/spidev.h>
#include <time.h>

static int fd;
static uint32_t HZ;
static double T0;
static int img_no = 0;
static double last_img_req = -1e9;
static long fdt_count = 0, finger_count = 0, img_count = 0, other_count = 0;

static double now_s(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return ts.tv_sec + ts.tv_nsec / 1e9;
}
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

static size_t hex2bin(const char *h, uint8_t *out, size_t max) {
    size_t n = 0;
    for (const char *p = h; p[0] && p[1]; p += 2) {
        unsigned v;
        if (n >= max || sscanf(p, "%2x", &v) != 1) break;
        out[n++] = (uint8_t)v;
    }
    return n;
}

// ITE wrapper write: [cc f2 #ctr LE16][milan frame][pad4]
static void write_milan(const uint8_t *frame, size_t flen) {
    uint8_t tx[512];
    if (flen > sizeof(tx) - 4) flen = sizeof(tx) - 4;
    tx[0] = 0xcc; tx[1] = 0xf2; tx[2] = 0x00; tx[3] = 0x01;
    memcpy(tx + 4, frame, flen);
    size_t pad = (4 - (flen & 3)) & 3;
    memset(tx + 4 + flen, 0, pad);
    uint8_t rx[512];
    if (xfer(tx, rx, 4 + flen + pad) < 0) perror("write xfer");
}

static void send_cmd(const char *name, const char *hex, int drain) {
    uint8_t f[512];
    size_t fl = hex2bin(hex, f, sizeof(f));
    tag(); printf(">> %s (%zu B) %s\n", name, fl, hex); fflush(stdout);
    write_milan(f, fl);
    usleep(4000);
    uint8_t acc[8192]; size_t accn = 0;
    for (int r = 0; r < drain; r++) {
        uint8_t tx[64], rx[64];
        memset(tx, 0, 64); tx[0] = 0xbb; tx[1] = 0xf1;
        if (xfer(tx, rx, 64) < 0) break;
        // each read: 4-byte exchange status cell + 60 bytes of stream (strip, like cc-capture)
        if (accn + 60 < sizeof(acc)) { memcpy(acc + accn, rx + 4, 60); accn += 60; }
        // scan + report + consume complete frames
        for (;;) {
            size_t i = 0, hit = 0;
            while (i + 4 <= accn) {
                uint8_t b0 = acc[i];
                if ((b0 == 0xa0 || b0 == 0xb0 || b0 == 0xc0) &&
                    ((b0 + acc[i+1] + acc[i+2]) & 0xff) == acc[i+3]) {
                    size_t total = 4 + (size_t)acc[i+1] + ((size_t)acc[i+2] << 8);
                    if (total >= 6 && total <= 8192 && i + total <= accn) {
                        tag(); printf("   rx: %zu B cmd=0x%02x\n", total, acc[i+4]);
                        if (acc[i+4] == 0xb0 && total >= 9)
                            printf("       ack for cmd 0x%02x\n", acc[i+7]);
                        fflush(stdout);
                        memmove(acc, acc + i + total, accn - i - total);
                        accn -= i + total;
                        hit = 1;
                        break;
                    }
                }
                i++;
            }
            if (!hit) break;
        }
        usleep(1000);
    }
}

static void handle_frame(uint8_t *f, size_t total) {
    uint8_t cmd = f[4];
    if (total == 24 && (cmd == 0x32 || cmd == 0x34 || cmd == 0x36)) {
        unsigned v[6];
        for (int j = 0; j < 6; j++) v[j] = f[11 + 2*j] | ((unsigned)f[12 + 2*j] << 8);
        unsigned sum = 0;
        for (int j = 0; j < 6; j++) sum += v[j];
        unsigned mean = sum / 6;
        fdt_count++;
        tag(); printf("FDT 0x%02x vals %04x %04x %04x %04x %04x %04x  mean 0x%03x",
                      cmd, v[0], v[1], v[2], v[3], v[4], v[5], mean);
        if (mean < 0x130) {
            printf("   *** FINGER ***\n");
            finger_count++;
            double now = now_s();
            if (now - last_img_req > 1.2) {
                last_img_req = now;
                printf("           -> requesting image (0x20)\n");
                uint8_t req[16];
                size_t rl = hex2bin("a00600a6200300010086", req, sizeof(req));
                write_milan(req, rl);
            }
        } else {
            printf("   (no finger)\n");
        }
    } else if (cmd == 0xb0) {
        other_count++;
        tag(); printf("ACK frame: ack for cmd 0x%02x\n", total >= 9 ? f[7] : 0);
    } else if (cmd == 0x20 && total > 1000) {
        img_count++;
        char path[128];
        snprintf(path, sizeof(path), "/tmp/fp-image-%d.bin", ++img_no);
        size_t datalen = total >= 8 ? total - 8 : 0;   // strip outer(4)+cmd+len(3)+csum(1)
        FILE *fp = fopen(path, "wb");
        if (fp) { fwrite(f + 7, 1, datalen, fp); fclose(fp); }
        tag(); printf("*** IMAGE %zu B (saved %zu B -> %s)\n", total, datalen, path);
        printf("           head:");
        for (size_t k = 0; k < 48 && k < total; k++) printf(" %02x", f[k]);
        printf("\n");
    } else {
        other_count++;
        tag(); printf("frame %zu B cmd=0x%02x :", total, cmd);
        for (size_t k = 0; k < 48 && k < total; k++) printf(" %02x", f[k]);
        if (total > 48) printf(" ...");
        printf("\n");
    }
    fflush(stdout);
}

int main(int argc, char **argv) {
    if (argc < 4) { fprintf(stderr, "usage: %s node mode hz [seconds] [rearm-seconds]\n", argv[0]); return 2; }
    uint8_t mode = (uint8_t)strtoul(argv[2], 0, 0);
    HZ = (uint32_t)strtoul(argv[3], 0, 0);
    int watch_s = argc > 4 ? atoi(argv[4]) : 300;
    int rearm_s = argc > 5 ? atoi(argv[5]) : 3;
    setvbuf(stdout, NULL, _IOLBF, 0);

    fd = open(argv[1], O_RDWR);
    if (fd < 0) { perror("open"); return 1; }
    uint8_t bits = 8;
    ioctl(fd, SPI_IOC_WR_MODE, &mode);
    ioctl(fd, SPI_IOC_WR_BITS_PER_WORD, &bits);
    ioctl(fd, SPI_IOC_WR_MAX_SPEED_HZ, &HZ);

    T0 = now_s();

    // ---- init (proven working, cc-init) — skipped with "noinit" to preserve a TLS session ----
    int noinit = (argc > 6 && strcmp(argv[6], "noinit") == 0);
    if (!noinit) {
        send_cmd("D4-unlock",   "a00600a6d503000000d2", 10);
        send_cmd("A8-version",  "a00600a6a803000000ff", 10);
        send_cmd("97-Install",  "a00600a697030001010e", 10);
        send_cmd("AE-mcu-state","a00900a9af0600555e3e000004000000", 10);

        // ---- arm sequence: byte-exact replay of Windows 10:43:17:045-361 ----
        send_cmd("36-setmode1", "a01200b2360f000901b0b0c0c0a7a7b9b9aeaebebee3", 12);
        send_cmd("50-navbase",  "a00600a6500300010056", 45);
        send_cmd("36-setmode2", "a01200b2360f00090180b080c180a780b880ad80be20", 12);
        send_cmd("82-?",         "a00900a982060000820002009e", 12);
        send_cmd("20-oneframe", "a00600a6200300010086", 12);
        send_cmd("36-setmode3", "a01200b2360f00090180b080c180a880b980af80be1c", 12);
        send_cmd("32-arm",      "a01400b4321100080180b180c280a880b980ae80bed1430a", 12);
    } else {
        tag(); printf("=== NOINIT: preserving existing session state ===\n");
    }

    tag(); printf("=== ARMED. Touch the sensor now. ===\n");
    if (rearm_s > 0) printf("    (fdt probe every %d s; fingers show as mean < 0x130; images -> /tmp/fp-image-N.bin)\n", rearm_s);
    printf("\n");

    // ---- watch ----
    double t0 = now_s(), next_rearm = rearm_s > 0 ? t0 + rearm_s : 1e18;
    uint8_t acc[65536]; size_t accn = 0;
    long reads = 0;
    while (now_s() - t0 < watch_s) {
        uint8_t tx[64], rx[64];
        memset(tx, 0, 64); tx[0] = 0xbb; tx[1] = 0xf1;
        if (xfer(tx, rx, 64) < 0) { perror("read"); break; }
        reads++;
        if (accn + 60 < sizeof(acc)) { memcpy(acc + accn, rx + 4, 60); accn += 60; }
        for (;;) {
            size_t i = 0, hit = 0;
            while (i + 4 <= accn) {
                uint8_t b0 = acc[i];
                if ((b0 == 0xa0 || b0 == 0xb0 || b0 == 0xc0) &&
                    ((b0 + acc[i+1] + acc[i+2]) & 0xff) == acc[i+3]) {
                    size_t total = 4 + (size_t)acc[i+1] + ((size_t)acc[i+2] << 8);
                    if (total >= 6 && total <= 8192 && i + total <= accn) {
                        uint8_t fb[8192];
                        memcpy(fb, acc + i, total);
                        memmove(acc, acc + i + total, accn - i - total);
                        accn -= i + total;
                        handle_frame(fb, total);
                        hit = 1;
                        break;
                    }
                }
                i++;
            }
            if (!hit) break;
        }
        if (accn > 48000) { memmove(acc, acc + 4096, accn - 4096); accn -= 4096; }

        if (rearm_s > 0 && now_s() > next_rearm) {
            next_rearm = now_s() + rearm_s;
            if (now_s() - last_img_req > 3.0) {   // don't poke while an image may be streaming
                uint8_t f[32];
                size_t fl = hex2bin("a01200b2360f00090180b080c180a780b880ad80be20", f, sizeof(f));
                write_milan(f, fl);
                usleep(4000);
                tag(); printf("-- fdt probe --\n");
            }
        }
        usleep(1500);
    }

    tag(); printf("=== done: %ld reads | fdt frames %ld (finger %ld) | images %ld | other %ld ===\n",
                  reads, fdt_count, finger_count, img_count, other_count);
    close(fd);
    return 0;
}
