// cc-init2.c — full Windows D0Entry replay, byte-exact from the 10:43:16 EVTX trace:
// D4 -> A8 -> 97-Install -> AE -> A8 -> E4(challenge) -> A2 -> 82 -> A6(S2H blob)
//   -> A2 -> 70 -> 98 -> 90(config upload) -> D1
// then watches for the sensor's TLS ClientHello (B0 frame carrying 16 03 03 ...).
//
// usage: cc-init2 <node> <mode> <hz> [watch-seconds]
// reads the 0x90 config frame hex from /tmp/cc90.hex
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
static long tls_seen = 0;

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

static void write_milan(const uint8_t *frame, size_t flen) {
    uint8_t tx[1024];
    if (flen > sizeof(tx) - 4) flen = sizeof(tx) - 4;
    tx[0] = 0xcc; tx[1] = 0xf2; tx[2] = 0x00; tx[3] = 0x01;
    memcpy(tx + 4, frame, flen);
    size_t pad = (4 - (flen & 3)) & 3;
    memset(tx + 4 + flen, 0, pad);
    uint8_t rx[1024];
    if (xfer(tx, rx, 4 + flen + pad) < 0) perror("write xfer");
}

static void report_frame(const uint8_t *f, size_t total) {
    tag();
    if (total >= 6 && f[0] == 0xb0 && total >= 5 && f[4] == 0x16 && f[5] == 0x03) {
        tls_seen++;
        printf("*** TLS RECORD (%zu B) ***:", total);
        for (size_t k = 0; k < total && k < 64; k++) printf(" %02x", f[k]);
        if (total > 64) printf(" ...");
        printf("\n");
    } else if (f[4] == 0xb0) {
        printf("ACK for cmd 0x%02x\n", total >= 9 ? f[7] : 0);
    } else {
        printf("frame %zu B cmd=0x%02x :", total, f[4]);
        for (size_t k = 0; k < total && k < 48; k++) printf(" %02x", f[k]);
        if (total > 48) printf(" ...");
        printf("\n");
    }
    fflush(stdout);
}

static void send_cmd(const char *name, const char *hex, int drain) {
    uint8_t f[1024];
    size_t fl = hex2bin(hex, f, sizeof(f));
    if (fl < 6) { tag(); printf("!! %s: bad hex (len %zu)\n", name, fl); return; }
    tag(); printf(">> %s (%zu B)\n", name, fl);
    write_milan(f, fl);
    usleep(4000);
    uint8_t acc[8192]; size_t accn = 0;
    for (int r = 0; r < drain; r++) {
        uint8_t tx[64], rx[64];
        memset(tx, 0, 64); tx[0] = 0xbb; tx[1] = 0xf1;
        if (xfer(tx, rx, 64) < 0) break;
        if (accn + 60 < sizeof(acc)) { memcpy(acc + accn, rx + 4, 60); accn += 60; }
        for (;;) {
            size_t i = 0, hit = 0;
            while (i + 4 <= accn) {
                uint8_t b0 = acc[i];
                if ((b0 == 0xa0 || b0 == 0xb0 || b0 == 0xc0) &&
                    ((b0 + acc[i+1] + acc[i+2]) & 0xff) == acc[i+3]) {
                    size_t total = 4 + (size_t)acc[i+1] + ((size_t)acc[i+2] << 8);
                    if (total >= 6 && total <= 8192 && i + total <= accn) {
                        report_frame(acc + i, total);
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

int main(int argc, char **argv) {
    if (argc < 4) { fprintf(stderr, "usage: %s node mode hz [watch-seconds]\n", argv[0]); return 2; }
    uint8_t mode = (uint8_t)strtoul(argv[2], 0, 0);
    HZ = (uint32_t)strtoul(argv[3], 0, 0);
    int watch_s = argc > 4 ? atoi(argv[4]) : 20;
    setvbuf(stdout, NULL, _IOLBF, 0);

    fd = open(argv[1], O_RDWR);
    if (fd < 0) { perror("open"); return 1; }
    uint8_t bits = 8;
    ioctl(fd, SPI_IOC_WR_MODE, &mode);
    ioctl(fd, SPI_IOC_WR_BITS_PER_WORD, &bits);
    ioctl(fd, SPI_IOC_WR_MAX_SPEED_HZ, &HZ);
    T0 = now_s();

    // load the 0x90 config frame from file (extracted verbatim from the EVTX)
    static char cfg90[1024];
    FILE *fp = fopen("/tmp/cc90.hex", "r");
    if (!fp) { fprintf(stderr, "missing /tmp/cc90.hex\n"); return 1; }
    if (!fgets(cfg90, sizeof(cfg90), fp)) { fprintf(stderr, "empty cc90.hex\n"); return 1; }
    fclose(fp);
    cfg90[strcspn(cfg90, "\r\n")] = 0;

    // full D0Entry replay (10:43:15.852 - 16.2xx trace)
    send_cmd("D4-unlock",   "a00600a6d503000000d2", 12);
    send_cmd("A8-version",  "a00600a6a803000000ff", 12);
    send_cmd("97-Install",  "a00600a697030001010e", 12);
    send_cmd("AE-mcu-state","a00900a9af0600555e3e000004000000", 12);
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

    printf("== watching %d s for sensor TLS ClientHello ==\n", watch_s);
    double t0 = now_s();
    uint8_t acc[65536]; size_t accn = 0;
    while (now_s() - t0 < watch_s) {
        uint8_t tx[64], rx[64];
        memset(tx, 0, 64); tx[0] = 0xbb; tx[1] = 0xf1;
        if (xfer(tx, rx, 64) < 0) { perror("read"); break; }
        if (accn + 60 < sizeof(acc)) { memcpy(acc + accn, rx + 4, 60); accn += 60; }
        for (;;) {
            size_t i = 0, hit = 0;
            while (i + 4 <= accn) {
                uint8_t b0 = acc[i];
                if ((b0 == 0xa0 || b0 == 0xb0 || b0 == 0xc0) &&
                    ((b0 + acc[i+1] + acc[i+2]) & 0xff) == acc[i+3]) {
                    size_t total = 4 + (size_t)acc[i+1] + ((size_t)acc[i+2] << 8);
                    if (total >= 6 && total <= 8192 && i + total <= accn) {
                        report_frame(acc + i, total);
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
        if (accn > 48000) { memmove(acc, acc + 4096, accn - 4096); accn -= 4096; }
        usleep(1000);
    }
    tag(); printf("== done, TLS records seen: %ld ==\n", tls_seen);
    close(fd);
    return 0;
}
