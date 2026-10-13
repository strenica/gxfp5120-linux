// cc-init.c — replay the Windows init sequence over the GXFP5120 ITE bridge.
//
// Phases: D4 TLS-unlock -> A8 GetEvkVersion -> 0x97 DriverState:Install -> AE MCU state,
// then an optional watch phase that continuously reads (bb f1, 64 B) and parses frames
// (touch the sensor during watch to try to capture finger data).
//
// usage: cc-init <node> <mode> <hz> [watch-seconds]
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

static double now_s(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return ts.tv_sec + ts.tv_nsec / 1e9;
}

static void hexprint(const uint8_t *b, size_t n) {
    for (size_t i = 0; i < n; i++) printf(" %02x", b[i]);
}

// scan buffer for outer frames; consume them from the front; return count found
static int scan_frames(uint8_t *acc, size_t *acclen, const char *tag) {
    int found = 0;
    size_t i = 0;
    while (i + 4 <= *acclen) {
        uint8_t b0 = acc[i];
        if ((b0 == 0xa0 || b0 == 0xb0 || b0 == 0xc0) &&
            ((b0 + acc[i+1] + acc[i+2]) & 0xff) == acc[i+3]) {
            size_t total = 4 + (size_t)acc[i+1] + ((size_t)acc[i+2] << 8);
            if (total >= 6 && total <= 8192 && i + total <= *acclen) {
                printf("[%s] FRAME %zuB cmd=0x%02x:", tag, total, acc[i+4]);
                size_t shown = total <= 64 ? total : 64;
                hexprint(acc + i, shown);
                if (shown < total) printf(" ... (+%zu B)", total - shown);
                printf("\n");
                found++;
                memmove(acc, acc + i + total, *acclen - i - total);
                *acclen -= i + total;
                i = 0;
                continue;
            }
        }
        i++;
    }
    return found;
}

static void send_cmd(const char *name, const char *hex) {
    uint8_t pbuf[128]; size_t plen = 0;
    for (const char *p = hex; p[0] && p[1]; p += 2) {
        unsigned v; if (plen >= sizeof(pbuf) || sscanf(p, "%2x", &v) != 1) break;
        pbuf[plen++] = (uint8_t)v;
    }
    size_t pad = (4 - (plen & 3)) & 3;
    uint8_t frame[256];
    frame[0] = 0xcc; frame[1] = 0xf2; frame[2] = 0x00; frame[3] = 0x01;
    memcpy(frame + 4, pbuf, plen);
    memset(frame + 4 + plen, 0, pad);
    size_t flen = 4 + plen + pad;

    uint8_t frx[256];
    if (xfer(frame, frx, flen) < 0) { perror("write"); return; }
    usleep(4000);   // quiet: bridge queues the response
    printf("== %s sent (%zu B), reading ==\n", name, flen);
    uint8_t acc[4096]; size_t acclen = 0;
    for (int r = 0; r < 6; r++) {
        uint8_t tx[64], rx[64];
        memset(tx, 0, sizeof(tx));
        tx[0] = 0xbb; tx[1] = 0xf1;
        memset(rx, 0, sizeof(rx));
        if (xfer(tx, rx, 64) < 0) { perror("read"); return; }
        if (acclen + 60 < sizeof(acc)) { memcpy(acc + acclen, rx, 64); acclen += 64; }
        scan_frames(acc, &acclen, name);
        if (r < 2) usleep(1000);
    }
}

int main(int argc, char **argv) {
    if (argc < 4) { fprintf(stderr, "usage: %s node mode hz [watch-seconds]\n", argv[0]); return 2; }
    uint8_t mode = (uint8_t)strtoul(argv[2], 0, 0);
    HZ = (uint32_t)strtoul(argv[3], 0, 0);
    int watch_s = argc > 4 ? atoi(argv[4]) : 0;

    fd = open(argv[1], O_RDWR);
    if (fd < 0) { perror("open"); return 1; }
    uint8_t bits = 8;
    ioctl(fd, SPI_IOC_WR_MODE, &mode);
    ioctl(fd, SPI_IOC_WR_BITS_PER_WORD, &bits);
    ioctl(fd, SPI_IOC_WR_MAX_SPEED_HZ, &HZ);

    // Windows D0Entry sequence (frames byte-exact from the working log)
    send_cmd("D4-unlock", "a00600a6d503000000d2");
    send_cmd("A8-version", "a00600a6a803000000ff");
    send_cmd("97-Install", "a00600a697030001010e");
    send_cmd("AE-mcu-state", "a00900a9af0600555e3e000004000000");
    // Windows' last step before touch data flows: the 0x36 fdt-start frame
    send_cmd("36-fdt-start", "a01200b2360f000901b0b0c0c0a7a7b9b9aeaebebee3");

    if (watch_s > 0) {
        printf("== watching for %d s (touch the sensor!) ==\n", watch_s);
        double t0 = now_s();
        uint8_t acc[65536]; size_t acclen = 0;
        long reads = 0;
        while (now_s() - t0 < watch_s) {
            uint8_t tx[64], rx[64];
            memset(tx, 0, sizeof(tx));
            tx[0] = 0xbb; tx[1] = 0xf1;
            memset(rx, 0, sizeof(rx));
            if (xfer(tx, rx, 64) < 0) { perror("read"); return 1; }
            reads++;
            if (acclen + 64 < sizeof(acc)) { memcpy(acc + acclen, rx, 64); acclen += 64; }
            scan_frames(acc, &acclen, "watch");
            // cap memory: drop consumed front if too much unconsumed noise
            if (acclen > 48000) { memmove(acc, acc + 4096, acclen - 4096); acclen -= 4096; }
            usleep(1000);
        }
        printf("== watch done (%ld reads, %.1f s) ==\n", reads, now_s() - t0);
    }
    close(fd);
    return 0;
}
