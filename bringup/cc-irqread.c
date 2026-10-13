// cc-irqread.c — read ONE [4+256] SPI parcel per GPIO edge (gpio17), in-process,
// replicating the Windows ISR cadence (one parcel per data-ready pulse).
//
// usage: cc-irqread <spidev> <gpiochipN> <line> <mode> <hz> <payload-hex|-> <seconds> <outfile>
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
#include <time.h>

static int fd;
static uint32_t HZ;

static double now_s(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return ts.tv_sec + ts.tv_nsec / 1e9;
}

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

int main(int argc, char **argv) {
    if (argc < 9) { fprintf(stderr, "usage: %s spidev gpiochipN line mode hz payload-hex|- seconds outfile\n", argv[0]); return 2; }
    uint8_t mode = (uint8_t)strtoul(argv[4], 0, 0);
    HZ = (uint32_t)strtoul(argv[5], 0, 0);
    int seconds = atoi(argv[7]);

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
    snprintf(req.consumer, sizeof(req.consumer), "cc-irqread");
    if (ioctl(chip, GPIO_V2_GET_LINE_IOCTL, &req) < 0) { perror("GPIO_V2_GET_LINE"); return 1; }
    int gfd = req.fd;

    if (strcmp(argv[6], "-") != 0) {
        uint8_t pb[512];
        size_t pl = hex2bin(argv[6], pb, sizeof(pb));
        uint8_t frame[520];
        frame[0] = 0xcc; frame[1] = 0xf2; frame[2] = 0x00; frame[3] = 0x01;
        memcpy(frame + 4, pb, pl);
        size_t pad = (4 - (pl & 3)) & 3;
        memset(frame + 4 + pl, 0, pad);
        uint8_t frx[520];
        if (xfer(frame, frx, 4 + pl + pad) < 0) perror("write");
        printf("command written (%zu B)\n", pl);
        usleep(4000);
    }

    FILE *f = fopen(argv[8], "wb");
    if (!f) { perror("fopen"); return 1; }

    uint8_t txA[4] = {0xbb, 0xf1, 0x00, 0x00};
    uint8_t rxA[4], zeros[256], win[256];
    memset(zeros, 0, sizeof(zeros));

    double t0 = now_s();
    int idx = 0;
    while (now_s() - t0 < seconds && idx < 400) {
        struct pollfd pfd = { .fd = gfd, .events = POLLIN };
        int pr = poll(&pfd, 1, 1000);
        if (pr <= 0) continue;
        struct gpio_v2_line_event ev;
        if (read(gfd, &ev, sizeof(ev)) < 0) continue;
        if (argc > 9) usleep(atoi(argv[9]));
        // one parcel read: [bb f1 00 00] + 256-byte data phase, one ioctl
        struct spi_ioc_transfer tr[2];
        memset(tr, 0, sizeof(tr));
        tr[0].tx_buf = (unsigned long)txA;
        tr[0].rx_buf = (unsigned long)rxA;
        tr[0].len = 4;
        tr[0].speed_hz = HZ;
        tr[0].bits_per_word = 8;
        tr[1].tx_buf = (unsigned long)zeros;
        tr[1].rx_buf = (unsigned long)win;
        tr[1].len = 256;
        tr[1].speed_hz = HZ;
        tr[1].bits_per_word = 8;
        memset(win, 0, sizeof(win));
        double tr0 = now_s();
        if (ioctl(fd, SPI_IOC_MESSAGE(2), tr) < 0) { perror("xfer2"); break; }
        fwrite(win, 1, 256, f);
        // second read per pulse: reveals tearing / block updates
        {
            uint8_t win2[256];
            memset(win2, 0, sizeof(win2));
            tr[1].rx_buf = (unsigned long)win2;
            if (ioctl(fd, SPI_IOC_MESSAGE(2), tr) == 0) {
                fwrite(win2, 1, 256, f);
                int same = (memcmp(win, win2, 256) == 0);
                printf("      read2 %s\n", same ? "IDENTICAL" : "DIFFERENT");
                fflush(stdout);
            }
        }
        printf("p%02d t=%.3f lat=%.3f : %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x\n",
               idx, tr0 - t0, now_s() - tr0,
               win[0], win[1], win[2], win[3], win[4], win[5], win[6], win[7],
               win[8], win[9], win[10], win[11], win[12], win[13], win[14], win[15]);
        fflush(stdout);
        idx++;
    }
    fclose(f);
    printf("done: %d parcels\n", idx);
    close(fd);
    return 0;
}
