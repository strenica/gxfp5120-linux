// cc-bigread.c — match the Windows ITE read pattern: optional command write,
// then repeated [phase A: 4-byte opcode transfer][phase B: data read] cycles
// with a configurable gap, dumping every data window raw for offline analysis.
//
// usage: cc-bigread <node> <mode> <hz> <payload-hex|-> <gap-us> <count> <outfile> [phases]
//   phases: 2 = separate opcode + data transfers (Windows style), 1 = merged (default 2)
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <linux/spi/spidev.h>

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
    if (argc < 8) { fprintf(stderr, "usage: %s node mode hz payload-hex|- gap-us count outfile [phases]\n", argv[0]); return 2; }
    uint8_t mode = (uint8_t)strtoul(argv[2], 0, 0);
    HZ = (uint32_t)strtoul(argv[3], 0, 0);
    int gap = atoi(argv[5]);
    int count = atoi(argv[6]);
    const char *out = argv[7];
    int phases = argc > 8 ? atoi(argv[8]) : 2;
    int pa_len = argc > 9 ? atoi(argv[9]) : 4;   // phase-A (opcode transfer) length
    if (pa_len < 4 || pa_len > 512) pa_len = 4;
    uint8_t opA[4] = {0xbb, 0xf1, 0x00, 0x00};
    if (argc > 10) hex2bin(argv[10], opA, sizeof(opA));

    fd = open(argv[1], O_RDWR);
    if (fd < 0) { perror("open"); return 1; }
    uint8_t bits = 8;
    ioctl(fd, SPI_IOC_WR_MODE, &mode);
    ioctl(fd, SPI_IOC_WR_BITS_PER_WORD, &bits);
    ioctl(fd, SPI_IOC_WR_MAX_SPEED_HZ, &HZ);

    if (strcmp(argv[4], "-") != 0) {
        uint8_t pb[512];
        size_t pl = hex2bin(argv[4], pb, sizeof(pb));
        uint8_t frame[520];
        frame[0] = 0xcc; frame[1] = 0xf2; frame[2] = 0x00; frame[3] = 0x01;
        memcpy(frame + 4, pb, pl);
        size_t pad = (4 - (pl & 3)) & 3;
        memset(frame + 4 + pl, 0, pad);
        uint8_t frx[520];
        if (xfer(frame, frx, 4 + pl + pad) < 0) { perror("write"); return 1; }
        printf("command written (%zu B)\n", pl);
        usleep((phases == 10) ? 60000 : 4000);
    }

    FILE *f = fopen(out, "wb");
    if (!f) { perror("fopen"); return 1; }
    char pathA[600]; snprintf(pathA, sizeof(pathA), "%s.pha", out);
    FILE *fa = fopen(pathA, "wb");

    uint8_t tx4[4] = {0xbb, 0xf1, 0x00, 0x00};
    uint8_t rx4[4];
    static uint8_t zeros[8192], win[8192];
    int pb_len = argc > 11 ? atoi(argv[11]) : 256;
    int fill = argc > 12 ? (int)strtoul(argv[12], 0, 0) : 0;
    if (pb_len < 8 || pb_len > 8192) pb_len = 256;

    int landed = 0;
    for (int i = 0; i < count; i++) {
        memset(win, 0, sizeof(win));
        if (phases == 5 || phases == 6) tx4[1] = 0xf0;
        else tx4[1] = 0xf1;
        if (phases == 1 || phases == 6) {
            uint8_t txm[256];
            memset(txm, 0, sizeof(txm));
            memcpy(txm, tx4, 4);
            if (xfer(txm, win, 256) < 0) { perror("xferM"); break; }
        } else if (phases == 2) {
            memset(rx4, 0, sizeof(rx4));
            if (xfer(tx4, rx4, 4) < 0) { perror("xferA"); break; }
            memset(zeros, 0, sizeof(zeros));
            if (xfer(zeros, win, 256) < 0) { perror("xferB"); break; }
        } else {   // phases 3/4/5: one ioctl, two descriptors (opcode phase + data phase)
            static uint8_t txA[512], rxA[512];
            memset(txA, 0, sizeof(txA));
            memcpy(txA, opA, 4);
            struct spi_ioc_transfer tr[2];
            memset(tr, 0, sizeof(tr));
            tr[0].tx_buf = (unsigned long)txA;
            tr[0].rx_buf = (unsigned long)rxA;
            tr[0].len = (phases == 10) ? (landed ? 4 : 512) : pa_len;
            tr[0].speed_hz = HZ;
            tr[0].bits_per_word = 8;
            tr[0].cs_change = (phases == 4) ? 1 : 0;
            tr[1].tx_buf = (unsigned long)zeros;
            tr[1].rx_buf = (unsigned long)win;
            tr[1].len = pb_len;
            tr[1].speed_hz = HZ;
            tr[1].bits_per_word = 8;
            memset(zeros, fill & 0xff, pb_len < 8192 ? (size_t)pb_len : 8192);
            if (ioctl(fd, SPI_IOC_MESSAGE(2), tr) < 0) { perror("xfer2"); break; }
            if (fa) fwrite(rxA, 1, 4, fa);
        }
        size_t outlen = (phases >= 3 && phases <= 5) ? (size_t)pb_len : 256;
        if (phases == 10 && !landed) {
            for (int q = 0; q + 4 <= 16; q++) {
                if (win[q] == 0xa0 && win[q+1] == 0x6d) {
                    landed = 1;
                    printf("LANDED at read %d offset %d\n", i, q);
                    break;
                }
            }
        }
        fwrite(win, 1, outlen, f);
        printf("win%02d A:%02x %02x %02x %02x | %02x %02x %02x %02x %02x %02x %02x %02x | %02x %02x %02x %02x %02x %02x %02x %02x\n",
               i, rx4[0], rx4[1], rx4[2], rx4[3],
               win[0], win[1], win[2], win[3], win[4], win[5], win[6], win[7],
               win[8], win[9], win[10], win[11], win[12], win[13], win[14], win[15]);
        fflush(stdout);
        if (gap > 0) usleep(gap);
    }
    fclose(f);
    printf("done: %d windows -> %s\n", count, out);
    close(fd);
    return 0;
}
