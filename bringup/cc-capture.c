// cc-capture.c — send a command frame, then continuously read the bridge stream
// (bb f1) and parse out complete Milan response frames (outer a0/b0/c0 + valid csum).
//
// usage: cc-capture <node> <mode> <hz> <payload-hex> [reads] [chunk]
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

int main(int argc, char **argv) {
    if (argc < 5) { fprintf(stderr, "usage: %s node mode hz payload-hex [reads] [chunk]\n", argv[0]); return 2; }
    uint8_t mode = (uint8_t)strtoul(argv[2], 0, 0);
    HZ = (uint32_t)strtoul(argv[3], 0, 0);
    int nreads = argc > 5 ? atoi(argv[5]) : 200;
    size_t chunk = argc > 6 ? strtoul(argv[6], 0, 0) : 32;
    if (chunk < 8 || chunk > 256) chunk = 32;

    fd = open(argv[1], O_RDWR);
    if (fd < 0) { perror("open"); return 1; }
    uint8_t bits = 8;
    ioctl(fd, SPI_IOC_WR_MODE, &mode);
    ioctl(fd, SPI_IOC_WR_BITS_PER_WORD, &bits);
    ioctl(fd, SPI_IOC_WR_MAX_SPEED_HZ, &HZ);

    // build write frame: cc f2 00 01 + payload + pad4
    uint8_t pbuf[128]; size_t plen = 0;
    const char *h = argv[4];
    for (const char *p = h; p[0] && p[1]; p += 2) {
        unsigned v; if (plen >= sizeof(pbuf) || sscanf(p, "%2x", &v) != 1) break;
        pbuf[plen++] = (uint8_t)v;
    }
    size_t pad = (4 - (plen & 3)) & 3;
    uint8_t frame[256];
    frame[0] = 0xcc; frame[1] = 0xf2; frame[2] = 0x00; frame[3] = 0x01;
    memcpy(frame + 4, pbuf, plen);
    memset(frame + 4 + plen, 0, pad);
    size_t flen = 4 + plen + pad;
    printf("write frame (%zu B):", flen);
    for (size_t i = 0; i < flen; i++) printf(" %02x", frame[i]);
    printf("\n");
    uint8_t frx[256];
    if (xfer(frame, frx, flen) < 0) { perror("write xfer"); return 1; }
    usleep(4000);   // quiet window: the bridge queues the response during this gap

    // continuous read + frame scan
    uint8_t acc[4096]; size_t acclen = 0;
    for (int r = 0; r < nreads; r++) {
        uint8_t tx[256], rx[256];
        memset(tx, 0, sizeof(tx));
        tx[0] = 0xbb; tx[1] = 0xf1;
        memset(rx, 0, sizeof(rx));
        if (xfer(tx, rx, chunk) < 0) { perror("read xfer"); return 1; }
        if (r < 3) { printf("raw[%d]:", r); for (size_t j = 0; j < chunk; j++) printf(" %02x", rx[j]); printf("\n"); }
        // each transfer = [4-byte exchange-buffer status][chunk-4 bytes of stream]
        if (acclen + chunk - 4 < sizeof(acc)) {
            memcpy(acc + acclen, rx + 4, chunk - 4);
            acclen += chunk - 4;
        }
        // scan for frames in the accumulated buffer
        size_t i = 0;
        while (i + 4 <= acclen) {
            uint8_t b0 = acc[i];
            if ((b0 == 0xa0 || b0 == 0xb0 || b0 == 0xc0) &&
                ((b0 + acc[i+1] + acc[i+2]) & 0xff) == acc[i+3]) {
                size_t total = 4 + (size_t)acc[i+1] + ((size_t)acc[i+2] << 8);
                if (total >= 4 && total <= 260 && i + total <= acclen) {
                    printf("FRAME (read %d, off %zu, %zu B):", r, i, total);
                    for (size_t j = 0; j < total; j++) printf(" %02x", acc[i+j]);
                    printf("\n");
                    // consume the frame
                    memmove(acc, acc + i + total, acclen - i - total);
                    acclen -= i + total;
                    i = 0;
                    continue;
                }
            }
            i++;
        }
        usleep(1500);
    }
    printf("done (%d reads, %zu bytes unconsumed)\n", nreads, acclen);
    close(fd);
    return 0;
}
