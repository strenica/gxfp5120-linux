// cc-drain.c — drain the GXFP5120 EC-bridge read stream and dump raw bytes.
// usage: cc-drain <node> <mode> <hz> <opcode-hex> <chunk> <count> <outfile>
// Reads <count> chunks of <chunk> bytes, each transfer carrying <opcode> on MOSI,
// writing all received bytes to <outfile> for offline analysis.
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <linux/spi/spidev.h>
#include <errno.h>

int main(int argc, char **argv) {
    if (argc < 7) { fprintf(stderr, "usage: %s node mode hz opcode chunk count outfile\n", argv[0]); return 2; }
    const char *dev = argv[1];
    uint8_t mode  = (uint8_t)strtoul(argv[2], 0, 0);
    uint32_t hz   = (uint32_t)strtoul(argv[3], 0, 0);
    const char *ohex = argv[4];
    size_t chunk  = strtoul(argv[5], 0, 0);
    int count     = atoi(argv[6]);
    const char *out = argv[7];

    uint8_t op[4] = {0xbb, 0xf1, 0x00, 0x00};
    for (int k = 0; k < 4 && ohex[2*k] && ohex[2*k+1]; k++) {
        unsigned v; if (sscanf(ohex + 2*k, "%2x", &v) == 1) op[k] = (uint8_t)v;
    }

    int fd = open(dev, O_RDWR);
    if (fd < 0) { perror("open"); return 1; }
    uint8_t bits = 8;
    ioctl(fd, SPI_IOC_WR_MODE, &mode);
    ioctl(fd, SPI_IOC_WR_BITS_PER_WORD, &bits);
    ioctl(fd, SPI_IOC_WR_MAX_SPEED_HZ, &hz);

    FILE *f = fopen(out, "wb");
    if (!f) { perror("fopen"); return 1; }

    uint8_t *tbuf = calloc(1, chunk), *rbuf = calloc(1, chunk);
    for (int i = 0; i < count; i++) {
        memset(tbuf, 0, chunk);
        memcpy(tbuf, op, 4);
        memset(rbuf, 0, chunk);
        struct spi_ioc_transfer tr;
        memset(&tr, 0, sizeof(tr));
        tr.tx_buf = (unsigned long)tbuf;
        tr.rx_buf = (unsigned long)rbuf;
        tr.len = (uint32_t)chunk;
        tr.speed_hz = hz;
        tr.bits_per_word = 8;
        if (ioctl(fd, SPI_IOC_MESSAGE(1), &tr) < 0) { perror("xfer"); return 1; }
        fwrite(rbuf, 1, chunk, f);
    }
    fclose(f);
    printf("drained %d x %zu bytes -> %s\n", count, chunk, out);
    close(fd);
    return 0;
}
