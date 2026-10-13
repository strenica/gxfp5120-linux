// cc-scan.c — write one 0x20 frame, then read 16 bytes at every address 0x00..0xFF
// (read opcode bb f1 <addr_le16>) and report any window containing frame bytes
// (a0/b0 with valid outer checksum). Also repeats 0x80 to test stability.
//
// usage: cc-scan <node> <mode> <hz>
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

static int looks_like_frame(const uint8_t *b, size_t n) {
    for (size_t i = 0; i + 4 <= n; i++) {
        uint8_t b0 = b[i], b1 = b[i+1], b2 = b[i+2], b3 = b[i+3];
        if (b0 == 0xa0 && ((b0 + b1 + b2) & 0xff) == b3) return (int)i;
    }
    return -1;
}

int main(int argc, char **argv) {
    if (argc < 4) { fprintf(stderr, "usage: %s node mode hz\n", argv[0]); return 2; }
    uint8_t mode = (uint8_t)strtoul(argv[2], 0, 0);
    HZ = (uint32_t)strtoul(argv[3], 0, 0);

    fd = open(argv[1], O_RDWR);
    if (fd < 0) { perror("open"); return 1; }
    uint8_t bits = 8;
    ioctl(fd, SPI_IOC_WR_MODE, &mode);
    ioctl(fd, SPI_IOC_WR_BITS_PER_WORD, &bits);
    ioctl(fd, SPI_IOC_WR_MAX_SPEED_HZ, &HZ);

    // send the 0x20 state frame
    uint8_t frame[16] = {0xcc,0xf2,0x00,0x01, 0xa0,0x06,0x00,0xa6, 0x20,0x03,0x00,0x01,0x00,0x86, 0x00,0x00};
    uint8_t rx16[16];
    xfer(frame, rx16, 16);
    usleep(4000);

    for (int pass = 0; pass < 2; pass++) {
        printf("=== pass %d ===\n", pass);
        for (int addr = 0; addr < 0x100; addr += 0x10) {
            uint8_t tx[16], rx[16];
            memset(tx, 0, sizeof(tx));
            tx[0] = 0xbb; tx[1] = 0xf1; tx[2] = addr & 0xff; tx[3] = 0;
            memset(rx, 0, sizeof(rx));
            xfer(tx, rx, 16);
            int fi = looks_like_frame(rx, 16);
            printf("addr=%02x:", addr);
            for (int j = 0; j < 16; j++) printf(" %02x", rx[j]);
            if (fi >= 0) printf("   <<< FRAME at +%d", fi);
            printf("\n");
        }
        usleep(30000);
    }
    // repeat address 0x80 three times to test stability
    printf("=== addr 0x80 repeated ===\n");
    for (int k = 0; k < 3; k++) {
        uint8_t tx[16], rx[16];
        memset(tx, 0, sizeof(tx));
        tx[0] = 0xbb; tx[1] = 0xf1; tx[2] = 0x80; tx[3] = 0;
        memset(rx, 0, sizeof(rx));
        xfer(tx, rx, 16);
        printf("rep%d:", k);
        for (int j = 0; j < 16; j++) printf(" %02x", rx[j]);
        printf("\n");
        usleep(5000);
    }
    close(fd);
    return 0;
}
