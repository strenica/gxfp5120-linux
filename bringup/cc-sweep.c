// cc-sweep.c — find the write-counter value the EC bridge accepts.
//
// Hypothesis: the ITE EC bridge validates the cc-f2 counter (continuing the
// Windows session sequence). Sweep counters, send a D4-unlock frame for each,
// and poll the 4-byte response slot (read opcode bb f1 00 00, first 4 bytes).
// Non-zero slot => accepted; then read the full frame (header len + body).
//
// usage: cc-sweep <node> <mode> <hz> <start> <end>
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

static int read_slot(uint8_t slot[4]) {
    uint8_t tx[4] = {0xbb, 0xf1, 0x00, 0x00};
    memset(slot, 0, 4);
    return xfer(tx, slot, 4);
}

static void print_hex(const char *tag, const uint8_t *b, size_t n) {
    printf("%s:", tag);
    for (size_t i = 0; i < n; i++) printf(" %02x", b[i]);
    printf("\n");
}

int main(int argc, char **argv) {
    if (argc < 6) { fprintf(stderr, "usage: %s node mode hz start end\n", argv[0]); return 2; }
    const char *dev = argv[1];
    uint8_t mode = (uint8_t)strtoul(argv[2], 0, 0);
    HZ = (uint32_t)strtoul(argv[3], 0, 0);
    unsigned start = strtoul(argv[4], 0, 0) & 0xffff;
    unsigned end = strtoul(argv[5], 0, 0) & 0xffff;

    fd = open(dev, O_RDWR);
    if (fd < 0) { perror("open"); return 1; }
    uint8_t bits = 8;
    ioctl(fd, SPI_IOC_WR_MODE, &mode);
    ioctl(fd, SPI_IOC_WR_BITS_PER_WORD, &bits);
    ioctl(fd, SPI_IOC_WR_MAX_SPEED_HZ, &HZ);

    // Idle control: sample the slot 5 times with no writes.
    uint8_t slot[4];
    for (int i = 0; i < 5; i++) { read_slot(slot); if (i == 0 || slot[0]) { char t[32]; snprintf(t, sizeof(t), "idle slot #%d", i); print_hex(t, slot, 4); } usleep(100000); }

    // D4-unlock payload (a0 06 00 a6 | d5 03 00 00 00 d2), padded to 16 with header.
    const uint8_t payload[10] = {0xa0,0x06,0x00,0xa6,0xd5,0x03,0x00,0x00,0x00,0xd2};

    unsigned ctr;
    for (ctr = start; ctr <= end; ctr++) {
        uint8_t frame[16];
        frame[0] = 0xcc; frame[1] = 0xf2;
        frame[2] = ctr & 0xff; frame[3] = (ctr >> 8) & 0xff;
        memcpy(frame + 4, payload, 10);
        frame[14] = 0; frame[15] = 0;
        uint8_t rx[16];
        if (xfer(frame, rx, 16) < 0) { perror("write xfer"); return 1; }

        // poll slot: immediate, +3ms, +8ms
        if (!read_slot(slot) && slot[0] == 0 && slot[1] == 0 && slot[2] == 0 && slot[3] == 0) {
            usleep(3000);
            if (!read_slot(slot) && slot[0] == 0 && slot[1] == 0 && slot[2] == 0 && slot[3] == 0) {
                usleep(5000);
                read_slot(slot);
            }
        }
        if (slot[0] || slot[1] || slot[2] || slot[3]) {
            printf("\n*** ACCEPTED at ctr=0x%04x ***\n", ctr);
            print_hex("slot", slot, 4);
            if ((slot[0] >> 4) == 0xa || (slot[0] >> 4) == 0xb) {
                size_t total = 4u + (size_t)slot[1] + ((size_t)slot[2] << 8);
                if (total > 4 && total < 0x1000) {
                    uint8_t body[4096];
                    size_t got = 4;
                    while (got < total) {
                        size_t chunk = total - got; if (chunk > 0x100) chunk = 0x100;
                        uint8_t t2[256], r2[256];
                        memset(t2, 0, sizeof(t2));
                        t2[0] = 0xbb; t2[1] = 0xf1;
                        if (xfer(t2, r2, chunk) < 0) break;
                        memcpy(body + got, r2, chunk);
                        got += chunk;
                    }
                    print_hex("full frame", body, got);
                }
            }
            return 0;
        }
        if ((ctr & 0x3ff) == 0) { printf("... 0x%04x\n", ctr); fflush(stdout); }
    }
    printf("\nsweep done, nothing accepted in [0x%04x, 0x%04x]\n", start, end);
    return 1;
}
