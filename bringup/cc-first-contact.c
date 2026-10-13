// cc-first-contact.c — GXFP5120 first-contact test with the ITE-EC wrapper.
//
// Sends one [cc f2 <ctr LE16>][milan outer+inner][00 00] frame over the Intel
// GSPI1 (spidev0.0) link that Windows uses for the "ITE_EC" transport, then
// reads MISO looking for a response.
//
// usage: cc-first-contact <spidev-node> [mode] [hz] [ctr] [payload-hex]
//   mode: raw spidev mode bits (0 = mode0; 0x04 = SPI_CS_HIGH; 0x08 = LOOP)
//   hz:   SPI clock (default 10000000 = 10 MHz per DSDT)
//   ctr:  16-bit counter to place after cc f2 (default 0)
//   payload-hex: milan outer+inner bytes (default "a00600a6200300010086" = cmd 0x20)
//                e.g. D4 TLS-unlock: "a00600a6d503000000d2"
//                     MB13 NOP:      "a00800a800050000000000a5"
//
// Safe class: kernel spidev driver only, no /dev/mem, no raw MMIO.

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <linux/spi/spidev.h>
#include <errno.h>

static void hexdump(const char *tag, const uint8_t *b, size_t n) {
    printf("%s (%zu): ", tag, n);
    for (size_t i = 0; i < n; i++) printf("%02x", b[i]);
    printf("\n");
}

static int do_xfer(int fd, uint8_t *tx, uint8_t *rx, size_t len, uint32_t hz) {
    struct spi_ioc_transfer tr;
    memset(&tr, 0, sizeof(tr));
    tr.tx_buf = (unsigned long)tx;
    tr.rx_buf = (unsigned long)rx;
    tr.len = (uint32_t)len;
    tr.speed_hz = hz;
    tr.bits_per_word = 8;
    if (ioctl(fd, SPI_IOC_MESSAGE(1), &tr) < 0) {
        perror("SPI_IOC_MESSAGE");
        return -1;
    }
    return 0;
}

int main(int argc, char **argv) {
    const char *dev = argc > 1 ? argv[1] : "/dev/spidev0.0";
    uint8_t  mode  = argc > 2 ? (uint8_t)strtoul(argv[2], 0, 0) : 0;
    uint32_t hz    = argc > 3 ? (uint32_t)strtoul(argv[3], 0, 0) : 10000000;
    uint16_t ctr   = argc > 4 ? (uint16_t)strtoul(argv[4], 0, 0) : 0;
    uint8_t  bits  = 8;

    int fd = open(dev, O_RDWR);
    if (fd < 0) { perror("open spidev"); return 1; }

    ioctl(fd, SPI_IOC_WR_MODE, &mode);
    ioctl(fd, SPI_IOC_WR_BITS_PER_WORD, &bits);
    ioctl(fd, SPI_IOC_WR_MAX_SPEED_HZ, &hz);
    uint8_t rd_mode = 0; uint32_t rd_hz = 0;
    ioctl(fd, SPI_IOC_RD_MODE, &rd_mode);
    ioctl(fd, SPI_IOC_RD_MAX_SPEED_HZ, &rd_hz);
    printf("spidev=%s mode=0x%02x (readback 0x%02x) hz=%u (readback %u)\n",
           dev, mode, rd_mode, hz, rd_hz);

    // Payload: optional hex string arg (milan bytes); default = cmd 0x20 state frame.
    const char *hexp = argc > 5 ? argv[5] : "a00600a6200300010086";
    uint8_t pbuf[128];
    size_t plen = 0;
    for (const char *p = hexp; p[0] && p[1]; p += 2) {
        unsigned v;
        if (plen >= sizeof(pbuf) || sscanf(p, "%2x", &v) != 1) break;
        pbuf[plen++] = (uint8_t)v;
    }
    size_t pad = (4 - (plen & 3)) & 3;
    size_t tlen = 4 + plen + pad;
    uint8_t tx[256];
    uint8_t rx[256];
    memset(tx, 0, sizeof(tx));
    memset(rx, 0, sizeof(rx));
    if (plen == 0 || tlen > sizeof(tx)) { fprintf(stderr, "bad payload\n"); return 1; }
    tx[0] = 0xcc;
    tx[1] = 0xf2;
    tx[2] = (uint8_t)(ctr & 0xff);
    tx[3] = (uint8_t)(ctr >> 8);
    memcpy(tx + 4, pbuf, plen);

    printf("sending frame (ctr=0x%04x, payload %zu B, total %zu B)...\n", ctr, plen, tlen);
    hexdump("TX", tx, tlen);
    if (do_xfer(fd, tx, rx, tlen, hz) < 0) return 1;
    hexdump("RX-during-write", rx, tlen);

    // Read opcode: the EC bridge only clocks out data when it sees bb f1 00 00 on MOSI.
    // (arg 6 overrides; default = the ISR's read pattern from gfspi.dll @0x1800c2e34)
    const char *rpat_hex = argc > 6 ? argv[6] : "bbf10000";
    uint8_t rpat[4] = {0xbb, 0xf1, 0x00, 0x00};
    for (int k = 0; k < 4 && rpat_hex[2*k] && rpat_hex[2*k+1]; k++) {
        unsigned v;
        if (sscanf(rpat_hex + 2*k, "%2x", &v) == 1) rpat[k] = (uint8_t)v;
    }
    printf("read opcode: %02x %02x %02x %02x\n", rpat[0], rpat[1], rpat[2], rpat[3]);

    // Rapid patterned reads: tx = opcode + zeros; look for the A0 response header.
    // arg 7: read chunk size (default 64; use 4 to match the ISR's header reads).
    size_t rxch = argc > 7 ? (size_t)strtoul(argv[7], 0, 0) : 64;
    if (rxch < 4 || rxch > 256) rxch = 64;
    int found = 0;
    uint8_t last[256];
    memset(last, 0xEE, sizeof(last));
    for (int i = 0; i < 334; i++) {
        uint8_t tbuf[256], rbuf[256];
        memset(tbuf, 0, sizeof(tbuf));
        memset(rbuf, 0, sizeof(rbuf));
        memcpy(tbuf, rpat, 4);
        if (do_xfer(fd, tbuf, rbuf, rxch, hz) < 0) return 1;
        if (memcmp(rbuf, last, rxch) != 0) {
            printf("READ#%d (~%d ms):", i, i * 3);
            for (size_t j = 0; j < rxch; j++) printf(" %02x", rbuf[j]);
            printf("\n");
            memcpy(last, rbuf, rxch);
            found++;
            if (found >= 8) break;
        }
        usleep(3000);
    }
    printf("patterned read loop done, %d distinct reads\n", found);

    close(fd);
    return 0;
}
