/* SPDX-License-Identifier: LGPL-2.1-or-later
 *
 * GXFP5120 — ITE EC SPI transport (spidev + GPIO IRQ), raw uapi ioctls.
 * Byte-level behaviour matches the proven bringup/cc-cap.c tool.
 */
#include "gxfp5120.h"

#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <string.h>
#include <sys/ioctl.h>
#include <time.h>
#include <unistd.h>
#include <linux/spi/spidev.h>
#include <linux/gpio.h>

double gx_now_s (void)
{
    struct timespec ts;
    clock_gettime (CLOCK_MONOTONIC, &ts);
    return ts.tv_sec + ts.tv_nsec / 1e9;
}

uint64_t gx_now_us (void)
{
    return (uint64_t) (gx_now_s () * 1e6);
}

int gx_ec_open (GxEc *ec, const char *spidev, const char *gpiochip,
                int line, uint8_t mode, uint32_t hz, GError **error)
{
    memset (ec, 0, sizeof (*ec));
    ec->fd = -1;
    ec->chip_fd = -1;
    ec->line_fd = -1;
    ec->hz = hz;
    ec->mode = mode;

    ec->fd = open (spidev, O_RDWR);
    if (ec->fd < 0) {
        g_set_error (error, G_IO_ERROR, G_IO_ERROR_NOT_FOUND,
                     "open %s: %s", spidev, g_strerror (errno));
        return -1;
    }
    uint8_t bits = 8;
    if (ioctl (ec->fd, SPI_IOC_WR_MODE, &mode) < 0 ||
        ioctl (ec->fd, SPI_IOC_WR_BITS_PER_WORD, &bits) < 0 ||
        ioctl (ec->fd, SPI_IOC_WR_MAX_SPEED_HZ, &hz) < 0) {
        g_set_error (error, G_IO_ERROR, G_IO_ERROR_FAILED,
                     "spidev config: %s", g_strerror (errno));
        gx_ec_close (ec);
        return -1;
    }

    ec->chip_fd = open (gpiochip, O_RDWR);
    if (ec->chip_fd < 0) {
        g_set_error (error, G_IO_ERROR, G_IO_ERROR_NOT_FOUND,
                     "open %s: %s", gpiochip, g_strerror (errno));
        gx_ec_close (ec);
        return -1;
    }

    struct gpio_v2_line_request req;
    memset (&req, 0, sizeof (req));
    req.offsets[0] = (unsigned) line;
    req.num_lines = 1;
    req.config.flags = GPIO_V2_LINE_FLAG_INPUT | GPIO_V2_LINE_FLAG_EDGE_RISING;
    g_strlcpy (req.consumer, "gxfp5120", sizeof (req.consumer));
    if (ioctl (ec->chip_fd, GPIO_V2_GET_LINE_IOCTL, &req) < 0) {
        g_set_error (error, G_IO_ERROR, G_IO_ERROR_FAILED,
                     "GPIO_V2_GET_LINE(%d): %s", line, g_strerror (errno));
        gx_ec_close (ec);
        return -1;
    }
    ec->line_fd = req.fd;
    return 0;
}

void gx_ec_close (GxEc *ec)
{
    if (ec->line_fd >= 0)
        close (ec->line_fd);
    if (ec->chip_fd >= 0)
        close (ec->chip_fd);
    if (ec->fd >= 0)
        close (ec->fd);
    ec->line_fd = ec->chip_fd = ec->fd = -1;
}

int gx_ec_xfer (GxEc *ec, const uint8_t *tx, uint8_t *rx, size_t len)
{
    struct spi_ioc_transfer tr;
    memset (&tr, 0, sizeof (tr));
    tr.tx_buf = (unsigned long) tx;
    tr.rx_buf = (unsigned long) rx;
    tr.len = (uint32_t) len;
    tr.speed_hz = ec->hz;
    tr.bits_per_word = 8;
    return ioctl (ec->fd, SPI_IOC_MESSAGE (1), &tr);
}

/* Windows-style parcel read: two descriptors in one ioctl —
 * [bb f1 00 00] (rx 4B status) then [00 x256] (rx 256B window). */
int gx_ec_parcel_read (GxEc *ec, uint8_t st[4], uint8_t win[256])
{
    uint8_t op[4] = { 0xbb, 0xf1, 0x00, 0x00 };
    uint8_t zeros[256];
    struct spi_ioc_transfer tr[2];
    memset (zeros, 0, sizeof (zeros));
    memset (tr, 0, sizeof (tr));
    tr[0].tx_buf = (unsigned long) op;
    tr[0].rx_buf = (unsigned long) st;
    tr[0].len = 4;
    tr[0].speed_hz = ec->hz;
    tr[0].bits_per_word = 8;
    tr[1].tx_buf = (unsigned long) zeros;
    tr[1].rx_buf = (unsigned long) win;
    tr[1].len = 256;
    tr[1].speed_hz = ec->hz;
    tr[1].bits_per_word = 8;
    return ioctl (ec->fd, SPI_IOC_MESSAGE (2), tr);
}

int gx_ec_write_milan (GxEc *ec, const uint8_t *frame, size_t flen)
{
    uint8_t tx[1024], rx[1024];
    if (flen > sizeof (tx) - 4)
        flen = sizeof (tx) - 4;
    tx[0] = 0xcc;
    tx[1] = 0xf2;
    tx[2] = 0x00;
    tx[3] = 0x01;
    memcpy (tx + 4, frame, flen);
    size_t pad = (4 - (flen & 3)) & 3;
    memset (tx + 4 + flen, 0, pad);
    return gx_ec_xfer (ec, tx, rx, 4 + flen + pad);
}

int gx_ec_wait_irq (GxEc *ec, int timeout_ms)
{
    struct pollfd pfd = { .fd = ec->line_fd, .events = POLLIN };
    int pr = poll (&pfd, 1, timeout_ms);
    if (pr <= 0)
        return pr;
    struct gpio_v2_line_event ev;
    if (read (ec->line_fd, &ev, sizeof (ev)) < 0)
        return -1;
    return 1;
}
