/*
 * First-contact test for the Goodix GXFP5120, following the confirmed
 * MateBook 13 discovery (GodsQuantum): NOP -> GetEvkVersion ("A8") with
 * SPI_CS_HIGH, 1 MHz, exact-length reads.
 *
 * Frame building per the Milan protocol evidence:
 *   outer: {0xA0, len_lo, len_hi, (b0+b1+b2)&0xff} + inner
 *   inner: {cmd, len_lo, len_hi, payload..., (0xAA - cmd - len_lo - len_hi - sum(payload)) & 0xff}
 *
 * Build: gcc -O2 -Wall -o spi-contact spi-contact.c
 * Run:   sudo ./spi-contact /dev/spidev0.0 [speed_hz]
 */
#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <linux/spi/spidev.h>

static int fd = -1;

static int
xfer_tx (const uint8_t *buf, int n, uint32_t speed)
{
  struct spi_ioc_transfer x = { 0 };
  x.tx_buf = (unsigned long) buf;
  x.len = n;
  x.speed_hz = speed;
  return ioctl (fd, SPI_IOC_MESSAGE (1), &x);
}

static int
xfer_rx (uint8_t *buf, int n, uint32_t speed)
{
  struct spi_ioc_transfer x = { 0 };
  x.rx_buf = (unsigned long) buf;
  x.len = n;
  x.speed_hz = speed;
  return ioctl (fd, SPI_IOC_MESSAGE (1), &x);
}

static void
hexdump (const char *tag, const uint8_t *b, int n)
{
  printf ("  %-12s [%3d] ", tag, n);
  for (int i = 0; i < n && i < 64; i++)
    printf ("%02X ", b[i]);
  if (n > 64) printf ("...");
  putchar ('\n');
}

static int
write_outer_inner (const uint8_t *inner, int n, uint32_t speed)
{
  uint8_t outer[4];
  outer[0] = 0xA0;
  outer[1] = n & 0xFF;
  outer[2] = (n >> 8) & 0xFF;
  outer[3] = (outer[0] + outer[1] + outer[2]) & 0xFF;
  if (xfer_tx (outer, 4, speed) < 1) return -1;
  usleep (2000);
  if (xfer_tx (inner, n, speed) < 1) return -1;
  return 0;
}

/* One round of exact-length reads: header, then body. Stops on FF FF FF FF. */
static int
read_round (uint32_t speed)
{
  int got = 0;
  for (int i = 0; i < 6; i++)
    {
      uint8_t hdr[4] = { 0 };
      if (xfer_rx (hdr, 4, speed) < 1) return got;
      if (hdr[0] != 0xA0 && hdr[0] != 0xB0)
        {
          printf ("  idle hdr   [  4] %02X %02X %02X %02X\n", hdr[0], hdr[1], hdr[2], hdr[3]);
          if (hdr[0] == 0xFF && hdr[1] == 0xFF && hdr[2] == 0xFF && hdr[3] == 0xFF)
            return got;                       /* no answer; stop this round */
          usleep (10000);
          continue;
        }
      int n = hdr[1] | (hdr[2] << 8);
      if (n <= 0 || n > 24000) { printf ("  bad len %d\n", n); return got; }
      uint8_t body[24000];
      usleep (200);
      if (xfer_rx (body, n, speed) < 1) return got;
      printf ("  ** FRAME type 0x%02X len %d **\n", hdr[0], n);
      hexdump ("body", body, n);
      if (n > 3)
        {
          char s[160]; int k = 0;
          for (int j = 3; j < n && k < 159; j++)
            s[k++] = (body[j] >= 32 && body[j] < 127) ? (char) body[j] : '.';
          s[k] = '\0';
          printf ("  ascii: '%s'\n", s);
        }
      got++;
      if (got >= 3) return got;
      usleep (10000);
    }
  return got;
}

int
main (int argc, char **argv)
{
  const char *path = argc > 1 ? argv[1] : "/dev/spidev0.0";
  uint32_t speed = argc > 2 ? (uint32_t) strtoul (argv[2], NULL, 0) : 1000000;
  uint8_t mode = SPI_MODE_0 | SPI_CS_HIGH;
  uint8_t bits = 8;
  int rc;

  /* NOP: outer A0 08 00 A8, inner 00 05 00 00 00 00 00 A5 */
  const uint8_t nop_inner[] = { 0x00, 0x05, 0x00, 0x00, 0x00, 0x00, 0x00, 0xA5 };
  /* GetEvkVersion ("A8" = cmd pair A/4) with the deterministic 00 00 fixture */
  const uint8_t a8_v1[] = { 0xA8, 0x03, 0x00, 0x00, 0x00, 0xFF };
  /* GetEvkVersion with the GXFP5187-derived payload */
  const uint8_t a8_v2[] = { 0xA8, 0x03, 0x00, 0x70, 0xDC, 0xB3 };

  fd = open (path, O_RDWR);
  if (fd < 0) { fprintf (stderr, "open %s: %s\n", path, strerror (errno)); return 1; }

  rc = ioctl (fd, SPI_IOC_WR_MODE, &mode);
  printf ("set mode 0x%02X (MODE_0|CS_HIGH): rc=%d%s\n", mode, rc, rc < 0 ? " FAILED" : "");
  ioctl (fd, SPI_IOC_WR_BITS_PER_WORD, &bits);
  rc = ioctl (fd, SPI_IOC_WR_MAX_SPEED_HZ, &speed);
  printf ("speed %u Hz: rc=%d\n", speed, rc);

  printf ("\n== NOP ==");
  if (write_outer_inner (nop_inner, sizeof nop_inner, speed) < 0)
    { printf (" write failed\n"); return 2; }
  printf ("\n");
  usleep (5000);

  printf ("== GetEvkVersion variant 1 (fixture 00 00) ==\n");
  if (write_outer_inner (a8_v1, sizeof a8_v1, speed) < 0) return 2;
  usleep (100000);
  if (read_round (speed) > 0) return 0;

  printf ("== NOP + GetEvkVersion variant 2 (70 DC) ==\n");
  if (write_outer_inner (nop_inner, sizeof nop_inner, speed) < 0) return 2;
  usleep (5000);
  if (write_outer_inner (a8_v2, sizeof a8_v2, speed) < 0) return 2;
  usleep (100000);
  if (read_round (speed) > 0) return 0;

  printf ("silent (no frame)\n");
  close (fd);
  return 3;
}
