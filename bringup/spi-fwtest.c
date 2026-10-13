/*
 * Minimal SPI bring-up test for the Goodix GXFP5120 fingerprint sensor
 * (Huawei MateBook D14, ACPI \_SB.SPBA, spi-GXFP5120:00).
 *
 * Mirrors the open sequence of the libfprint-goodixtls GXFP5187 driver:
 *   AMORCE preamble -> FW_VERSION command -> read ACK -> read version.
 *
 * Standalone: talks straight to the spidev node, no libfprint involved.
 * Frame format from goodixtls.c:
 *   TX: [type=0xA0][len LE16][sum of first 3 bytes][body]
 *   RX: 4-byte header (type 0xA0 plain / 0xB0 TLS), then the body.
 *
 * Build: gcc -O2 -Wall -o spi-fwtest spi-fwtest.c
 * Run:   sudo ./spi-fwtest /dev/spidev0.0
 */
#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <linux/spi/spidev.h>

#define PKT_PLAIN 0xA0
#define PKT_TLS   0xB0
#define SPI_SPEED 10000000   /* 10 MHz, matches the DSDT _CRS */

static int fd = -1;

static void
hexdump (const char *tag, const uint8_t *b, int n)
{
  printf ("%-10s [%3d] ", tag, n);
  for (int i = 0; i < n && i < 64; i++)
    printf ("%02X ", b[i]);
  if (n > 64)
    printf ("... (%d more)", n - 64);
  putchar ('\n');
}

static int
write_frame (uint8_t type, const uint8_t *body, int n)
{
  uint8_t buf[512];
  struct spi_ioc_transfer xfer = { 0 };

  buf[0] = type;
  buf[1] = n & 0xFF;
  buf[2] = (n >> 8) & 0xFF;
  buf[3] = buf[0] + buf[1] + buf[2];
  memcpy (buf + 4, body, n);

  xfer.tx_buf = (unsigned long) buf;
  xfer.len = n + 4;
  xfer.speed_hz = SPI_SPEED;

  hexdump ("TX", buf, n + 4);
  int r = ioctl (fd, SPI_IOC_MESSAGE (1), &xfer);
  if (r < 1)
    {
      fprintf (stderr, "write ioctl failed: %d (%s)\n", r, strerror (errno));
      return -1;
    }
  return 0;
}

/* One frame = header transfer, 200us, body transfer (as in the driver). */
static int
read_frame (uint8_t *type, uint8_t *rx, int cap)
{
  uint8_t hdr[4] = { 0 };
  struct spi_ioc_transfer xh = { 0 }, xb = { 0 };
  int n;

  xh.rx_buf = (unsigned long) hdr;
  xh.len = 4;
  xh.speed_hz = SPI_SPEED;
  if (ioctl (fd, SPI_IOC_MESSAGE (1), &xh) < 1)
    {
      fprintf (stderr, "read header ioctl failed\n");
      return -1;
    }
  hexdump ("RX hdr", hdr, 4);

  if (hdr[0] != PKT_PLAIN && hdr[0] != PKT_TLS)
    {
      fprintf (stderr, "  -> unexpected frame type 0x%02X\n", hdr[0]);
      return -1;
    }
  *type = hdr[0];
  n = hdr[1] | (hdr[2] << 8);
  if (n <= 0 || n > cap)
    {
      fprintf (stderr, "  -> bad body length %d\n", n);
      return -1;
    }

  usleep (200);
  xb.rx_buf = (unsigned long) rx;
  xb.len = n;
  xb.speed_hz = SPI_SPEED;
  if (ioctl (fd, SPI_IOC_MESSAGE (1), &xb) < 1)
    {
      fprintf (stderr, "read body ioctl failed\n");
      return -1;
    }
  hexdump ("RX body", rx, n);
  return n;
}

int
main (int argc, char **argv)
{
  const char *path = argc > 1 ? argv[1] : "/dev/spidev0.0";
  const uint8_t amorce[] = { 0, 5, 0, 0, 0, 0, 0, 0x88 };
  const uint8_t fwcmd[]   = { 0xA8, 0x03, 0x00, 0x70, 0xDC, 0xB3 };
  uint8_t mode = SPI_MODE_0, bits = 8;
  uint32_t speed = SPI_SPEED;
  uint8_t ty, rx[4096];
  int n;

  fd = open (path, O_RDWR);
  if (fd < 0)
    {
      fprintf (stderr, "cannot open %s: %s\n", path, strerror (errno));
      return 1;
    }
  printf ("opened %s, mode 0, 8 bits, 10 MHz\n", path);
  ioctl (fd, SPI_IOC_WR_MODE, &mode);
  ioctl (fd, SPI_IOC_WR_BITS_PER_WORD, &bits);
  ioctl (fd, SPI_IOC_WR_MAX_SPEED_HZ, &speed);

  printf ("\n== step 1: AMORCE + FW_VERSION ==\n");
  if (write_frame (PKT_PLAIN, amorce, sizeof amorce) < 0)
    return 2;
  usleep (8000);
  if (write_frame (PKT_PLAIN, fwcmd, sizeof fwcmd) < 0)
    return 2;
  usleep (10000);

  printf ("-- waiting for ACK --\n");
  n = read_frame (&ty, rx, sizeof rx);
  usleep (5000);
  printf ("-- waiting for version --\n");
  n = read_frame (&ty, rx, sizeof rx);
  if (n > 3)
    {
      char fw[160];
      int k = 0;
      for (int i = 3; i < n && k < 159; i++)
        {
          uint8_t c = rx[i];
          fw[k++] = (c >= 32 && c < 127) ? (char) c : '.';
        }
      fw[k] = '\0';
      printf ("\nFIRMWARE STRING: '%s'\n", fw);
    }
  else
    {
      printf ("\nno usable version frame — dialogue not confirmed\n");
    }

  printf ("\n== step 2: probe for leftover frames (2 reads) ==\n");
  for (int i = 0; i < 2; i++)
    {
      if (read_frame (&ty, rx, sizeof rx) < 0)
        break;
    }

  close (fd);
  return 0;
}
