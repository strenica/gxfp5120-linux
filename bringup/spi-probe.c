/*
 * Systematic SPI dialogue probe for the Goodix GXFP5120.
 *
 * Tries several transport variants (speed, SPI mode, wake repeat) of the
 * goodixtls open sequence and reports the first variant that gets an answer,
 * plus a raw idle/duplex MISO sample. Diagnostic aid for bring-up.
 *
 * Build: gcc -O2 -Wall -o spi-probe spi-probe.c
 * Run:   sudo ./spi-probe /dev/spidev0.0
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

static int fd = -1;

static void
hexdump (const char *tag, const uint8_t *b, int n)
{
  printf ("  %-12s [%3d] ", tag, n);
  for (int i = 0; i < n && i < 40; i++)
    printf ("%02X ", b[i]);
  if (n > 40)
    printf ("... (%d more)", n - 40);
  putchar ('\n');
}

static int
set_transport (uint8_t mode, uint32_t speed)
{
  uint8_t bits = 8;
  if (ioctl (fd, SPI_IOC_WR_MODE, &mode) < 0)
    return -1;
  ioctl (fd, SPI_IOC_WR_BITS_PER_WORD, &bits);
  return ioctl (fd, SPI_IOC_WR_MAX_SPEED_HZ, &speed);
}

static int
write_frame (uint8_t type, const uint8_t *body, int n, uint32_t speed)
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
  xfer.speed_hz = speed;
  return ioctl (fd, SPI_IOC_MESSAGE (1), &xfer);
}

static int
read_frame (uint8_t *type, uint8_t *rx, int cap, uint32_t speed)
{
  uint8_t hdr[4] = { 0 };
  struct spi_ioc_transfer x = { 0 };
  int n;

  x.rx_buf = (unsigned long) hdr;
  x.len = 4;
  x.speed_hz = speed;
  if (ioctl (fd, SPI_IOC_MESSAGE (1), &x) < 1)
    return -1;
  if (hdr[0] != PKT_PLAIN && hdr[0] != PKT_TLS)
    return -1;
  *type = hdr[0];
  n = hdr[1] | (hdr[2] << 8);
  if (n <= 0 || n > cap)
    return -1;
  usleep (200);
  struct spi_ioc_transfer xb = { 0 };
  xb.rx_buf = (unsigned long) rx;
  xb.len = n;
  xb.speed_hz = speed;
  if (ioctl (fd, SPI_IOC_MESSAGE (1), &xb) < 1)
    return -1;
  return n;
}

/* Full-duplex sample: drive a pattern, see what MISO gives while active. */
static void
duplex_sample (uint32_t speed)
{
  uint8_t tx[16], rx[16];
  struct spi_ioc_transfer x = { 0 };

  memset (tx, 0x00, sizeof tx);
  x.tx_buf = (unsigned long) tx;
  x.rx_buf = (unsigned long) rx;
  x.len = sizeof tx;
  x.speed_hz = speed;
  memset (rx, 0xEE, sizeof rx);
  if (ioctl (fd, SPI_IOC_MESSAGE (1), &x) >= 1)
    hexdump ("idle MISO", rx, 16);

  for (int i = 0; i < 16; i++)
    tx[i] = (i & 1) ? 0x55 : 0xAA;
  memset (rx, 0xEE, sizeof rx);
  if (ioctl (fd, SPI_IOC_MESSAGE (1), &x) >= 1)
    hexdump ("duplex MISO", rx, 16);
}

int
main (int argc, char **argv)
{
  const char *path = argc > 1 ? argv[1] : "/dev/spidev0.0";
  const uint8_t amorce[] = { 0, 5, 0, 0, 0, 0, 0, 0x88 };
  const uint8_t fwcmd[]   = { 0xA8, 0x03, 0x00, 0x70, 0xDC, 0xB3 };

  struct variant
  {
    const char *name;
    uint8_t mode;
    uint32_t speed;
    useconds_t am_gap_us;
    int am_repeats;
  } variants[] = {
    { "std 10M mode0",    SPI_MODE_0, 10000000,  8000, 1 },
    { "1M mode0",         SPI_MODE_0,  1000000, 20000, 1 },
    { "10M mode3",        SPI_MODE_3, 10000000,  8000, 1 },
    { "1M mode0 x3 wake", SPI_MODE_0,  1000000, 20000, 3 },
    { "100k mode0",       SPI_MODE_0,   100000, 50000, 1 },
  };

  fd = open (path, O_RDWR);
  if (fd < 0)
    {
      fprintf (stderr, "cannot open %s: %s\n", path, strerror (errno));
      return 1;
    }
  printf ("opened %s\n", path);

  printf ("\n== raw MISO sample (mode 0, 1 MHz) ==\n");
  set_transport (SPI_MODE_0, 1000000);
  duplex_sample (1000000);

  for (unsigned v = 0; v < sizeof variants / sizeof variants[0]; v++)
    {
      struct variant *va = &variants[v];
      uint8_t ty, rx[4096];

      printf ("\n== variant %u: %s ==\n", v + 1, va->name);
      if (set_transport (va->mode, va->speed) < 0)
        {
          printf ("  transport set failed\n");
          continue;
        }

      for (int r = 0; r < va->am_repeats; r++)
        {
          write_frame (PKT_PLAIN, amorce, sizeof amorce, va->speed);
          usleep (va->am_gap_us);
        }
      if (write_frame (PKT_PLAIN, fwcmd, sizeof fwcmd, va->speed) < 0)
        {
          printf ("  write failed\n");
          continue;
        }
      usleep (va->am_gap_us * 2 > 20000 ? va->am_gap_us * 2 : 20000);

      for (int r = 0; r < 5; r++)
        {
          int n = read_frame (&ty, rx, sizeof rx, va->speed);
          if (n > 0)
            {
              printf ("  ** RESPONSE: type 0x%02X len %d **\n", ty, n);
              hexdump ("body", rx, n);
              if (n > 3)
                {
                  char fw[160];
                  int k = 0;
                  for (int i = 3; i < n && k < 159; i++)
                    fw[k++] = (rx[i] >= 32 && rx[i] < 127) ? (char) rx[i] : '.';
                  fw[k] = '\0';
                  printf ("  firmware guess: '%s'\n", fw);
                }
              printf ("\nSUCCESS with variant: %s\n", va->name);
              close (fd);
              return 0;
            }
          usleep (30000);
        }
      printf ("  no response\n");
    }

  printf ("\nNo variant answered. Sensor silent (MISO constant).\n");
  close (fd);
  return 3;
}
