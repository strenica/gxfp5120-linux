/*
 * Extended first-contact test for GXFP5120 (CS_HIGH, IRQ-aware reads).
 *
 * Sequences per the MateBook 13 (GodsQuantum) findings:
 *   - "A8 alone" (GetEvkVersion) after reset = their first-contact winner
 *   - NOP = A0 08 00 A8 outer / 00 05 00 00 00 00 00 A5 inner
 *   - Install ("DriverState") = 96 03 00 01 00 10
 *   - reads gated on the IRQ pad (offset 17) going HIGH; FF FF FF FF = no data
 *
 * Build: gcc -O2 -Wall -o spi-contact2 spi-contact2.c
 * Run:   sudo ./spi-contact2 /dev/spidev0.0 [speed_hz]
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
#include <linux/gpio.h>

#define IRQ_OFFSET 17

static int fd = -1;
static int irq_fd = -1;

static int
irq_level (void)
{
  struct gpio_v2_line_values v = { 0 };
  v.mask = 1;
  if (irq_fd < 0 || ioctl (irq_fd, GPIO_V2_LINE_GET_VALUES_IOCTL, &v) < 0)
    return -1;
  return v.bits & 1;
}

static int
irq_wait_high (int ms)
{
  for (int i = 0; i < ms / 5; i++)
    {
      if (irq_level () == 1) return 1;
      usleep (5000);
    }
  return 0;
}

static int
xfer_tx (const uint8_t *buf, int n, uint32_t speed)
{
  struct spi_ioc_transfer x = { 0 };
  x.tx_buf = (unsigned long) buf; x.len = n; x.speed_hz = speed;
  return ioctl (fd, SPI_IOC_MESSAGE (1), &x);
}
static int
xfer_rx (uint8_t *buf, int n, uint32_t speed)
{
  struct spi_ioc_transfer x = { 0 };
  x.rx_buf = (unsigned long) buf; x.len = n; x.speed_hz = speed;
  return ioctl (fd, SPI_IOC_MESSAGE (1), &x);
}

static void
hexdump (const char *tag, const uint8_t *b, int n)
{
  printf ("  %-10s [%3d] ", tag, n);
  for (int i = 0; i < n && i < 48; i++) printf ("%02X ", b[i]);
  if (n > 48) printf ("...");
  putchar ('\n');
}

static int
send_frame (const uint8_t *inner, int n, uint32_t speed)
{
  uint8_t outer[4] = { 0xA0, n & 0xFF, (n >> 8) & 0xFF, 0 };
  outer[3] = (outer[0] + outer[1] + outer[2]) & 0xFF;
  if (xfer_tx (outer, 4, speed) < 1) return -1;
  usleep (2000);
  if (xfer_tx (inner, n, speed) < 1) return -1;
  return 0;
}

/* One protocol read: only if IRQ high (bounded wait); exact lengths; FF stops. */
static int
gated_read (uint32_t speed, int gate_ms, int *saw_irq)
{
  uint8_t hdr[4];
  int lvl = irq_level ();

  if (irq_fd >= 0 && lvl != 1)
    {
      if (!irq_wait_high (gate_ms))
        {
          printf ("  (no IRQ within %d ms)\n", gate_ms);
          return 0;                     /* no IRQ: no read (their rule) */
        }
    }
  if (irq_fd < 0)
    printf ("  (ungated read: IRQ line unavailable)\n");
  *saw_irq = 1;
  memset (hdr, 0, 4);
  if (xfer_rx (hdr, 4, speed) < 1) return -1;
  hexdump ("hdr", hdr, 4);
  if (hdr[0] == 0xFF && hdr[1] == 0xFF && hdr[2] == 0xFF && hdr[3] == 0xFF)
    { printf ("  (idle FF FF FF FF — no data)\n"); return 1; }
  if (hdr[0] != 0xA0 && hdr[0] != 0xB0)
    { printf ("  (unexpected header byte 0x%02X)\n", hdr[0]); return 1; }
  int n = hdr[1] | (hdr[2] << 8);
  if (n <= 0 || n > 24000) { printf ("  bad len %d\n", n); return 1; }
  uint8_t body[24000];
  usleep (200);
  if (xfer_rx (body, n, speed) < 1) return -1;
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
  return 2;                              /* got a real frame */
}

int
main (int argc, char **argv)
{
  const char *path = argc > 1 ? argv[1] : "/dev/spidev0.0";
  uint32_t speed = argc > 2 ? (uint32_t) strtoul (argv[2], NULL, 0) : 1000000;
  uint8_t mode = SPI_MODE_0 | SPI_CS_HIGH, bits = 8;

  if (argc > 3 && strcmp (argv[3], "nocs") == 0)
    mode = SPI_MODE_0;
  printf ("mode: %s\n", (mode & SPI_CS_HIGH) ? "MODE_0|CS_HIGH" : "MODE_0 (normal CS)");

  const uint8_t nop[]     = { 0x00, 0x05, 0x00, 0x00, 0x00, 0x00, 0x00, 0xA5 };
  const uint8_t install[] = { 0x96, 0x03, 0x00, 0x01, 0x00, 0x10 };
  const uint8_t a8_fix[]  = { 0xA8, 0x03, 0x00, 0x00, 0x00, 0xFF };
  const uint8_t a8_5187[] = { 0xA8, 0x03, 0x00, 0x70, 0xDC, 0xB3 };

  fd = open (path, O_RDWR);
  if (fd < 0) { fprintf (stderr, "open %s: %s\n", path, strerror (errno)); return 1; }
  if (ioctl (fd, SPI_IOC_WR_MODE, &mode) < 0)
    { fprintf (stderr, "CS_HIGH rejected\n"); return 1; }
  ioctl (fd, SPI_IOC_WR_BITS_PER_WORD, &bits);
  ioctl (fd, SPI_IOC_WR_MAX_SPEED_HZ, &speed);

  {
    struct gpio_v2_line_request req = { 0 };
    irq_fd = open ("/dev/gpiochip0", O_RDWR | O_CLOEXEC);
    if (irq_fd >= 0)
      {
        req.num_lines = 1;
        req.offsets[0] = IRQ_OFFSET;
        req.config.flags = GPIO_V2_LINE_FLAG_INPUT;
        if (ioctl (irq_fd, GPIO_V2_GET_LINE_IOCTL, &req) < 0)
          { printf ("IRQ line request failed: %s\n", strerror (errno)); irq_fd = -1; }
        else
          {
            close (irq_fd);
            irq_fd = req.fd;
            printf ("IRQ line %d acquired, level=%d\n", IRQ_OFFSET, irq_level ());
            usleep (1000);
          }
      }
  }

  struct { const char *name; const uint8_t *parts[4]; int lens[4]; } seqs[] = {
    { "A8 alone",            { a8_fix, NULL, NULL, NULL },       { 6, 0, 0, 0 } },
    { "A8 (5187 payload)",   { a8_5187, NULL, NULL, NULL },      { 6, 0, 0, 0 } },
    { "NOP + A8",            { nop, a8_fix, NULL, NULL },        { 8, 6, 0, 0 } },
    { "Install + A8",        { install, a8_fix, NULL, NULL },    { 6, 6, 0, 0 } },
    { "NOP + Install + A8",  { nop, install, a8_fix, NULL },     { 8, 6, 6, 0 } },
    { "NOP + A8 + A8 retry", { nop, a8_fix, a8_fix, NULL },      { 8, 6, 6, 0 } },
  };

  for (unsigned s = 0; s < sizeof seqs / sizeof seqs[0]; s++)
    {
      printf ("\n== seq: %s (irq level before: %d) ==\n", seqs[s].name, irq_level ());
      for (int p = 0; p < 4 && seqs[s].lens[p]; p++)
        {
          if (send_frame (seqs[s].parts[p], seqs[s].lens[p], speed) < 0)
            { printf ("  write failed\n"); break; }
          usleep (5000);
        }
      usleep (20000);
      int saw_irq = 0, rc;
      rc = gated_read (speed, 300, &saw_irq);
      if (rc == 0)
        {                                /* no IRQ: one blind diagnostic read */
          uint8_t h[4] = { 0 };
          if (xfer_rx (h, 4, speed) >= 1)
            printf ("  blind read: %02X %02X %02X %02X\n", h[0], h[1], h[2], h[3]);
        }
      printf ("  (irq level after: %d, saw_irq=%d)\n", irq_level (), saw_irq);
      if (rc == 2) { printf ("\n>>> CONTACT: %s\n", seqs[s].name); return 0; }
      usleep (10000);
    }

  printf ("\nno response to any sequence\n");
  if (irq_fd >= 0) close (irq_fd);
  close (fd);
  return 3;
}
