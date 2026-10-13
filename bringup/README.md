# bringup — tooling from the reverse-engineering work

Small C/Python tools used to bring the sensor up, kept for reference and further
development. The full story is in `../PORT-PLAN.md`.

- **First contact / transport**: `spi-probe`, `spi-contact`, `spi-contact2`,
  `spi-fwtest`, `probes-now.sh`.
- **Capture & session tools**: `cc-cap` (one full capture), `cc-bg` (background + five
  presses in one session), `cc-imageread` (full session + single image), `cc-fing2`
  (per-press choreography), plus the protocol-experiment tools (`cc-scan`, `cc-sweep`,
  `cc-touch`, `cc-tlsreplay`, …). They read the PSK from `../psk_raw32.bin` or
  `/etc/gxfp5120/psk.bin`.
- **PSK extraction**: `psk-unseal-windows.ps1` (run inside Windows), `unseal-psk.py`.
- **Matcher harness**: `gxfp-match.c` — SigFM score matrices over `.content.bin`
  capture dumps (`GXFP_VARIANT=0..6`, optional scale argument).
- **Rendering**: `decode-cap.py` — `.content.bin` → PNG. Also `analyze-imageread.py`,
  `matcher-sift.py`, `fp-live4.py` from the matcher evaluation phase.
- **Manual test**: `bind-and-test.sh` — binds spidev by hand and reads the firmware
  version. (Boot-time persistence now lives in `../driver/boot-bind/`.)

⚠️ **Historical MMIO phase (dangerous)**: `dump-mmio*.sh`, `dump-ec-ram.py`,
`fps-boot-test.sh`, `fps-diag2.sh`, `fps-diag3.sh`, `diag.sh`, `install-boottest.sh`.
These probe raw MMIO/EC space and **hard-froze this laptop 10+ times**; self-guarded
with `ALLOW_DEVMEM=1` where applicable. The supported path is spidev — use that.

Also kept: `enable-osi.sh` / `disable-osi.sh` (reversible ACPI `_OSI` OSYS spoof).

Build any C tool with the command in its header comment (usually
`gcc -O2 -o <name> <name>.c`).
