# GXFP5120 — Linux driver for the Goodix "Milan" sensor behind the ITE EC

Linux support for the fingerprint reader in the **Huawei MateBook D 14 (2020)**
(ACPI `GXFP5120`, Goodix GF3658 "Milan", solution string
`GF_ITE_EC_20063_GF3658`).

**Status: working end-to-end** — enroll, verify, fprintd, PAM (KDE lock screen +
sudo), and the sensor comes up by itself after every reboot. Developed on Debian 13 /
KDE Plasma 6.3 against libfprint v1.94.100 (patched) and fprintd 1.94.5.

> Scope: this targets the **ITE-EC variant**. USB models and the Nuvoton eSPI variant
> (`GXFP5130`) use different transports and are not supported here.

## How it works (short version)

- **Transport** — the sensor sits on Intel GSPI1 (`PCI 00:1e.3`); the ITE embedded
  controller bridges it. Userspace talks to it through `/dev/spidev0.0` (mode 0,
  10 MHz) with one GPIO pulse (`gpio17`) per response parcel.
- **Session** — TLS 1.2 pre-shared-key handshake per session, then the driver replays
  the Windows driver's per-press choreography (arm → finger-mode → image), with the
  sensor's FDT operating parameters **read live from the device** and locked per
  session (mirrors the Windows driver's calibration loop).
- **Images** — 12-bit 80×64 frames → 6→4 nibble decode → 80×61 display → row/column
  median deband → ×2 bilinear (160×122).
- **Matching** — SigFM (FAST-9 corners + unsteered BRIEF-256 + RANSAC rigid transform),
  ported from the mb13-godsquantum GXFP51A0 driver. Two frames are captured per press
  and scored against all enrolled views; the better match is kept. Acceptance:
  score ≥ 40 **and** raster ZNCC ≥ 200 (wrong-finger probes stay ≤ 6).
- **Delivery** — a libfprint `FPI` driver (`gxfp5120`) integrated via `driver/apply.sh`,
  plus a udev rule (`driver/boot-bind/`) binding `spidev` to the sensor on every boot.

## The per-device PSK

The sensor requires a 32-byte pre-shared key, unsealed by Windows from the Goodix
cache (`C:\ProgramData\Goodix\Goodix_Cache.bin`, DPAPI-protected). Extract it from
**your own Windows installation** with `bringup/psk-unseal-windows.ps1` (run in
PowerShell), then place the resulting `psk_raw32.bin` on Linux as
`/etc/gxfp5120/psk.bin`. **Never publish or share this file** — it is unique to your
sensor.

## Install (summary)

Full walkthrough: `driver/README-BUILD.md`.

1. Get the PSK (above).
2. `driver/apply.sh build/libfprint-1.94.100` → meson/ninja build →
   `sudo meson install -C _b --no-rebuild`, `sudo ldconfig`.
3. `sudo driver/boot-bind/install.sh` — spidev auto-bind at every boot, plus
   `cc90.hex` placement and the fprintd sandbox drop-in.
4. `sudo pam-auth-update` → enable the fingerprint profile (lock screen / sudo).
5. `fprintd-enroll` / `fprintd-verify` (or System Settings → Users on KDE).

## Repository layout

| path | what |
|---|---|
| `driver/gxfp5120/` | libfprint driver sources (transport, TLS, image pipeline, matcher) |
| `driver/boot-bind/` | boot-time spidev bind: udev rule + helper + installer |
| `bringup/` | bring-up tooling: capture tools, matcher harness, PSK extraction |
| `PORT-PLAN.md` | the full development log — research, dead ends, and gotchas |
| `FINDINGS-ROOT-CAUSE.md` | early transport investigation notes |

## Safety note

`bringup/` includes historical `/dev/mem` probe scripts (`dump-mmio*.sh`,
`fps-boot-test.sh`, …) from the phase *before* the spidev transport was found. On this
hardware those probes hard-froze the laptop 10+ times. They are guarded behind
`ALLOW_DEVMEM=1` — don't run them without understanding the risk. The supported
transport is plain spidev; it has never frozen the machine.

## Credits & licensing

- Driver and tooling: **LGPL-2.1-or-later** (SPDX headers in each source, see `LICENSE`).
- The matcher (`driver/gxfp5120/goodix_sift.c`, `fastbrief/`) is a port from
  **mb13-godsquantum**; those files keep their original copyright notices.
- Prior art that made this possible: **goodix-fp-dump**, **gxfp5130-linux**,
  **sigfrodr-goodixtls**, **mbd14** — see `PORT-PLAN.md` for what came from where.
- Not affiliated with Goodix or Huawei. Use at your own risk.
