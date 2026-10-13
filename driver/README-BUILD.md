# GXFP5120 libfprint driver — build & install

Driver sources live in `driver/gxfp5120/`; `driver/apply.sh` integrates them
into a libfprint tree (idempotent; patches `driver_sources` + `drivers_info`).

Target tree used here: `build/libfprint-1.94.100` (upstream tag v1.94.100,
same base the mb13 GXFP51A0 driver pins).

## Deps (once)

```sh
sudo apt-get install -y meson ninja-build libgusb-dev libpixman-1-dev
```

## Build

```sh
cd ~/Desktop/projects/fingerprint
driver/apply.sh build/libfprint-1.94.100
cd build/libfprint-1.94.100
meson setup _b \
  -Ddrivers=gxfp5120 \
  -Dintrospection=false -Ddoc=false -Dgtk-examples=false \
  -Dinstalled-tests=false -Dudev_hwdb=disabled \
  --prefix=/usr --libdir=lib/x86_64-linux-gnu
ninja -C _b
```

(`drivers=gxfp5120` builds only this driver — keeps the dependency surface
minimal. `libfprint-2.so.2` soname is unchanged, fprintd 1.94.5 keeps working.)

## Install over the distro library

```sh
# ONE-TIME backup — keep it OUT of /usr/lib: ldconfig scans that directory and
# will repoint the libfprint-2.so.2 soname symlink at any second file that
# claims the same SONAME (that is exactly how a stale backup silently wins).
sudo cp -a /usr/lib/x86_64-linux-gnu/libfprint-2.so.2.0.0 \
           /var/backups/libfprint-2.so.2.0.0.distro-backup

sudo meson install -C _b --no-rebuild   # avoids root-owned regen files
sudo ldconfig
sudo pkill -f fprintd                    # dbus re-activates fresh on demand
```

(Do NOT re-run the backup cp after installing — it would overwrite the
pristine backup with our build. `systemctl restart fprintd` also works but
the unit is D-Bus-activated; pkill is the simplest reliable reset.)

## Runtime files + fprintd access

Beyond the library itself, three things must exist on the system:

- `/etc/gxfp5120/psk.bin` — the per-device PSK (see the top-level README).
- `/etc/gxfp5120/cc90.hex` — the sensor config frame. **Device open fails without it.**
- a fprintd **sandbox drop-in** — stock `fprintd.service` cannot open `/dev/spidev0.0`
  or `/dev/gpiochip0` (its `DeviceAllow` list doesn't cover those device classes).

`driver/boot-bind/install.sh` installs the last two (plus the boot-time spidev bind).
Only the PSK has to be provided manually.

## Rollback

```sh
sudo cp -a /var/backups/libfprint-2.so.2.0.0.distro-backup \
           /usr/lib/x86_64-linux-gnu/libfprint-2.so.2.0.0
sudo ldconfig && sudo pkill -f fprintd
# or: reinstall the libfprint-2-2 package
```

## Test

```sh
fprintd-enroll      # 5 presses, finger on sensor each prompt
fprintd-verify
ls /var/lib/fprint/$(whoami)/   # stored template (driver-private SigFM blob)
```

KDE login/unlock uses fprintd through PAM (`libpam-fprintd` is installed;
enable with `sudo pam-auth-update` → "Fingerprint authentication" if needed).

## Runtime knobs (env; fprintd runs as root)

- `GXFP5120_SPIDEV`      default `/dev/spidev0.0`
- `GXFP5120_GPIOCHIP`    default `/dev/gpiochip0`
- `GXFP5120_GPIO_LINE`   default `17`
- `GXFP5120_SPI_HZ`      default `10000000`
- `GXFP5120_PSK`         PSK file override (default: `/etc/gxfp5120/psk.bin`,
  then `psk_raw32.bin` in the project)
- `GXFP5120_CONFIG`      90-config hex override (default: `/etc/gxfp5120/cc90.hex`,
  then `driver/gxfp5120/cc90.hex`)
- `GXFP5120_DUMP_DIR`    if set, every capture is dumped as `<dir>/capNNN.content.bin`

Session keys are cached in `/var/lib/fprint/gxfp5120-session.txt` (the tools also check `/tmp/gxfp-session.txt`) so a
fprintd restart can rejoin a still-mounted sensor session without re-handshaking.
