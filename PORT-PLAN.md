# PORT-PLAN — GXFP5120 (Goodix GF3658 "Milan") fingerprint on Linux

Researched 2026-10-12 (evening session). Everything below is from **static analysis and
Windows-side logs** — no Linux hardware probing was performed to produce this document.

---

## 0. TL;DR

- Sensor is **behind the ITE embedded controller**, not on the Intel SPI bus the DSDT's
  SPBA device advertises (that resource is a decoy / alternative wiring).
- The **sensor protocol is fully decoded and matches the working MB13 project**
  (same GF3658/ST411 Milan silicon): outer A0-frames + inner cmd-frames with known checksums.
- The host↔EC transport adds a wrapper: **`cc f2 <counter LE16> <milan frame>`**, written via
  the `ITE_EC_SPI_WRITE` path; responses arrive via the **GpioInt (SPBA pin 0x09000011 → gpio17)
  IRQ** and are read out as Milan frames.
- **RESOLVED (evening, 18:50)**: the hardware resource is the **Intel SPI bus — GSPI1 /
  `spidev0.0`, 10 MHz** (DSDT `SpiSerialBusV2` on `\_SB.PC00.SPI1`). Windows opens it through
  Microsoft's in-box Resource Hub (`\\.\RESOURCE_HUB\<%016I64x>`, rhproxy); failure is logged as
  **"Open SPI Failed"** in `MilanEvtDevicePrepareHardware`. The ITE EC bridge sits on that SPI
  link. Transport selection by HardwareID: `ACPI\GXFP5120` → **bus type 1 (ITE)**;
  `ACPI\GXFP5130` → Nuvoton eSPI (the gxfp5130-linux project's path); USB models → other types.
- Next steps: (1) crash capture — re-scoped to MMIO-class experiments only, (2) staged spidev
  first-contact test (safe class: kernel SPI driver — this class has never frozen the laptop),
  (3) port the driver + Milan state machine.

---

## 1. The Windows stack (evidence: `windows-driver/*`, live EVTX log)

Components: `gfspi.dll` (UMDF driver, ACPI\GXFP5120) + `EngineAdapter.dll`
(origin `F:\git\huawei_win\winfpcode\Milan_Watt\MilanSpi\adapters\engine_adapter`),
`AlgoMilan.dll`, `GoodixEventLog.dll`, `SessionService.exe`.
Solution string logged by the engine: **`1.1.17.140_GF_ITE_EC_20063_GF3658_2504_EC`**.

### 1.1 Transport chain (from disasm + log)

```
Engine (Milan protocol)  →  SpiSendDataToDevice (log: cmd0-cmd1-Len-ackt-ec:...)
  →  ITE_EC_SPI_WRITE      (gfspi.dll @ VA 0x18000fe78; log: "write headcount 0x%04x",
                            "ITE write data:0x…", "spi write Error code")
  →  frame builder: [cc f2][counter LE16][milan outer][milan inner][pad to 4B]
  →  PeripheralWriteWrapper (@0x18001055c) — dispatches by global bus type (@0x1800c5430):
       1 = ITE (this laptop)   5 = two-part writer   0xC = NUVOTON_EC_ESPI_WRITE
  →  thunk via global vtable (@0x1800eec30, ctx @0x1800eec38), index 0x70/0x72/0x73/0x74…
  →  device I/O to "\\.\RESOURCE_HUB\<%016I64x>" (Microsoft Resource Hub, rhproxy) — this handle
     IS the SPI resource on \_SB.PC00.SPI1 (see §4); writes/reads on it are SPI transfers
```

- **Read path**: `MilanEvtInterruptIsr` — EC raises IRQ → driver reads header (length) then
  payload ("data len N", "read data done", "data::0x…"); big transfers ~7.7 KB (image).
  Read helper logs "read data from mcu ret:0x%x, length: %d".
- **Power/init**: `MilanEvtDeviceD0Entry` → `init_FPSensor` ("OTP data valid, download config 1")
  → `_TlsInitAndHandShake` (TLS handshake ~1100 ms) → enroll/verify. D0Exit → "enter S0 idle".
- The heartbeat/init command set includes Milan `NotifyPowerState`/sleep cleanup — see §2.
- `oem5.inf`: `UmdfDirectHardwareAccess=AllowDirectHardwareAccess`; UMDF service `gfspi`;
  winbio database GUID `D38EDC56-D60C-4F85-8C5A-B18086A61B1E`; device name
  "Goodix Fingerprint SPI Device"; supports ACPI\GXFP5120, ACPI\GXFP5130,
  USB\VID_27C6&PID_5120/5135/5125 in one codebase.
- The Resource Hub is **Microsoft in-box** (`rhproxy.sys` contains `\Device\RESOURCE_HUB\%0*I64x`);
  its resource IDs are supplied from runtime configuration (not found in any binary as constants).

### 1.2 The ITE wrapper (write direction) — from live log frames

```
cc f2 | <ctr lo> <ctr hi> | <milan outer> | <milan inner> | 00 00          (pad to 4-byte)
e.g.  ccf2 f328 a0 06 00 a6 20 03 00 01 00 86 00 00     ("write headcount 0x28f3")
```

- Counter = 16-bit **little-endian**, incremented per EC command ("headcount"), wrap ok.
- Frame padded to 4-byte alignment; total = 4 (header) + payload + pad; if >0x100 it is sent in
  ≤256-byte chunks (disasm @0x18000ff5d-0x1800102e0).

---

## 2. The sensor protocol (Milan) — matches MB13 project exactly

Sources: our live Windows log frames **and** `refs/mb13-godsquantum/fingerprint/docs/protocol.md`
(same GF3658 silicon, working driver — treat as protocol bible).

```
Outer:  A0 <len> 00 <csum>;            csum = (A0 + len + 0x00) & 0xFF
Inner:  <cmd> <len_lo> <len_hi> <payload…> <csum>;
        csum = (0xAA - cmd - len_lo - len_hi - sum(payload)) & 0xFF
        cmd  = (cmd0 << 4) | (cmd1 << 1)
```

Commands observed working on **our** laptop (from log; map ≈ gxfp5130 constants + MB13 docs):

| cmd  | cmd0,1 | meaning (working hypothesis)            |
|------|--------|------------------------------------------|
| 0x20 | 2,0    | state/keepalive (first frame after wake)|
| 0x32/0x34/0x36 | 3,1 / 3,2 / 3,3 | image/fdt phases (3,3 carries 14B payload) |
| 0x82 | 8,1    | `0xa9 82 06 00 00 82 00 02 00 9e` seen in log |
| 0x90 | 9,0    | upload config MCU (gxfp5130: 0x90)      |
| 0x96 | 9,3    | DriverState:Install (MB13 confirmed)     |
| 0xA8 | 10,4   | GetEvkVersion / firmware version         |
| 0xAE | 10,7   | query MCU state (gxfp5130: 0xAE)         |
| 0xB0 | 11,0   | ACK — payload[0] = acked cmd (log: `b0 03 00 20 01 d6`) |
| 0xD0/0xD2/0xD4 | 13,0/1/2 | sleep-cleanup / TLS-unlock variants |
| 0xE4 | 14,2   | ? (len 8, ack 1000ms)                    |

ACK/retry semantics, reset behavior, and the EVK flow: see MB13 `docs/protocol.md`
(they verified against Goodix driver 1.1.141.36/40 — very close to our 1.1.17.140 line).

---

## 3. Our ACPI (the resources the platform declares)

- **SPBA** (`_HID GXFP5120`, DSDT 59157): `_CRS` = `SpiSerialBusV2` on `\_SB.PC00.SPI1`
  10 MHz mode 0 + one `GpioInt` (pin list = `GNUM(0x09000011)` → gpio17, edge, active high,
  ExclusiveAndWake). `_INI`: `SHPO(0x09000011, 1)` (TX bit ownership). **No reset GPIO.**
  `_DSM` (UUID cc58b68a-…) returns only func0 {0x01} — inert. `_STA` = FPSW.
- **H_EC** (PNP0C09): windows at 0x62/0x66 (standard), 0x68/0x6C (`ECMD`), 0x72/0x73
  (`HQRE`/`HQWE`), 0x25C/0x25D (`EIOC`); `SRAM` (cmd 0x7E on 0x62/0x66).
- **EC RAM windows**: `ERAM` @0xFE800700 len 0xFF (battery/temps TP00-09); `SMA2` @0xFE800800
  len 0x80 = command mailbox (CMDB/STAT/NUMB/DAT0-2) with commands 0x29/0x80/0x81 + generic
  `ECCC(cmd, d0, d1, d2)`; helpers `RDER` (0x80) / `WTER` (0x81, gated by 0x29/0x4D).
- **OGNS** @0x45AC3D18: `ECFG, HGSL, AKVA, FPSW` — BIOS↔EC fingerprint handshake; `_QAA`
  reads EC KECD, computes AKVA, writes it back to EC regs 0x18/0x19 via `HQWE`.
- **GNVS** fields: GFPS, GFPI, FPTT, SDS7.
- 0xFE800000 is the EC shared-memory page family — the gxfp5130's mailbox lives at
  0xFE800000 on their laptop; our windows sit at +0x700 / +0x800 in the same page.

---

## 4. RESOLVED — the resource is the Intel SPI bus (GSPI1 / spidev0.0)

Evidence (gfspi.dll disassembly, 2026-10-12 evening):

- `MilanEvtDevicePrepareHardware` (source `...\milanspi\milanfusb\device.c`) selects the transport
  by HardwareID string:
  `ACPI\GXFP5120` → bus type **1 (ITE)** · `ACPI\GXFP5130` → 0xC (Nuvoton eSPI) ·
  `USB\VID_27C6&PID_51xx` → types 2/7/8/0xD/0xE/4/9/0xA/0xB · else "HardwareID not match".
- For bus type 1 it opens a device via `\\.\RESOURCE_HUB\%016I64x` and logs failure as
  "**Open SPI Failed with 0x%x**" (with "SPI resource not found" / "Interrupt resource not
  found" alongside) — i.e. the Resource Hub handle **is the SPI resource**; the interrupt
  resource is the GpioInt. Conclusion: the ITE EC bridge hangs on the DSDT's
  `SpiSerialBusV2` → `\_SB.PC00.SPI1` (Intel GSPI1 = PCI 00:1e.3 = Linux `spidev0.0` (pxa2xx-spi.3)),
  10 MHz, mode 0.
- This explains the earlier silence on raw SPI: those attempts sent bare Milan frames without the
  `cc f2 <counter>` wrapper and without any post-wake init sequence.

**PROVEN ON HARDWARE 2026-10-12 ~19:20** (spidev0.0, mode 0, 10 MHz, no crash risk):

```
WRITE:  [cc f2 <ctr LE16>] + <milan outer+inner frame> + pad to 4B   (single SPI transfer)
QUIET:  ~4 ms (the bridge queues the response during this gap)
READ:   opcode [bb f1 00 00] + zeros; 64-BYTE transfer chunks (16/20-byte transfers lose
        4-byte seams; 64 is lossless); first 4 bytes of each transfer = exchange-buffer status
PARSE:  scan received stream for a0/b0/c0 outer headers, validate csum = (b0+b1+b2)&0xff
        (responses are one-shot: they appear at the first read after the quiet window, and
        loop/repeat in the exchange buffer for a while)
```

Verified live on Linux (each also matches the Windows log byte-for-byte where comparable):
- cmd 0x20 → `a0 06 00 a6 b0 03 00 20 01 d6` (ACK)
- cmd 0xD4 → `a0 06 00 a6 b0 03 00 d4 01 22` (TLS-unlock ACK — identical to Windows .870 response)
- cmd 0xA8 → ACK `…b0 03 00 a8 01 4e` + version frame
  `a0 14 00 b4 a8 11 00 "GF_ITE_EC_20063" 00 e2` — the exact solution string Windows logs
- cmd 0xAE → `a0 18 00 b8 ae 15 00 02 00 31 03 00 …` (live MCU state)
- Malformed frame (wrong payload) → silently ignored (no ACK) — bridge validates frames.
- ESP: counter value does NOT gate acceptance (swept 0x3d00–0x6fff and 0x0000/0x0100 all fine).

Tooling built tonight (all in `bringup/`, source + binary):
`cc-first-contact` (single frame + patterned reads) · `cc-capture` (write + response parse —
the reference implementation of the transport) · `cc-drain` (raw stream dump) ·
`cc-scan` (address-window scan; established the exchange-buffer layout) · `cc-sweep` (counter sweep).

---

## 5. Safety rails (do not bypass)

- **/dev/mem EC/PCH probes remain forbidden** until crash capture is in place (see
  `crashlog/`). The guards added to all six `/dev/mem` scripts (`ALLOW_DEVMEM=1`) stay.
- Never read outside the declared EC windows (ERAM 0xFF / SMA2 0x80 at the addresses above);
  the 17:46 death came from an 8 KB read starting at 0xFE800700.
- Crash capture (netconsole or equivalent) before any new MMIO-class experiments.
- USB key / Windows partition mounted RO at `/media/<user>/<win-volume>`
  (`udisksctl unmount -b /dev/nvme0n1p3` to release).

---

## 6. Implementation sketch (when unblocked)

1. **Transport** (userspace first): spidev0.0 + libgpiod(gpio17) implementing
   `cc f2 <ctr> <milan>` write + IRQ-driven read; then a kernel module exposing `/dev/gxfp`
   if that's the chosen UX (mirror `refs/gxfp5130-linux` char-device API).
2. **Protocol**: port the Milan state machine from `refs/mb13-godsquantum/fingerprint/research/`
   (`milan_packet.c`, `milan_rx.c`, `milan_attempt.c`) + the ACK/retry rules from their
   `docs/protocol.md`; align command table with §2 and the live log.
3. **Init sequence**: NOP → DriverState:Install → GetEvkVersion → TLS unlock (0xD4) →
   (config upload 0x90 if needed) → capture. Mirror the Windows D0Entry trace from the EVTX.
4. **PSK**: extract the existing key from the Windows side (`C:\ProgramData\Goodix\goodix.dat`
   header `S2H826.` + blob; also `goodix_calib.dat`) instead of re-provisioning — keeps Windows
   login working. See gxfp5130 `userspace/PSK.md` for the extraction approach.
5. **libfprint/fprintd**: fork GodsQuantum's libfprint integration (MB13, same silicon) or
   gxfp5130's SIGFM fork; KDE/PAM integration after enroll/verify work.

---

## 8. READ PATH deep-dive + LIVE FINGER DETECTION (2026-10-12 late)

**MILESTONE: live finger detection works on Linux** (`bringup/cc-touch`):
Windows init sequence + `0x36` fdt probes every 2 s → each probe returns a fresh
fdt frame (24 B, cmd 0x36). Finger present ⇒ six LE16 values drop from ~0x160s to
~0x090s (mean `0x16b → ~0x0a0`; Windows' own touch signature was `0x16b → ~0x0d0`).
14/14 user touches detected. On detection the tool auto-writes `0x20` (image request).

**Read-path findings** (tools: `cc-drain`, `cc-bigread`):
- MERGED single transfer `[bb f1 00 00][zeros…]`: MISO = `[4B status][window]`.
  Works for frames at/near the window start (acks, 24–28 B). Repeated reads do not
  advance (window loops / freezes).
- **TWO-DESCRIPTOR single ioctl** (transfer[0] = 4 B `bb f1 00 00`, transfer[1] = 256 B
  zero-read) = exactly what gfspi's helper builds (0x18000fde4 → 0x180011178, two
  descriptors). Phase A MISO = 0xbb idle; phase B = the 256 B exchange window, which
  WALKS: advances 4–8 B/read in calm state, loops over a ~256 B ring, glitches on bursts.
- Two separate ioctls / cs_change=1 variants: dead (all 0xbb).
- Exchange ring ≈ 256 B. After a bus gap (≥50 ms) the first read presents a big
  response's HEAD at window start (navbase: `a0 6d 09 16 50 6a 09 00 …`; image: `c0 0d 1e eb …`).
  The BODY beyond ~256 B never enters the ring on its own; the walk cannot pull it;
  longer gaps (0.5 s) lose the head (overwritten by idle stream).
- Windows reads big bodies across multiple ISR rounds (the ISR returns 1 = "more
  expected"); the ITE body-fill primitive is not yet located (0x18007ae10 = memset;
  the Nuvoton branch memcpy's 0xE00 B from local buffer+0x200).
- Windows EVTX: `data::0x…` = complete small frames; `test::0x…` = **first 544 B preview**
  of every big frame (99 dumps). Headers validated: image = `C0 0d 1e eb | 20 0a 1e 00 |
  payload 7690` (≈12-bit packed 5120 px = 7680 B + 9 B header + csum; engine regroups to
  16-bit 64×80 = 10240 B); navbase = `A0 6d 09 16 | 50 6a 09 00 | 2410 B`.

**Next (highest priority): IRQ-paced reads** — one `[4+256]` parcel per gpio17 edge
(the bridge raises the line per parcel; trains of edges observed after writes).
Then: image capture on touch → decode 12-bit → libfprint/fprintd.

## 9. TLS SECURE SESSION REPLAYED (2026-10-12 ~21:00)

Full D0Entry pre-TLS sequence captured & replayed (`bringup/cc-init2`, `cc-tlsreplay`):
`D4 → A8 → 97-Install → AE → A8 → E4(challenge; static 44 B response) → A2 → 82 →
A6 (65 B "S2H826." blob — identical to the first 65 B of Windows
`C:\ProgramData\Goodix\goodix.dat`) → A2 → 70 → 98 → 90 (224 B config upload;
verbatim hex in `/tmp/cc90.hex`) → D1` → **the sensor then sends a TLS 1.2
ClientHello unprompted** (B0-type outer frame carrying plaintext TLS records).

- Cipher: **0x00AE = TLS_PSK_WITH_AES_128_GCM_SHA256**. Sensor = TLS *client*
  (PSK identity literally "Client_identity"), host = TLS server.
- The sensor's ClientHello random is semi-static (observed byte-identical to a
  Windows capture, then changing — treat as sensor-state-derived, not random).
- **The full handshake is replayable**: wrote the byte-exact server flight
  (ServerHello/ServerHelloDone/CCS/Finished) captured from the 10:43 EVTX session
  (extracted to `/tmp/tls-{sh,shd,ccs,fin}.hex`); the sensor accepted it (it
  recomputed its own Finished and continued). Whether it cryptographically
  validates the server Finished is uncertain (weak firmware likely).
- MCU-state AE response decodes session state: trailing byte-pair + a `00 90 63`
  vs `00 00 63` marker. Post-TLS Windows sessions = states 04-09 with `90`;
  pre-TLS = 02/03 without. **After the replay our session reports `05 05`** and
  fdt readings become byte-identical to the Windows login session
  (`0161 0182 014e 0171 015b 017c`).
- Post-TLS touch test: 5/5 touches detected (mean drops to ~0x08d) — image body
  still did not stream.

**Bulk reads remain the one blocker**: small frames read fine in every mode;
navbase (2410 B)/image (7690 B) never enter the 256 B exchange window (slides
~4 B/read regardless of phase-A length; opcode length-field sweep inconclusive).
All attempted read modes are in §8. Remaining leads: disasm the frame validator
`0x180014ec4` / `0x1800206f8`; find the un-replayed Windows step that triggers
bulk delivery; PSK extraction (DPAPI `Goodix_Cache.bin` via the gxfp5130
`unseal_bb010002.py`, Windows-side) is NOT needed for the replay path.

## 10. Bulk-read attack #2 (2026-10-12 late-late)

New mechanics measured (all from `cc-bigread` variants; session in post-TLS state):
- **Exchange ring ≈ 640 B** (phase-A length `pa` cycles with period 88; positions
  repeat after ~640 B of stream).
- **`pa` (phase-A transfer length) = a read-position selector**: `pa=512+88k` lands the
  window on the 0x50 ACK region; `pa=520+88k` lands **exactly on the navbase frame head**
  (`a0 6d 09 16 50 6a 09 00…`) — 3/3 reproducible; mid-cycle values land elsewhere in
  the ring. This "landing" works via a fresh `[write 0x50 -> 55 ms gap -> single read(pa)]`.
- From a head landing, a back-to-back read walk advances **~4–8 B/read with 248-byte
  overlap**; captures ~600 B of clean frame stream before the ring content jumps.
  Repeated rounds: head fragment captured (~600 B stable across rounds within ~1 min;
  drifts over minutes — the response carries fresh measurements).
- Jump-stitched full-frame reconstruction did NOT validate (csum mismatch) — bytes are
  lost at ring jumps; the ring cannot hold the 2.4 KB frame at once.
- Read-opcode sweeps: `bb f0/f1`, length field bytes, incrementing counter bytes —
  none change the walk rate. The curl `/ Message too long`: spidev max transfer = 4096 B
  (`/sys/module/spidev/parameters/bufsiz`; raise via modprobe if needed).
- The Windows driver pulls the 2417 B body in ~10 consecutive `[4+256]` reads over ~12 ms
  (one parcel per ISR round); our 4 B/read crawl ≈ 600× too slow — the per-parcel
  consume/advance handshake remains unidentified.

**Next idea (unexplored): systematic opcode/parameter fuzz of the read cycle** (bounded,
spidev = safe class): sweep `[bb xx yy zz]` byte2/byte3 values and lengths, watching the
walk rate/parcel progression; plus re-test `pa` landing + walk combinations per opcode.
Note the write counter `[cc f2 <ctr LE16>]` is confirmed irrelevant both directions.

## 11. PULSES & PARCELS — the IRQ-paced read (2026-10-12, final round)

**The bridge signals each parcel with a gpio17 pulse — confirmed live:**
- A fresh `0x50` write triggers a pulse STORM: **11 rising edges ~1 ms apart** = 1 ack
  parcel + 10 frame parcels (navbase 2417 B ÷ 256 = 10).
- Tool `bringup/cc-irqread` (raw GPIO v2 chardev + SPI in one process) reads one
  `[4+256]` parcel per pulse, in-process: captures all 11 parcels within ~22 ms
  (vs the ~15 ms/read bash loop which loses the storm).
- Parcel windows = **disjoint 256 B blocks** (zero cross-read overlap — the window is
  replaced per parcel; between updates a re-read returns the identical block).
- Windows ISR confirmed (disasm): exactly ONE `[4+256]` helper read per ISR invocation
  and no other read call anywhere in the body-round code → the `0x18001b07c` body loop
  only memcpy's the freshly-read buffer by offset — i.e. **one parcel per interrupt**,
  the driver assembling by received-counter offset.

**Assembly status (this is the last mile):** storm capture of head+10 parcels does NOT
yet checksum-validate (inner csum). Established:
- head parcel = `a0 6d 09 16 50 6a 09 00 …` at slot 1 (always);
- a fixed 4-byte trailer `88 33 43 33` sits at slot-10 offset 112 in EVERY capture
  (stable while the payload varies) → assembly is structurally close but misaligned by
  ~4 B somewhere per parcel, or one window is not a true parcel (tearing).
- The csum is a byte-sum → the test is independent of middle-parcel ORDER (only the
  head slice, the 8 full middle parcels, and the last parcel's first 112 B matter):
  no choice of last parcel validates → **the multiset of captured windows is wrong**
  (≥1 window ≠ its true parcel; per-read timing variants produce deterministic per-delay
  tearing — delayed reads are visibly torn, no-delay runs are clean but still fail).
- Windows ground truth available: the EVTX `test::` dumps = the ISR's own 544 B view of
  big frames (`win-navbase-544.bin` for the 10:43 navbase; 99 dumps incl. image frames)
  — structure (fixed bytes at fixed offsets) matches our capture alignment.

**Next session's recipe:** multi-storm clean capture (no post-pulse delay, double-read
per pulse to detect tearing), cross-run slot comparison to find the bad/missing window
(content drifts slowly, so slots within a minute compare), then csum-validate; the same
storm reader gives the image in one go (`0x20` on touch → 31 parcels).

## 12. THE PAYLOADS ARE ENCRYPTED (2026-10-12, discovery)

Comparing repeated captures of the same finger across the Windows EVTX (three logins in
one minute): the image frame payloads share only **12/488 bytes** — and our own navbase
captures differ in ~85% of bytes between runs seconds apart. Meanwhile small frames
(fdt values, acks) are plaintext. Conclusion: **post-TLS, the sensor encrypts the bulk
payloads** (navbase, image) — the frame header + outer csum remain plaintext, so
capture/assembly validation via the frame csum is unaffected, but the *content* needs
decryption.

Driver evidence (strings): gfspi.dll embeds **mbedTLS** (TLS-PSK, "Client_identity");
EngineAdapter.dll contains the vendor **Sec*** crypto module:
`SecAes128CbcNopad`, `SecAes256CbcNopad`, `SecAes256CbcPKCS7pad(Encrypt/Decrypt)`,
`SecAes256GcmNopad`, `SecHmacSha256`, `SecPbkdf2`, `SecSha256/512`, and the key
assembly hint: **`Alloc intermediate buffer for assemble [Nonce || 0xffffffe2 ||
SHA256(identity)]`** — i.e. a KDF info string (purpose tag 0xffffffe2, identity =
"Client_identity"). So the payload = AES-256-GCM under a per-message key derived from
a device secret (the TLS PSK) + nonce + purpose + SHA256(identity).

The device secret lives on the Windows side (DPAPI-sealed `Goodix_Cache.bin`; the
gxfp5130 project's `userspace/tools/unseal_bb010002.py` shows the format:
`[DPAPI blob][seed8]`, entropy = pure function of seed8). **Decision point (user):**
(A) user performs the key extraction themselves and provides the key (or boots Windows
and runs the reference tool there — output = 32-byte PSK), then we implement the
decryption pipeline offline; (B) re-provision a new PSK onto the sensor (makes Linux
independent; **breaks Windows login** — needs the provisioning command on our transport);
(C) leave encrypted-payload work aside and keep the working parts (detection etc.).
No extraction of the stored credential will be performed without explicit user
authorization.

## 7. Evidence index

| What | Where |
|---|---|
| Live Windows debug log (init, TLS, enroll, all frames) | `windows-driver/Goodix-FingerprintProvider%4Debug.evtx` (20 MB) |
| Windows transport binaries + INF | `windows-driver/{gfspi,EngineAdapter,AlgoMilan,GoodixEventLog}.dll`, `oem5.inf` |
| Reference: EC-mailbox architecture, constants, libfprint | `refs/gxfp5130-linux/` |
| Reference: same-silicon protocol bible + research code | `refs/mb13-godsquantum/fingerprint/` |
| ACPI tables (full) | `~/Desktop/projects/acpi-tables/*.dsl` |
| Crash history + logs | `crashlog/{events.jsonl,events.db}`, `FINDINGS-ROOT-CAUSE.md` |
| Key gfspi.dll VAs | ITE write fn 0x18000fe78 · PeripheralWriteWrapper 0x18001055c · hub open 0x180010760 / 0x180010884 / 0x180010d18 · vtable globals 0x1800eec30 / 0x1800eec38 |

## 13. LIVE END-TO-END CAPTURE — DONE (2026-10-13 night)

Working tool: `bringup/cc-imageread` (built with `-lcrypto`). Run:
`sudo ./cc-imageread /dev/spidev0.0 /dev/gpiochip0 17 0 10000000 /tmp/out`
Press the finger when `--- capture phase ---` prints.

Proven pipeline (3 consecutive flawless runs):
1. D0Entry replay (first frame = D5 session-cleanup `a00600a6d503000000d2`; after the handshake D4-2 + AE-af).
2. **mcu-state (0xAE) queries MUST carry a live ms timestamp** `af 06 00 | 55 <ms LE16> 00 00 | csum` (ms = monotonic ms & 0xffff). With a stale timestamp the sensor answers but does NOT mount (`tls=0`, capture commands ignored).
3. TLS: generated server flight (own SH random; Finished computed in-process; see §9 corrections: cipher = 0x00AE = **TLS_PSK_WITH_AES_128_CBC_SHA256** (not GCM); premaster RFC4279; key_block order = client_MAC|server_MAC|client_key|server_key). Sensor validates the server Finished (alert 15 03 03 00 40 on failure) and sets `isTlsConnected` (mcu-state payload[1] bit 0x02).
4. Capture: `36(fdt)` → `50(nav 2417B)` → `36` → `82` → `20` at ~16-32ms gaps (bytes in §9). All ACKed when tls=1.
5. Image = ONE TLS record: outer `b0 45 1e 13` (len16 7749) + `17 03 03 1e 40` + 7744 body. Read via **one [bb f1 + 256] parcel per gpio17 pulse** (no double reads); assemble 7753 bytes sequentially; outer csum validates.
6. Decrypt with client_write_key → pt = 8B header (`20 0a 1e 00 00 00 00 00`) + **7680B = 5120 px 12-bit** + trailer (sensor-session MAC layout = nonstandard/random-padded; ignore MAC; content is structure-validated).
7. Pixels: 6→4 decode (`p0=((b0&0xf)<<8)|b1; p1=(b3<<4)|(b0>>4); p2=((b5&0xf)<<8)|b2; p3=(b4<<4)|(b5>>4)`); wire = 64-px rows × 80 with ~2-3 dark marker px per row start; **display = `disp[y*80+x] = px[x*64+y]` (80 wide × 64 tall, transposed)**.
8. Validation: two captures of the same finger → Pearson correlation **+0.969**. Renders: `captures/fp7.png`, `fp8.png`, `fp-mean.png` (ridges vertical, contact blob correct).

Next: package as libfprint TOD driver (port from `refs/mb13-godsquantum` + `refs/goodix-fp-dump` `driver_51x0_spi.py`), matcher = mb13 SigFM (see §14), then fprintd + PAM/KDE login, and OTP/DAC per-device calibration from the OTP frame (tcode/delta parsing in `driver_51x0_spi.py`).

## 14. PHASE 2 — MATCHER VALIDATION — DONE (2026-10-13 night)

Dataset: `/tmp/enroll/cap1-10.content.bin` (10 presses, same finger) + `/tmp/other/cap1-5.content.bin` (5 presses, other finger), captured with `cc-cap`, decoded to display orientation 80×61 (3 marker rows dropped).

Discovery: all captures carry heavy **vertical striping** = per-wire-row banding (display columns = wire rows). Both reference drivers remove it (mb13: bg-frame subtraction at open; sigfrodr: per-row + per-column median). Median debanding needs no extra capture — chosen.

Harness: `bringup/gxfp-match.c`:
`gcc -O2 -o gxfp-match gxfp-match.c ../refs/mb13-godsquantum/fingerprint/driver/goodix51a0/goodix_sift.c ../refs/mb13-godsquantum/fingerprint/driver/goodix51a0/fastbrief/sigfm.c -I../refs/mb13-godsquantum/fingerprint/driver/goodix51a0 $(pkg-config --cflags --libs glib-2.0) -lm`
`./gxfp-match /tmp/enroll /tmp/other <scale>` — prints per-view best genuine/impostor and separation.

Results (genuine min vs impostor max, pairwise max over set):
| matcher / pipeline | genuine min | impostor max | gap |
|---|---|---|---|
| cv2 SIFT + RootSIFT + ratio0.8 + RANSAC (Python, 320×244) | 12 | 7 | +5 |
| sigfrodr goodix_sift.c, nearest ×6 | 15 | 10 | +5 |
| mb13 SigFM (FAST-9 + unsteered BRIEF-256 + RANSAC), native | 33 | 37 | −4 |
| mb13 SigFM, bilinear ×2 (no deband) | 27 | 15 | +12 |
| mb13 SigFM, bilinear ×3 (no deband) | 26 | 13 | +13 |
| mb13 SigFM, deband, native | 26 | 29 | −3 |
| **mb13 SigFM, deband, bilinear ×2 (160×122) — CHOSEN** | **26** | **12** | **+14** |
| mb13 SigFM, deband, bilinear ×3 | 27 | 16 | +11 |

Chosen pipeline (Phase 3): 6→4 decode → display 80×61 (drop 3 marker rows) → row/col median deband → bilinear ×2 → `gx_sift_extract` (internal 1-99% stretch + unsharp) → `gx_sift_match`. Threshold ≈ 20 (genuine ≥26, impostor ≤12). Weak genuine pairs = cap4/cap8 (~26-31; partial/off-pose presses) — still above threshold.

Phase 3 must also port from mb13's real driver: contrast quality gate (`std < GOODIX_FINGER_STD/3` → reject), multi-view `gx_sift_match_mask` consistency verification, OTP/DAC calibration; then fprintd + PAM/KDE.

## 15. PHASE 3 — LIBFPRINT DRIVER SOURCES WRITTEN (2026-10-13 night)

`driver/gxfp5120/` — FpDevice subclass (FP_TYPE_DEVICE, PRESS, 5 stages), one capture per decision:
- `gxfp5120-ec.c` — spidev + GPIO v2 uapi transport (from cc-cap)
- `gxfp5120-tls.c` — live TLS 1.2 PSK server flight + session cache (from cc-cap)
- `gxfp5120-proto.c` — D0Entry/TLS mount, FDT finger gate, in-memory parcel capture, early image exit, decrypt; warm path via `/tmp/gxfp-session.txt`
- `gxfp5120-image.c` — 6→4 decode → 80×61 → median deband → bilinear ×2 (PORT-PLAN §14 pipeline)
- `goodix_sift.c` + `fastbrief/sigfm.c` — mb13 SigFM matcher (LGPL), threshold 20
- Templates: print "fpi-data" GVariant (u + aay of SigFM serializations), version 1
- Build: `driver/apply.sh build/libfprint-1.94.100` (patches meson, copies sources) + `README-BUILD.md`
- Base: upstream tag v1.94.100 (same as mb13). fprintd 1.94.5 + libpam-fprintd already on the system.
- Retry semantics: bad capture → FP_DEVICE_RETRY_GENERAL (fprintd loops); cancel → G_IO_ERROR_CANCELLED.

Open items for the first hardware session:
1. Second capture within one mount (enroll stages 2-5): flow re-arms with the same schedule then remounts on failure — verify, and port Windows' alternate preambles (34-frame variants in Windows log) if needed.
2. Quality gate GX_GATE_STD=25 and GX_MIN_KEYPOINTS=40 are conservative placeholders — tune from dumps.
3. After enroll/verify CLI passes: pam-auth-update (fingerprint) for KDE login/lock/sudo.

### 15b. Install gotchas found during bring-up (2026-10-13)
- fprintd.service sandbox: `ProtectHome=true` + `PrivateTmp=true` → driver fallback paths under /home and /tmp are invisible to the daemon. PSK + cc90.hex must be in /etc/gxfp5120/; session cache now lives in /var/lib/fprint (StateDirectory).
- fprintd.service DeviceAllow: stock list (`char-spi`, `char-usb_device`, ...) does not resolve `spidev` class or gpiochip → drop-in `/etc/systemd/system/fprintd.service.d/gxfp5120.conf` adds `DeviceAllow=/dev/spidev0.0 rw` + `/dev/gpiochip0 rw`.
- **ldconfig soname trap**: any backup copy left inside /usr/lib/x86_64-linux-gnu that shares SONAME libfprint-2.so.2 makes ldconfig repoint libfprint-2.so.2 at it (lexicographic preference) — keep backups in /var/backups. Symptom: driver works or vanishes depending on whether ldconfig ran after install.
- UDEV discovery: FP_DEVICE_TYPE_UDEV drivers need id_table {.udev_types = SPIDEV, .spi_acpi_id = "GXFP5120"}; HAVE_UDEV is only compiled in when some driver declares the 'udev' helper.
- fp-context.c currently carries 4 `gxfpdbg:` g_debug lines (instrumentation) — harmless, remove at final packaging.

### 15c. FIRST FULL ENROLL VIA fprintd — SUCCESS (2026-10-13 night)
`fprintd-enroll` completed: mount → 5 captures (repeat-capture in one session works) → template stored.
- Last mount bug: my CKE wait exited as soon as CKE was captured; cc-cap waits until the sensor's OWN Finished
  record (b0550005) is seen before sending CCS+Finished. Sending ours while the sensor's flight was still in
  progress → handshake never completed (AE tls=0). Fixed by mirroring cc-cap's exit-prefix waits exactly.
- Reminder: only `pkill fprintd` (not ldconfig-after-install pitfalls, see 15b) between driver reinstalls.
Next: fprintd-verify (match / no-match), pam-auth-update (fingerprint), KDE login/lock test.

### 15d. DRIVER WORKS END-TO-END (2026-10-13 late night)
`fprintd-enroll` (5 stages) + `fprintd-verify` → verify-match. Score on good presses: 92 (threshold 20); a light/partial press scored 2 → press-dependence, not a pipeline bug.
Critical contract fixes found this session (all in driver/gxfp5120/gxfp5120.c):
1. **fpi-data GVariant lifetime**: pass the FLOATING variant straight into `g_object_set` — never keep it in a g_autoptr (property dups + GValue consumes the floating ref → double-unref → dangling template → fprintd SEGV in fp_print_serialize). Cost us: corrupted templates, no-match verifies, daemon crash.
2. **Enroll contract**: one Enroll action must run ALL 5 stages inside the driver with `fpi_device_enroll_progress(dev, stage, print, NULL)` after each capture; complete with the accumulated print. (Completing after 1 capture = 1-view template.)
3. **Pre-enroll identify** (fprintd dup-check) now short-circuits on an empty gallery (no wasted press).
4. Kill stale fprintd with `systemctl kill -s SIGKILL fprintd` when it is wedged (SIGTERM can be ignored while stuck); debug drop-ins live in /etc/systemd/system/fprintd.service.d/ (debug.conf, dump.conf).
Remaining: reliability runs, PAM/KDE, remove debug drop-ins, packaging polish.

### 15e. cc-bg session + pipeline A/B (2026-10-13, ~21:00)
- New tool `bringup/cc-bg` (one mount: background frame + 5 finger frames, driver-identical timing incl. 500ms settle).
- Session-file path fix: driver saves keys to /var/lib/fprint/gxfp5120-session.txt; cc-cap/cc-bg now read that first, /tmp/gxfp-session.txt second (stale /tmp keys silently decrypt to garbage — check for `pt header 20 0a 1e 00`).
- A/B on 5 careful same-finger presses (bgsess.cap1-5):
  - current driver pipeline (deband): pairwise 24-102 — GOOD (matches §14 dataset quality).
  - bg subtraction (naive no-finger frame): breaks (DC populations differ ~1160 vs ~2770 per capture; sensor drifts DC) — mb13 handle this with adaptive54 + a dedicated FDT background capture mode; our simple approach is worse than deband, so NOT ported.
  - p54 recenter also worse than plain deband on this data. Do not add.
- Conclusion: core pipeline validated on live data. Remaining live issues were: premature gates (reverted), press quality, stale-key mixups. Next: install reverted-gate build, careful labeled far/frr test, then PAM.

### 15f. FINAL — PAM + KDE LOCK SCREEN UNLOCK (2026-10-13 night)
- pam-auth-update enabled pam_fprintd in common-auth; lock screen (kscreenlocker → PAM) unlocks with the enrolled finger — CONFIRMED at least once.
- sudo also uses fingerprint-first via common-auth (password fallback intact).
- max-tries=1 → 3 for a fairer retry window (edit both /usr/share/pam-configs/fprintd and /etc/pam.d/common-auth).
- No per-scan UI feedback is possible with fprintd 1.94 (no events reach clients during verify) — success = unlock, failure = password fallback. Cosmetic polish (custom lock-screen plugin) optional, out of scope.
- Remaining optional polish: SDDM boot-time fingerprint; remove debug drop-ins (debug.conf/dump.conf) once satisfied; drop gxfpdbg instrumentation from fp-context.c; note the driver build is local (re-run install after libfprint distro upgrades).

### 15g. SECURITY FINDING — matcher latches on banding (2026-10-13 ~21:30)
- Lock-screen + sudo verify accept ANY finger: journal shows "different finger" probes scoring 91-108 / zncc 850-936 vs template. zncc ≥0.85 between different fingers is impossible for real ridge texture → the shared signal is the session's vertical banding artifact (identical across all captures in one mount).
- Within one mount session, ANY decent-contact press matches (artifact); bad-contact presses score ~0-30. Cross-session scores drop (stripe state/DC differs) — explains why the §14 dataset (two sessions: /tmp/enroll vs /tmp/other) separated while live same-session usage does not. LESSON: validate FAR within-session with clearly different fingers.
- Actions taken: lock-screen fingerprint + pam_fprintd disabled via pam-auth-update (password-only) until the matcher is fixed; /etc/pam.d/kde-fingerprint set to pam_deny.
- REAL FIX (next): port the reference background-frame machinery: dedicated FDT background mode + OTP/DAC calibration (tcode/delta from goodix-fp-dump driver_51x0_spi.py) → bg subtraction per capture (mb13 gx51_capture_recipe background recipe + DAC regs). Then re-validate offline on fresh cc-bg captures with multiple different fingers (in-session FAR test), only then re-enable PAM.
- Note: deband-only pipeline cannot fix this; p54 recenter alone cannot fix this; naive no-mode bg frame cannot fix this (tested, §15e).

### 15h. WINDOWS PER-PRESS FLOW DISCOVERED (2026-10-13 ~21:30)
- Mined /tmp/goodix_l.txt per-capture TX sequences: the session-start capture (no finger, "ImageBase") uses exactly our replayed sequence (36-fdt1 boot → 50-nav → 36-fdt2 → 82 → 20). **Every subsequent finger press uses a DIFFERENT short arm: 34-frame → 36-finger-mode → 20-image (or 34 → 32×2 → 20) with NO boot/nav/82 frames.** We have been replaying the ImageBase sequence for every finger capture — likely why live images are artifact-dominated (sensor forced through boot/background path each time).
- The 34-frame (a0 12 00 b2 34 0f 00 0a 01 <6 pairs> ff) varies per press — likely per-press FDT zone data; v1 test uses a fixed observed instance. 36-finger-mode = our known fdt2. 32-frames (cmd 0x32, 12B data) also per-press.
- Tool `bringup/cc-fing2`: ImageBase once (full sequence) + per press 34→36→20. Next: run with shots 1-3 = enrolled finger, 4-5 = different finger (in-session FAR test); compare banding + same/different-finger score separation vs old flow. If good → port flow to driver (capture schedule for repeat presses) + bg frame per mount + subtract.

### 15i. FALSE-ACCEPT FIXED — VERIFIED (2026-10-13 ~21:35)
- Ported the Windows per-press flow into the driver (SCHED_FINGER: 34-arm -> 36-finger-mode -> 20-image for every press; SCHED_IMAGEBASE full boot sequence once at open, best-effort). Threshold 40 (+ zncc floor 300).
- Offline dump verification (daemon 199022 session): template vs verifies: same finger best 112 / 97; different fingers 10 / 0 (previously 91-108 in-session). Clean separation.
- Same session: enroll stage self-scores 26-99; genuine per-view profile consistent (two dominant template views ~70-110).
- Remaining: re-enable PAM (pam-auth-update + kde-fingerprint = pam_fprintd line), lock-screen both-finger test, sudo test, REBOOT cross-session test (template now survives cold remount? untested), soak. Cleanup pass afterwards (drop-ins, gxfpdbg).

### 15j. BOOT PERSISTENCE FIX — spidev bind (2026-10-13 late night)
- First real reboot: fingerprint dead. Root cause: `spi-GXFP5120:00` auto-enumerates at boot (spi0 ← pxa2xx-spi.3 ← intel-lpss ← PCI 00:1e.3) but nothing binds it to spidev — the bind had only ever been done manually via bind-and-test.sh. With no `/dev/spidev0.0`, fprintd (D-Bus activated — "inactive" at boot is normal) finds no device.
- Everything else survives reboot: PAM (common-auth + kde-fingerprint pam_fprintd), PSK (/etc/gxfp5120), templates/session (/var/lib/fprint), local libfprint build (FpiDeviceGxfp5120 present in /usr/lib/x86_64-linux-gnu/libfprint-2.so.2.0.0).
- Fix: `driver/boot-bind/` — `install.sh` (sudo) installs `/usr/local/sbin/gxfp5120-spidev-bind` + `/etc/udev/rules.d/70-gxfp5120-spidev.rules` (RUN on MODALIAS acpi:GXFP5120*); idempotent driver_override=spidev + bind on every SPI add. List alongside driver/apply.sh in packaging notes (redo after OS reinstall).
- spidev is **builtin** on this kernel: `modprobe spidev bufsiz=…` is a no-op and the param is r--r--r--, so bufsiz stays 4096 — fine, the final pipeline never issues >4096-byte messages (largest read 4+256 B). A bump would require kernel cmdline `spidev.bufsiz=65536` + reboot; not needed.
- Next reboot check: `ls -la /dev/spidev0.0` right after boot; then enrolled finger + different finger (settles the §15i cold-remount item).

### 15k. SECOND-FINGER ENROLL — STALE INSTALLED BUILD (2026-10-13 ~22:45)
- Symptom (KDE "Add fingerprint", a second finger): every attempt died after the 3rd scan. Daemon log: `enroll: stage 2 rejected (best prior match 2)` on every retry — the installed driver contained an enroll cross-view gate (each new view must match the prior views, floor somewhere above 5). The already-enrolled finger re-enroll scored 47-92 and passed; the new finger presses cross-scored 2-5 (the gate's expected values, but the gate is premature — §15e reverted it in source).
- Root cause: the running libfprint was the **18:16 build**; the gate revert (source 18:35) + the §15h/15i per-press flow never reached the system — the 21:41 rebuild left a **0-byte `_b/libfprint/libfprint-2.so.2.0.0`** and no install followed (installed .so mtime stuck at 18:16).
- Fix: `meson compile -C _b` (relinked clean, 22:49) + `sudo meson install -C _b --no-rebuild` + `sudo ldconfig` + `sudo systemctl restart fprintd`. The second finger enroll now passes all 5 stages; verify OK (user-confirmed).
- **LESSON**: after every source change, verify the INSTALLED artifact before testing: `ls -la /usr/lib/x86_64-linux-gnu/libfprint-2.so.2.0.0` (mtime) and `strings … | grep <marker>` (the gate string must be gone). A 0-byte .so in `_b` = the build never finished.
- Side notes for the cleanup pass: fprintd spams `file_storage_discover_prints() for user 'gxfp5120-session.txt'/'dump'` — the session file and dump dir inside `/var/lib/fprint` get probed as usernames (harmless; move the session file out of /var/lib/fprint at packaging). `fpi_print_set_type` assertion warning fires on stages 2+ (type already RAW — harmless; guard it at cleanup).
