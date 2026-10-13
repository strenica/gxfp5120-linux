# ROOT CAUSE FOUND (2026-10-12 17:4x)

## The sensor is NOT on the Intel SPI controller. It is behind the ITE EC.

Evidence — Windows driver's own debug log
(`C:\Windows\System32\winevt\Logs\Goodix-FingerprintProvider%4Debug.evtx`, live data from 2026-10-12 10:06,
enrollment succeeded: "preprocessor success, coverage:100 quality:26", "algo_ret for enroll add 0x0"):

    [GFDrv][info][ITE_EC_SPI_WRITE:00124] Goodix>>> write headcount 0x28ec
    [GFDrv][debug][ITE_EC_SPI_WRITE:00170] Goodix>>> ITE write data:0xccf2ec28a00600a62003000100860000
    [GFDrv][debug][SpiSendDataToDevice:03010] Goodix>>> cmd0-cmd1-Len-ackt-ec:0x3-2-0xe-1000-1
    [GFDrv][debug][MilanEvtInterruptIsr:05173] Goodix>>> data len 10  /  read data done
    [GFEngine][info] solution string: 1.1.17.140_GF_ITE_EC_20063_GF3658_2504_EC

=> Transport is "ITE_EC_SPI_WRITE" = EC mailbox, ISR-driven (MilanEvtInterruptIsr).
=> Sensor silicon: GF3658 (ST411 / Milan family) — same family as the MateBook 13 GXFP51A0
   which HAS a working Linux driver (GodsQuantum) and as GXFP5130 (eSPI mailbox + GPIOs).

Corroboration: oem5.inf comment `ACPI\GXFP5120  ; ITE EC`.

## Why every previous attempt failed
All bring-up work drove the Intel GSPI1 controller (\_SB.PC00.SPI1, pci 00:1e.3, spidev0.0).
That bus is a decoy: the ACPI device \_SB.SPBA/GXFP5120 declares SpiSerialBus, but the
physical sensor hangs off the EC's internal SPI, reached through EC mailbox commands.
- LPSS SPI1 registers match Windows byte-for-byte  -> decoy confirmed
- GPP_B pads match Windows byte-for-byte           -> decoy confirmed
- The GpioInt (GNVS GFPI=0x09000011, gpio 17) is the EC->host data-ready interrupt, not a sensor IRQ.
- DSDT _INI writes SHPO(0x09000011, 1) = TX bit of that line.

## Device identity
- Windows: ACPI\GXFP5120, driver oem5.inf (UMDF gfspi.dll), status Started
- ProgramData/Goodix/{goodix.dat,goodix_calib.dat} header "S2H826." + 8-byte blob
- WinBio database GUID D38EDC56-D60C-4F85-8C5A-B18086A61B1E (from oem5.inf), touched 10:44

## Frame format observed (EC write direction)
    cc f2 <ctr_lo> <ctr_hi> <a0> <len> <payload...> 00 00
    ctr increments per EC command (0x28ec, 0x28ed, ... 0x28f3)
    payload example: a0 06 00 a6 20 03 00 01 00 86 00   (len 0x0e frame)
    SpiSendDataToDevice log: cmd0-cmd1-Len-ackt-ec:0x3-2-0xe-1000-1

## Next
Reference implementation: Void755's gxfp5130 kernel driver (eSPI mailbox + GPIO handshake,
LKML 2026-07-18, packaged at github.com/Metrohan/gxfp5130-linux).
Adapt for GXFP5120/GF3658 + this ITE EC's mailbox addresses.
Also: fan project already found EC access path (HQRE/HQWE ports 0x72/0x73, ERAM @0xFE800700).
